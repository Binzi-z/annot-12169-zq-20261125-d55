"""Allow decisions that bind rule generation, actual digest and signatures."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from . import ed25519
from .pki import PolicyState, TrustView
from .util import (b64d, b64e, domain_bytes, now_iso, safe_rel_path,
                   sha256_hex)

BIND_DOMAIN = "ISO-ALLOW-BIND/v1"
SCHEMA = "isolation.allow_decision/v1"

# Exact set of fields covered by every signature (prevents unsigned extras).
BIND_FIELDS = (
    "schema",
    "decision_id",
    "rule_generation",
    "rules_hash",
    "artifact_name",
    "rel_path",
    "size",
    "digest_alg",
    "digest",
    "issuer",
    "seat",
    "controllers",
    "issued_at",
)
SIG_FIELDS = {"issuer_sig_b64", "approvals"}
RECORD_FIELDS: Set[str] = set(BIND_FIELDS) | SIG_FIELDS


def build_bind(*, decision_id: str, rule_generation: int, rules_hash: str,
               artifact_name: str, rel_path: str, size: int, digest: str,
               issuer: str, controllers: List[str],
               seat: Optional[str] = None,
               issued_at: Optional[str] = None) -> Dict[str, Any]:
    if len(controllers) != 2:
        raise ValueError("exactly two controllers are required")
    controllers = sorted(controllers)
    return {
        "schema": SCHEMA,
        "decision_id": decision_id,
        "rule_generation": rule_generation,
        "rules_hash": rules_hash,
        "artifact_name": artifact_name,
        "rel_path": safe_rel_path(rel_path),
        "size": int(size),
        "digest_alg": "sha256",
        "digest": digest.lower(),
        "issuer": issuer,
        "seat": seat,
        "controllers": controllers,
        "issued_at": issued_at or now_iso(),
    }


def sign_decision(keystore: Dict[str, Any], bind: Dict[str, Any]) -> Dict[str, Any]:
    """Sign the bind core with the issuer and both controller seeds."""
    missing = [k for k in BIND_FIELDS if k not in bind]
    if missing:
        raise ValueError(f"bind payload missing fields: {missing}")
    if len(bind["controllers"]) != 2:
        raise ValueError("two controllers required")

    msg = domain_bytes(BIND_DOMAIN, bind)

    issuer_seed = bytes.fromhex(
        keystore["keys"][bind["issuer"]]["seed_hex"])
    issuer_sig = ed25519.sign_message(issuer_seed, msg)

    approvals = []
    for cid in bind["controllers"]:
        seed_hex = keystore["keys"][cid]["seed_hex"]
        sig = ed25519.sign_message(bytes.fromhex(seed_hex), msg)
        approvals.append({
            "controller": cid,
            "pub_b64": keystore["keys"][cid]["pub_b64"],
            "sig_b64": b64e(sig),
        })

    rec = dict(bind)
    rec["issuer_sig_b64"] = b64e(issuer_sig)
    rec["approvals"] = approvals
    if set(rec.keys()) != RECORD_FIELDS:
        raise AssertionError("decision record field shape mismatch")
    return rec


def verify_decision_record(rec: Dict[str, Any], trust: Dict[str, Any],
                           policy: PolicyState,
                           rule_map: Dict[int, Dict[str, Any]],
                           current_generation: Optional[int] = None,
                           require_current: bool = False) -> Dict[str, Any]:
    """Fail-closed wrapper: any malformed/tampered value yields invalid."""
    try:
        return _verify_decision_record_inner(
            rec, trust, policy, rule_map, current_generation,
            require_current)
    except Exception:
        return {"ok": False, "codes": ["RECORD_MALFORMED"],
                "primary": "RECORD_MALFORMED", "bind": {}}


def _verify_decision_record_inner(
        rec: Dict[str, Any], trust: Dict[str, Any],
        policy: PolicyState,
        rule_map: Dict[int, Dict[str, Any]],
        current_generation: Optional[int] = None,
        require_current: bool = False) -> Dict[str, Any]:
    """Cryptographically and policy-verify one signed decision record."""
    codes: List[str] = []
    bind: Dict[str, Any] = {}

    if not isinstance(rec, dict) or set(rec.keys()) != RECORD_FIELDS:
        return {"ok": False, "codes": ["RECORD_SHAPE_INVALID"],
                "primary": "RECORD_SHAPE_INVALID", "bind": {}}

    bind = {k: rec[k] for k in BIND_FIELDS}
    tv = TrustView(trust)
    msg = domain_bytes(BIND_DOMAIN, bind)

    digest = bind.get("digest", "")
    if not (isinstance(digest, str) and len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest)):
        codes.append("DIGEST_FIELD_INVALID")
    if bind.get("digest_alg") != "sha256":
        codes.append("DIGEST_ALG_UNSUPPORTED")
    if not isinstance(bind.get("size"), int) or bind["size"] < 0:
        codes.append("SIZE_FIELD_INVALID")

    # -- rule generation binding ------------------------------------------
    gen = bind.get("rule_generation")
    rule_rec = rule_map.get(gen) if isinstance(gen, int) else None
    if rule_rec is None:
        codes.append("RULE_GENERATION_UNKNOWN")
    elif rule_rec.get("rules_hash") != bind.get("rules_hash"):
        codes.append("RULES_HASH_NOT_BOUND")
    if (require_current and current_generation is not None
            and isinstance(gen, int) and gen < current_generation):
        codes.append("RULE_GENERATION_RETIRED")

    # -- issuer signature + revocation / anti-backfill ---------------------
    issuer = bind.get("issuer", "")
    issuer_pub = tv.certified_pub(issuer)
    if issuer_pub is None:
        codes.append("ISSUER_CERT_UNTRUSTED")
    else:
        try:
            issuer_sig_ok = ed25519.verify_message(
                issuer_pub, msg, b64d(rec["issuer_sig_b64"]))
        except Exception:
            issuer_sig_ok = False
        if not issuer_sig_ok:
            codes.append("ISSUER_SIG_BAD")

        verdict = tv.evaluate_issuer(issuer, policy, bind.get("seat"))
        if not verdict["allowed"]:
            codes.extend(verdict["reasons"] or [verdict["code"]])

    # -- two independent controller signatures -----------------------------
    approvals = rec.get("approvals")
    controllers = bind.get("controllers")
    if not isinstance(approvals, list) or len(approvals) != 2:
        codes.append("CONTROLLER_APPROVAL_COUNT")
    if not (isinstance(controllers, list) and len(controllers) == 2):
        codes.append("CONTROLLER_BINDING_INVALID")

    if isinstance(approvals, list) and isinstance(controllers, list) \
            and len(controllers) == 2:
        seen: Set[str] = set()
        for ap in approvals:
            cid = ap.get("controller") if isinstance(ap, dict) else None
            if cid not in controllers:
                codes.append("APPROVAL_NOT_BOUND_CONTROLLER")
                continue
            if cid == bind.get("issuer"):
                # Four-eyes: the issuer's own key cannot fill a controller seat.
                codes.append("ISSUER_CONTROLLER_OVERLAP")
                continue
            seen.add(cid)
            cert_pub = tv.certified_pub(cid)
            if cert_pub is None:
                codes.append("CONTROLLER_CERT_UNTRUSTED")
                continue
            if ap.get("pub_b64") != b64e(cert_pub):
                codes.append("APPROVAL_PUB_MISMATCH")
            try:
                sig_ok = ed25519.verify_message(
                    cert_pub, msg, b64d(ap.get("sig_b64", "")))
            except Exception:
                sig_ok = False
            if not sig_ok:
                codes.append("CONTROLLER_SIG_BAD")
        if seen != set(controllers) or len(seen) != 2:
            codes.append("TWO_DISTINCT_CONTROLLERS_REQUIRED")
        else:
            indep, why = tv.controllers_independent(
                controllers[0], controllers[1])
            if not indep:
                codes.append("CONTROLLERS_NOT_INDEPENDENT:" + why)

    # -- explicit revocations ---------------------------------------------
    did = bind.get("decision_id")
    if did in policy.revoked_decisions:
        codes.append("DECISION_REVOKED")
    if digest in policy.revoked_digests:
        codes.append("DIGEST_REVOKED")

    # de-duplicate while preserving order
    deduped: List[str] = []
    for c in codes:
        if c not in deduped:
            deduped.append(c)

    primary = "OK" if not deduped else _primary_code(deduped)
    return {"ok": not deduped, "codes": deduped, "primary": primary,
            "bind": bind}


_PRIORITY = [
    "DECISION_REVOKED", "DIGEST_REVOKED",
    "SAME_ROOT_PROXY_BACKFILL", "REVOKED_PRINCIPAL_PROXY", "ISSUER_REVOKED",
    "ISSUER_SIG_BAD", "CONTROLLER_SIG_BAD", "CONTROLLERS_NOT_INDEPENDENT",
    "RULES_HASH_NOT_BOUND", "RULE_GENERATION_RETIRED",
    "ID_DIGEST_CONFLICT",
]


def _primary_code(codes: List[str]) -> str:
    for p in _PRIORITY:
        for c in codes:
            if c == p or c.startswith(p + ":"):
                return c
    return codes[0]
