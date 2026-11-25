"""Security rule generations bound into every allow decision."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .pki import TrustView
from .util import canonical, domain_bytes, now_iso, sha256_hex
from . import ed25519
from .util import b64d, b64e

RULE_DOMAIN = "ISO-RULE-GENERATION/v1"

GENESIS_RULES: Dict[str, Any] = {
    "baseline": "synthetic-isolation-baseline-2026-11",
    "allowed_extensions": [".bin", ".txt", ".drill"],
    "max_bytes": 64 * 1024 * 1024,
    "required_controller_count": 2,
    "require_independent_roots": True,
    "issuer_anti_backfill": "same-root-proxy-denied",
}


def hash_rules(rules: Dict[str, Any]) -> str:
    return sha256_hex(canonical(rules))


def publish_generation(keystore: Dict[str, Any], generation: int,
                       rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rules = dict(GENESIS_RULES if rules is None else rules)
    rules["generation"] = generation
    rules_hash = hash_rules(rules)
    core = {
        "generation": generation,
        "rules_hash": rules_hash,
        "issued_by": "rules.admin",
        "issued_at": now_iso(),
    }
    seed_hex = keystore["keys"]["rules.admin"]["seed_hex"]
    sig = ed25519.sign_message(
        bytes.fromhex(seed_hex), domain_bytes(RULE_DOMAIN, core)
    )
    return {**core, "rules": rules, "sig_b64": b64e(sig)}


def verify_generation(trust: Dict[str, Any], rec: Dict[str, Any]
                      ) -> Tuple[bool, str, Optional[str]]:
    """Return ``(ok, code, rules_hash)``."""
    try:
        rules = rec["rules"]
        rules_hash = hash_rules(rules)
        if rules_hash != rec.get("rules_hash"):
            return False, "RULES_HASH_MISMATCH", None
        if rules.get("generation") != rec.get("generation"):
            return False, "RULE_GENERATION_NUMBER_MISMATCH", rules_hash
        tv = TrustView(trust)
        pub = tv.certified_pub(rec.get("issued_by", ""))
        if pub is None:
            return False, "RULE_AUTHORITY_UNTRUSTED", rules_hash
        core = {k: v for k, v in rec.items() if k not in ("rules", "sig_b64")}
        # core must contain exactly the signed fields; rebuild explicitly:
        signed_core = {
            "generation": rec["generation"],
            "rules_hash": rec["rules_hash"],
            "issued_by": rec["issued_by"],
            "issued_at": rec["issued_at"],
        }
        if core != signed_core:
            return False, "RULE_RECORD_SHAPE", rules_hash
        ok = ed25519.verify_message(
            pub, domain_bytes(RULE_DOMAIN, signed_core),
            b64d(rec["sig_b64"]),
        )
        if not ok:
            return False, "RULE_SIG_BAD", rules_hash
        return True, "RULE_GEN_OK", rules_hash
    except Exception:
        return False, "RULE_RECORD_MALFORMED", None
