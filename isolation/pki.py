"""Synthetic PKI, controller-independence and issuer anti-backfill policy.

Everything here is generated locally from deterministic label-derived seeds;
there is no real certificate authority and no production key material.

Trust model
-----------
* Four pinned synthetic roots ``root.alpha/beta/gamma/delta`` plus a pinned
  governance key ``gov.council``.
* Controllers chained to *different* roots are considered independent.  Two
  controllers under the same root are explicitly **not** independent.
* When an issuer is revoked its seat is frozen.  A candidate that shares the
  revoked holder's root (a "same-root proxy"/clone) cannot fill the seat.
  A legitimate successor must be re-anchored to a different root and installed
  by a signed governance appointment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import ed25519
from .util import b64d, b64e, domain_bytes, sha256_text

CERT_DOMAIN = "ISO-SYNTH-CERT/v1"
APPOINTMENT_DOMAIN = "ISO-GOV-APPOINTMENT/v1"
REVOCATION_DOMAIN = "ISO-GOV-REVOCATION/v1"

SEAT_MAIN = "SEAT-ISSUER-MAIN"
SEAT_BACKUP = "SEAT-ISSUER-BACKUP"

# ---------------------------------------------------------------------------
# deterministic synthetic key derivation
# ---------------------------------------------------------------------------


def seed_for(label: str) -> bytes:
    import hashlib
    return hashlib.sha256(
        b"isolation-drill/v1/seed/" + label.encode("utf-8")
    ).digest()


def _sign_with_seed_hex(seed_hex: str, domain: str, core: Dict[str, Any]) -> str:
    sig = ed25519.sign_message(
        bytes.fromhex(seed_hex), domain_bytes(domain, core)
    )
    return b64e(sig)


def verify_domain_sig(pub_b64: str, domain: str, core: Dict[str, Any],
                      sig_b64: str) -> bool:
    try:
        return ed25519.verify_message(
            b64d(pub_b64),
            domain_bytes(domain, core),
            b64d(sig_b64),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# build the synthetic organisation
# ---------------------------------------------------------------------------

# principal -> (kind, root_id, extra cert fields)
_PRINCIPALS: Dict[str, Tuple[str, str, Dict[str, Any]]] = {
    "ctrl.alice": ("controller", "root.alpha", {}),
    "ctrl.bob": ("controller", "root.beta", {}),
    "ctrl.cara": ("controller", "root.alpha", {}),
    "ctrl.dev": ("controller", "root.beta", {}),
    "rules.admin": ("rules-authority", "root.alpha", {}),
    "issuer.ivan": ("issuer", "root.gamma", {"seat": SEAT_MAIN}),
    "proxy.pia": ("proxy", "root.gamma",
                  {"proxy_for": "issuer.ivan", "backfill_seat": SEAT_MAIN}),
    "issuer.ivan2": ("issuer", "root.gamma",
                     {"backfill_seat": SEAT_MAIN,
                      "note": "same-root replacement clone"}),
    "issuer.iris": ("issuer", "root.delta", {"seat": SEAT_MAIN}),
    "issuer.nora": ("issuer", "root.delta", {"seat": SEAT_BACKUP}),
}

_ROOTS = ["root.alpha", "root.beta", "root.gamma", "root.delta", "root.gov"]


def build_synthetic_pki() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return ``(trust, keystore)`` for a fresh synthetic organisation."""
    keystore: Dict[str, Any] = {
        "synthetic": True,
        "warning": "THROWAWAY DRILL KEYS DERIVED FROM PUBLIC LABELS - DO NOT USE",
        "keys": {},
    }
    roots: Dict[str, Dict[str, str]] = {}
    root_seeds: Dict[str, bytes] = {}
    for rid in _ROOTS:
        seed = seed_for("root:" + rid)
        root_seeds[rid] = seed
        pub = ed25519.derive_public(seed)
        roots[rid] = {"pub_b64": b64e(pub)}
        keystore["keys"][rid] = {"seed_hex": seed.hex(), "pub_b64": b64e(pub)}

    gov_seed = seed_for("gov.council")
    gov_pub = ed25519.derive_public(gov_seed)
    keystore["keys"]["gov.council"] = {
        "seed_hex": gov_seed.hex(), "pub_b64": b64e(gov_pub),
    }

    certs: List[Dict[str, Any]] = []
    serial_n = 1000
    for subject, (kind, root_id, extra) in _PRINCIPALS.items():
        seed = seed_for("principal:" + subject)
        pub = ed25519.derive_public(seed)
        keystore["keys"][subject] = {
            "seed_hex": seed.hex(), "pub_b64": b64e(pub), "kind": kind,
        }
        serial_n += 1
        core: Dict[str, Any] = {
            "version": 1,
            "subject": subject,
            "subject_pub": b64e(pub),
            "cert_type": kind,
            "root_id": root_id,
            "issuer_id": root_id,
            "serial": f"SYN-{serial_n:04d}",
        }
        core.update(extra)
        sig = ed25519.sign_message(
            root_seeds[root_id], domain_bytes(CERT_DOMAIN, core)
        )
        cert = dict(core)
        cert["ca_sig_b64"] = b64e(sig)
        certs.append(cert)

    trust = {
        "version": 1,
        "synthetic": True,
        "pinned_roots": roots,
        "governance": {"gov.council": {"pub_b64": b64e(gov_pub)}},
        "certs": certs,
    }
    return trust, keystore


# ---------------------------------------------------------------------------
# runtime policy state (revocations + governance succession)
# ---------------------------------------------------------------------------


@dataclass
class PolicyState:
    revoked_ids: Set[str] = field(default_factory=set)
    revoked_serials: Set[str] = field(default_factory=set)
    revoked_decisions: Set[str] = field(default_factory=set)
    revoked_digests: Set[str] = field(default_factory=set)
    # seat -> revoked holder whose revocation froze the seat
    frozen_seats: Dict[str, str] = field(default_factory=dict)
    # seat -> legitimately appointed successor (signed governance appointment)
    successors: Dict[str, str] = field(default_factory=dict)

    def merge_revocation(self, rec: Dict[str, Any]) -> None:
        target = rec.get("target_id")
        if target:
            self.revoked_ids.add(target)
        serial = rec.get("target_serial")
        if serial:
            self.revoked_serials.add(serial)
        did = rec.get("decision_id")
        if did:
            self.revoked_decisions.add(did)
        digest = rec.get("digest")
        if digest:
            self.revoked_digests.add(digest)
        seat = rec.get("freeze_seat")
        if seat and target:
            # A governed successor appointed later wins; tracked separately.
            self.frozen_seats.setdefault(seat, target)

    def merge_appointment(self, appt: Dict[str, Any]) -> None:
        seat = appt.get("seat")
        holder = appt.get("holder")
        if seat and holder and appt.get("action") in ("successor", "appoint"):
            self.successors[seat] = holder


# ---------------------------------------------------------------------------
# trust view + policy checks
# ---------------------------------------------------------------------------


class TrustView:
    """Public-only view of the synthetic PKI (usable by the reconstructor)."""

    def __init__(self, trust: Dict[str, Any]):
        self.trust = trust
        self.roots: Dict[str, str] = {
            rid: meta["pub_b64"]
            for rid, meta in trust.get("pinned_roots", {}).items()
        }
        self.gov_keys: Dict[str, str] = {
            gid: meta["pub_b64"]
            for gid, meta in trust.get("governance", {}).items()
        }
        self.certs: Dict[str, Dict[str, Any]] = {
            c["subject"]: c for c in trust.get("certs", [])
        }
        self._cert_ok_cache: Dict[Tuple[Any, Any], bool] = {}
        self._pub_cache: Dict[str, Optional[bytes]] = {}

    # -- certificates -------------------------------------------------------

    def verify_cert(self, cert: Dict[str, Any]) -> bool:
        cache_key = (cert.get("subject"), cert.get("serial"))
        if cache_key in self._cert_ok_cache:
            return self._cert_ok_cache[cache_key]
        ok = False
        try:
            issuer_id = cert["issuer_id"]
            root_pub = self.roots.get(issuer_id)
            if root_pub is not None and issuer_id == cert.get("root_id"):
                sig_b64 = cert.get("ca_sig_b64")
                core = {k: v for k, v in cert.items() if k != "ca_sig_b64"}
                ok = verify_domain_sig(
                    root_pub, CERT_DOMAIN, core, sig_b64)
        except Exception:
            ok = False
        self._cert_ok_cache[cache_key] = ok
        return ok

    def certified_pub(self, subject: str) -> Optional[bytes]:
        if subject in self._pub_cache:
            return self._pub_cache[subject]
        out: Optional[bytes] = None
        cert = self.certs.get(subject)
        if cert is not None and self.verify_cert(cert):
            try:
                out = b64d(cert["subject_pub"])
            except Exception:
                out = None
        self._pub_cache[subject] = out
        return out

    def root_of(self, subject: str) -> Optional[str]:
        cert = self.certs.get(subject)
        return cert.get("root_id") if cert else None

    # -- controller independence ------------------------------------------

    def controllers_independent(self, a: str, b: str) -> Tuple[bool, str]:
        if a == b:
            return False, "SAME_CONTROLLER"
        ca, cb = self.certs.get(a), self.certs.get(b)
        if ca is None or cb is None:
            return False, "UNKNOWN_CONTROLLER"
        if not self.verify_cert(ca) or not self.verify_cert(cb):
            return False, "CONTROLLER_CERT_INVALID"
        if ca.get("cert_type") != "controller" or \
                cb.get("cert_type") != "controller":
            return False, "CONTROLLER_ROLE_INVALID"
        if ca.get("root_id") == cb.get("root_id"):
            return False, "CONTROLLERS_SAME_ROOT"
        if ca.get("proxy_for") == b or cb.get("proxy_for") == a:
            return False, "CONTROLLER_DELEGATED"
        if ca.get("proxy_for") and ca["proxy_for"] == cb.get("proxy_for"):
            return False, "CONTROLLERS_COMMON_LINEAGE"
        return True, "INDEPENDENT"

    # -- issuer / anti-backfill -------------------------------------------

    def evaluate_issuer(self, subject: str, policy: PolicyState,
                        seat_hint: Optional[str] = None) -> Dict[str, Any]:
        reasons: List[str] = []
        notes: List[str] = []
        cert = self.certs.get(subject)
        if cert is None or not self.verify_cert(cert):
            return {"allowed": False, "code": "ISSUER_CERT_INVALID",
                    "reasons": ["ISSUER_CERT_INVALID"], "notes": notes,
                    "cert": cert}

        if cert.get("serial") in policy.revoked_serials:
            reasons.append("CERT_SERIAL_REVOKED")
        if cert.get("root_id") in policy.revoked_ids:
            reasons.append("ROOT_REVOKED")
        if subject in policy.revoked_ids:
            reasons.append("ISSUER_REVOKED")

        proxy_for = cert.get("proxy_for")
        if proxy_for and proxy_for in policy.revoked_ids:
            reasons.append("REVOKED_PRINCIPAL_PROXY")

        # Union every seat this signature could plausibly act for: the
        # caller-bound hint cannot hide a certificate-declared backfill seat.
        candidate_seats = []
        for s in (seat_hint, cert.get("seat"), cert.get("backfill_seat")):
            if s and s not in candidate_seats:
                candidate_seats.append(s)

        governed_any = any(
            policy.successors.get(s) == subject for s in candidate_seats)
        if governed_any:
            notes.append("GOVERNED_SUCCESSOR")

        for seat in candidate_seats:
            holder = policy.frozen_seats.get(seat)
            if not holder or subject == holder:
                # The revoked holder itself is already charged above.
                continue
            holder_root = self.root_of(holder)
            same_root = (cert.get("root_id") is not None
                         and cert.get("root_id") == holder_root)
            is_proxy_of_holder = proxy_for == holder
            if same_root or is_proxy_of_holder:
                # Categorical: an appointment cannot legitimize a same-root
                # proxy/clone filling a revoked issuer's frozen seat.
                reasons.append("SAME_ROOT_PROXY_BACKFILL")
            elif policy.successors.get(seat) != subject:
                # Different trust root but no signed governance re-anchor yet.
                reasons.append("SUCCESSOR_NOT_GOVERNED")
            else:
                notes.append("GOVERNED_REANCHOR")

        allowed = not reasons
        if allowed:
            code = "GOVERNED_SUCCESSOR" if governed_any else "ISSUER_OK"
        else:
            # Prefer the headline anti-backfill code when it applies.
            priority = [
                "SAME_ROOT_PROXY_BACKFILL",
                "REVOKED_PRINCIPAL_PROXY",
                "ISSUER_REVOKED",
            ]
            code = next((c for c in priority if c in reasons), reasons[0])
        return {"allowed": allowed, "code": code, "reasons": reasons,
                "notes": notes, "cert": cert}


def revocation_id_for(target: str) -> str:
    return "REV-" + sha256_text("rev:" + target)[:12].upper()
