"""On-disk workspace layout and synthetic drill initialization."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import ed25519
from .ledger import Ledger
from .pki import (APPOINTMENT_DOMAIN, SEAT_MAIN, PolicyState,
                  build_synthetic_pki, verify_domain_sig)
from .rules import publish_generation, verify_generation
from .util import (append_jsonl, atomic_write_json, b64e, domain_bytes,
                   now_iso, read_json, read_jsonl)

SUBDIRS = [
    "pki", "rules", "ledger",
    "records/decisions", "records/revocations",
    "quarantine", "allow", "quarantine_reconstructed",
]


class Workspace:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self._ledger: Optional[Ledger] = None

    # -- paths -------------------------------------------------------------
    @property
    def pki_dir(self) -> Path: return self.root / "pki"
    @property
    def trust_path(self) -> Path: return self.pki_dir / "trust.json"
    @property
    def keystore_path(self) -> Path: return self.pki_dir / "keystore.synthetic.json"
    @property
    def appointments_path(self) -> Path: return self.pki_dir / "appointments.jsonl"

    @property
    def rules_dir(self) -> Path: return self.root / "rules"
    @property
    def rule_log_path(self) -> Path: return self.rules_dir / "generations.jsonl"
    @property
    def current_rule_path(self) -> Path: return self.rules_dir / "current.json"

    @property
    def ledger_dir(self) -> Path: return self.root / "ledger"
    @property
    def audit_path(self) -> Path: return self.ledger_dir / "audit.jsonl"
    @property
    def watermark_path(self) -> Path: return self.ledger_dir / "watermark.json"
    @property
    def watermark_history_path(self) -> Path:
        return self.ledger_dir / "watermark_history.jsonl"

    @property
    def decisions_dir(self) -> Path:
        return self.root / "records" / "decisions"
    @property
    def revocations_dir(self) -> Path:
        return self.root / "records" / "revocations"
    @property
    def quarantine_dir(self) -> Path: return self.root / "quarantine"
    @property
    def allow_dir(self) -> Path: return self.root / "allow"
    @property
    def recon_quarantine_dir(self) -> Path:
        return self.root / "quarantine_reconstructed"

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    # -- setup -------------------------------------------------------------
    def initialize(self, clean: bool = True) -> "Workspace":
        if clean and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
        for sub in SUBDIRS:
            (self.root / sub).mkdir(parents=True, exist_ok=True)

        trust, keystore = build_synthetic_pki()
        atomic_write_json(self.trust_path, trust)
        atomic_write_json(self.keystore_path, keystore)

        gen1 = publish_generation(keystore, 1)
        append_jsonl(self.rule_log_path, gen1)
        atomic_write_json(self.current_rule_path,
                          {"generation": 1, "rules_hash": gen1["rules_hash"]})

        # Genesis governance appointment for the main issuer seat.
        appt_core = {
            "appt_id": "APPT-GEN-IVAN",
            "ts": now_iso(),
            "action": "appoint",
            "seat": SEAT_MAIN,
            "holder": "issuer.ivan",
            "root_id": "root.gamma",
            "note": "genesis synthetic appointment",
        }
        appt = sign_governance(keystore, APPOINTMENT_DOMAIN, appt_core)
        append_jsonl(self.appointments_path, appt)

        # Genesis watermark (seq 0).
        if not self.watermark_history_path.exists():
            append_jsonl(self.watermark_history_path,
                         {"seq": 0, "hash": "0" * 64,
                          "updated_at": now_iso(), "genesis": True})
        return self

    # -- material ----------------------------------------------------------
    def write_artifact(self, name: str, data: bytes) -> Path:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        p = self.quarantine_dir / name
        p.write_bytes(data)
        return p

    # -- loaders -----------------------------------------------------------
    def load_trust(self) -> Dict[str, Any]:
        return read_json(self.trust_path)

    def load_keystore(self) -> Dict[str, Any]:
        return read_json(self.keystore_path)

    def rule_records(self) -> List[Dict[str, Any]]:
        return read_jsonl(self.rule_log_path)

    def verified_rule_map(self, trust: Optional[Dict[str, Any]] = None
                          ) -> Dict[int, Dict[str, Any]]:
        trust = trust or self.load_trust()
        out: Dict[int, Dict[str, Any]] = {}
        for rec in self.rule_records():
            ok, _code, _h = verify_generation(trust, rec)
            if ok:
                out[rec["generation"]] = rec
        return out

    def current_generation(self) -> Optional[int]:
        if self.current_rule_path.exists():
            return read_json(self.current_rule_path).get("generation")
        return None

    @property
    def ledger(self) -> Ledger:
        if self._ledger is None:
            self._ledger = Ledger(
                self.audit_path, self.watermark_path,
                self.watermark_history_path)
        return self._ledger

    # -- signed governance / policy state --------------------------------
    def gov_pub_b64(self, trust: Dict[str, Any]) -> Optional[str]:
        return trust.get("governance", {}).get("gov.council", {}).get("pub_b64")

    def verify_gov_record(self, trust: Dict[str, Any], domain: str,
                          rec: Dict[str, Any]) -> bool:
        sig = rec.get("gov_sig_b64")
        core = {k: v for k, v in rec.items() if k != "gov_sig_b64"}
        pub = self.gov_pub_b64(trust)
        if not pub or not sig:
            return False
        return verify_domain_sig(pub, domain, core, sig)

    def load_policy_state(self, trust: Optional[Dict[str, Any]] = None
                          ) -> Tuple[PolicyState, List[Dict[str, str]]]:
        from .pki import REVOCATION_DOMAIN
        trust = trust or self.load_trust()
        policy = PolicyState()
        diag: List[Dict[str, str]] = []

        for appt in read_jsonl(self.appointments_path):
            if self.verify_gov_record(trust, APPOINTMENT_DOMAIN, appt):
                policy.merge_appointment(appt)
            else:
                diag.append({"kind": "appointment", "id":
                             str(appt.get("appt_id")), "code": "GOV_SIG_BAD"})

        if self.revocations_dir.exists():
            for p in sorted(self.revocations_dir.glob("*.json")):
                try:
                    rec = read_json(p)
                except Exception:
                    diag.append({"kind": "revocation", "id": p.name,
                                 "code": "UNREADABLE_JSON"})
                    continue
                if self.verify_gov_record(trust, REVOCATION_DOMAIN, rec):
                    policy.merge_revocation(rec)
                else:
                    diag.append({"kind": "revocation", "id":
                                 str(rec.get("rev_id", p.name)),
                                 "code": "GOV_SIG_BAD"})
        return policy, diag

    def new_decision_path(self, decision_id: str, digest: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_"
                       for c in decision_id)
        fname = f"{safe}__{digest[:12]}__{uuid.uuid4().hex[:8]}.json"
        self.decisions_dir.mkdir(parents=True, exist_ok=True)
        return self.decisions_dir / fname


def sign_governance(keystore: Dict[str, Any], domain: str,
                    core: Dict[str, Any]) -> Dict[str, Any]:
    seed_hex = keystore["keys"]["gov.council"]["seed_hex"]
    sig = ed25519.sign_message(
        bytes.fromhex(seed_hex), domain_bytes(domain, core))
    rec = dict(core)
    rec["gov_sig_b64"] = b64e(sig)
    return rec
