"""Promote/revoke operations with a commit-time policy linearization point."""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .decision import build_bind, verify_decision_record, sign_decision
from .pki import REVOCATION_DOMAIN, TrustView, revocation_id_for
from .util import (append_jsonl, atomic_write_bytes, atomic_write_json,
                   now_iso, safe_rel_path, sha256_file)
from .workspace import Workspace, sign_governance


class PolicyDenied(Exception):
    def __init__(self, verification: Dict[str, Any]):
        self.verification = verification
        super().__init__(
            "policy denied: " + ",".join(verification.get("codes", [])))


class PromoteHooks:
    """Override methods to script deterministic thread interleavings."""

    def before_linearize(self) -> None: ...
    def after_decision_persisted(self, info: Dict[str, Any]) -> None: ...
    def after_audit(self, info: Dict[str, Any]) -> None: ...
    def after_dir_materialized(self, info: Dict[str, Any]) -> None: ...
    def after_dir_changed_unsafe(self, info: Dict[str, Any]) -> None: ...


_NO_HOOKS = PromoteHooks()


class Engine:
    def __init__(self, ws: Workspace):
        self.ws = ws
        # Serializes the check -> durable commit -> materialize critical section.
        self.commit_lock = threading.RLock()

    # ------------------------------------------------------------------
    # revocation / governance
    # ------------------------------------------------------------------
    def revoke(self, *, target_id: Optional[str] = None,
               decision_id: Optional[str] = None,
               digest: Optional[str] = None,
               freeze_seat: Optional[str] = None,
               reason: str = "drill revocation",
               target_serial: Optional[str] = None) -> Dict[str, Any]:
        ws = self.ws
        with self.commit_lock:
            keystore = ws.load_keystore()
            rev_id = revocation_id_for(
                (target_id or "") + (decision_id or "") + (digest or ""))
            core: Dict[str, Any] = {
                "rev_id": rev_id,
                "ts": now_iso(),
                "authority": "gov.council",
                "target_id": target_id,
                "target_serial": target_serial,
                "decision_id": decision_id,
                "digest": (digest or "").lower() or None,
                "freeze_seat": freeze_seat,
                "reason": reason,
            }
            rec = sign_governance(keystore, REVOCATION_DOMAIN, core)
            path = ws.revocations_dir / f"{rev_id}.json"
            if path.exists():
                # A repeated revocation submission keeps every signed record.
                path = ws.revocations_dir / (
                    f"{rev_id}-{uuid.uuid4().hex[:8]}.json")
            atomic_write_json(path, rec)
            event = ws.ledger.append("revocation.issued", {
                "rev_id": rev_id, "target_id": target_id,
                "decision_id": decision_id, "digest": core["digest"],
                "freeze_seat": freeze_seat, "record_file": path.name,
                "reason": reason,
            })
            wm = ws.ledger.persist_watermark()
            return {"record": rec, "path": path, "ledger_event": event,
                    "watermark": wm}

    def appoint_successor(self, holder: str, seat: str,
                          action: str = "successor") -> Dict[str, Any]:
        ws = self.ws
        with self.commit_lock:
            trust = ws.load_trust()
            keystore = ws.load_keystore()
            tv = TrustView(trust)
            root_id = tv.root_of(holder)
            # Defence in depth: governance cannot re-anchor a successor to the
            # same root as a revoked holder of a currently frozen seat.
            policy, _diag = ws.load_policy_state(trust)
            frozen_holder = policy.frozen_seats.get(seat)
            reanchored = False
            if frozen_holder is not None:
                old_root = tv.root_of(frozen_holder)
                if old_root is not None and root_id == old_root:
                    raise PolicyDenied({"ok": False, "codes": [
                        "SAME_ROOT_PROXY_BACKFILL_APPOINTMENT_REFUSED"]})
                reanchored = old_root != root_id
            core = {
                "appt_id": f"APPT-{holder}-{uuid.uuid4().hex[:8]}",
                "ts": now_iso(),
                "action": action,
                "seat": seat,
                "holder": holder,
                "root_id": root_id,
                "reanchored": bool(reanchored),
            }
            appt = sign_governance(
                keystore, "ISO-GOV-APPOINTMENT/v1", core)
            append_jsonl(ws.appointments_path, appt)
            ws.ledger.append("governance.appointment", {
                "seat": seat, "holder": holder, "action": action,
                "root_id": root_id,
            })
            wm = ws.ledger.persist_watermark()
            return {"appointment": appt, "watermark": wm}

    # ------------------------------------------------------------------
    # promotion
    # ------------------------------------------------------------------
    def _current_rule_hash(self, trust: Dict[str, Any]):
        ws = self.ws
        gen = ws.current_generation()
        rule_map = ws.verified_rule_map(trust)
        if gen is None or gen not in rule_map:
            raise PolicyDenied({"ok": False, "codes": ["NO_ACTIVE_RULE_GENERATION"]})
        return gen, rule_map, rule_map[gen]["rules_hash"]

    def promote(self, *, decision_id: str, source: Path | str, issuer: str,
                controllers: List[str], rel_path: Optional[str] = None,
                seat: Optional[str] = None,
                hooks: Optional[PromoteHooks] = None,
                require_current_rules: bool = True,
                allow_duplicate_id: bool = False) -> Dict[str, Any]:
        ws = self.ws
        hooks = hooks or _NO_HOOKS
        source = Path(source)
        data = source.read_bytes()
        digest = sha256_file(source)
        rel_path = safe_rel_path(rel_path or source.name)

        trust = ws.load_trust()
        gen, rule_map, rules_hash = self._current_rule_hash(trust)

        bind = build_bind(
            decision_id=decision_id, rule_generation=gen,
            rules_hash=rules_hash, artifact_name=source.name,
            rel_path=rel_path, size=len(data), digest=digest,
            issuer=issuer, controllers=list(controllers), seat=seat)
        keystore = ws.load_keystore()
        record = sign_decision(keystore, bind)

        # Scripted gate OUTSIDE the lock so a parked promoter cannot block a
        # revoker that needs the same commit lock.
        hooks.before_linearize()

        with self.commit_lock:
            # Uniqueness guard: a ticket number must not bind two digests.
            if not allow_duplicate_id:
                clash = self._find_id_digest_clash(decision_id, digest)
                if clash is not None:
                    raise PolicyDenied({"ok": False, "codes": [
                        "DECISION_ID_DIGEST_REUSE"], "clash": clash})

            # Commit-time re-read of durable revocation state = linearization.
            policy, diag = ws.load_policy_state(trust)
            verification = verify_decision_record(
                record, trust, policy, rule_map,
                current_generation=gen,
                require_current=require_current_rules)
            verification["policy_diagnostics"] = diag
            if not verification["ok"]:
                raise PolicyDenied(verification)

            dpath = ws.new_decision_path(decision_id, digest)
            atomic_write_json(dpath, record)
            info = {"decision_path": dpath, "digest": digest,
                    "rel_path": rel_path, "decision_id": decision_id}
            hooks.after_decision_persisted(info)

            event = ws.ledger.append("allow.committed", {
                "decision_id": decision_id, "digest": digest,
                "rel_path": rel_path, "record_file": dpath.name,
                "issuer": issuer, "controllers": sorted(controllers),
            })
            wm = ws.ledger.persist_watermark()
            hooks.after_audit({**info, "ledger_seq": event["seq"]})

            dest = ws.allow_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(dest, data)
            hooks.after_dir_materialized({**info, "dest": dest})

            return {"ok": True, "record": record, "decision_path": dpath,
                    "dest": dest, "ledger_event": event, "watermark": wm}

    def _find_id_digest_clash(self, decision_id: str,
                              digest: str) -> Optional[Dict[str, Any]]:
        if not self.ws.decisions_dir.exists():
            return None
        from .util import read_json
        for p in self.ws.decisions_dir.glob("*.json"):
            try:
                rec = read_json(p)
            except Exception:
                continue
            if rec.get("decision_id") == decision_id \
                    and rec.get("digest") != digest:
                return {"existing_file": p.name,
                        "existing_digest": rec.get("digest")}
        return None

    # ------------------------------------------------------------------
    # Fault injection: the hazardous "directory changed, receipt lost" state
    # ------------------------------------------------------------------
    def promote_with_lost_receipt(self, *, decision_id: str,
                                  source: Path | str, issuer: str,
                                  controllers: List[str],
                                  rel_path: Optional[str] = None,
                                  seat: Optional[str] = None,
                                  severity: str = "hard",
                                  hooks: Optional[PromoteHooks] = None
                                  ) -> Dict[str, Any]:
        """Simulate a crash in the unsafe directory-before-commit window.

        severity="hard": directory bytes survive, but neither the signed
        decision record nor the audit receipt does (the opening incident).
        severity="receipt_only": the signed decision record survives but the
        hash-chained audit append/watermark receipt was lost.
        """
        ws = self.ws
        hooks = hooks or _NO_HOOKS
        source = Path(source)
        data = source.read_bytes()
        digest = sha256_file(source)
        rel_path = safe_rel_path(rel_path or source.name)

        trust = ws.load_trust()
        gen, rule_map, rules_hash = self._current_rule_hash(trust)
        bind = build_bind(
            decision_id=decision_id, rule_generation=gen,
            rules_hash=rules_hash, artifact_name=source.name,
            rel_path=rel_path, size=len(data), digest=digest,
            issuer=issuer, controllers=list(controllers), seat=seat)
        record = sign_decision(ws.load_keystore(), bind)

        # HAZARDOUS ORDER: mutate the allowed directory first.
        dest = ws.allow_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(dest, data)
        info = {"digest": digest, "rel_path": rel_path, "dest": dest,
                "decision_id": decision_id}
        hooks.after_dir_changed_unsafe(info)

        if severity == "hard":
            # Commit + audit receipt both lost; signed record never persisted.
            return {"ok": False, "dir_changed": True,
                    "decision_written": False, "ledger_written": False,
                    "severity": severity, **info}

        if severity == "receipt_only":
            dpath = ws.new_decision_path(decision_id, digest)
            atomic_write_json(dpath, record)
            # Deliberately NO ledger.append / persist_watermark: receipt lost.
            return {"ok": True, "dir_changed": True,
                    "decision_written": True, "ledger_written": False,
                    "decision_path": dpath, "severity": severity, **info}

        raise ValueError(f"unknown loss severity: {severity}")
