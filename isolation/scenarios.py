"""Deterministic two-worker-thread barrier retests.

Each case starts a *revocation* worker and a *promotion* worker and uses a
real :class:`threading.Barrier` plus ordering events to force one specific
linearization without sleeps:

1. ``revoke_first``          - revocation is durably persisted before the
                                promoter's commit-time recheck -> denied; also
                                proves same-root proxy cannot backfill.
2. ``lost_receipt``           - directory is mutated but the audit receipt
                                (and, in the hard variant, the signed record)
                                is lost -> reconstructor denies the orphan but
                                can still rebuild from a surviving signature.
3. ``same_id_diff_digest``    - one ticket number binds two different digests;
                                digest matching + conflict fail-closed + a
                                revoke-vs-promote barrier race.
"""

from __future__ import annotations

import threading
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from .engine import Engine, PolicyDenied, PromoteHooks
from .pki import SEAT_MAIN
from .reconstructor import reconstruct
from .workspace import Workspace

WAIT = 60  # seconds; generous for slow Windows + pure-python Ed25519


def _check(checks: List[Dict[str, Any]], name: str, passed: bool,
           detail: Any = None) -> bool:
    checks.append({"name": name, "passed": bool(passed), "detail": detail})
    return bool(passed)


def _wait(event: threading.Event, checks: List[Dict[str, Any]],
          name: str, timeout: float = WAIT) -> bool:
    fired = event.wait(timeout)
    _check(checks, name + " (signalled)", fired,
           None if fired else "timed out waiting for event")
    return fired


# ===========================================================================
# Case 1: revocation persisted first
# ===========================================================================

class _RevokeFirstHooks(PromoteHooks):
    def __init__(self, barrier: threading.Barrier,
                 release: threading.Event):
        self.barrier = barrier
        self.release = release

    def before_linearize(self) -> None:
        self.barrier.wait(timeout=WAIT)
        self.release.wait(timeout=WAIT)


def case_revoke_first(base: Path | str) -> Dict[str, Any]:
    base = Path(base)
    checks: List[Dict[str, Any]] = []
    try:
        ws = Workspace(base).initialize(clean=True)
        eng = Engine(ws)
        src = ws.write_artifact("firmware.bin", b"FW-v1-reverified-synthetic")

        barrier = threading.Barrier(2)
        release_promoter = threading.Event()
        revoke_persisted = threading.Event()
        errors: List[Any] = []
        promote_out: Dict[str, Any] = {}
        revoke_out: Dict[str, Any] = {}

        def revoke_worker() -> None:
            try:
                barrier.wait(timeout=WAIT)
                r = eng.revoke(
                    target_id="issuer.ivan", freeze_seat=SEAT_MAIN,
                    reason="two controllers reported issuer key compromise")
                revoke_out["path"] = str(r["path"])
                revoke_out["ledger_seq"] = r["ledger_event"]["seq"]
            except Exception as exc:  # noqa: BLE001
                errors.append(["revoke", repr(exc), traceback.format_exc()])
            finally:
                revoke_persisted.set()

        def promote_worker() -> None:
            try:
                eng.promote(
                    decision_id="ALLOW-RF-1", source=src,
                    issuer="issuer.ivan",
                    controllers=["ctrl.alice", "ctrl.bob"],
                    seat=SEAT_MAIN,
                    hooks=_RevokeFirstHooks(barrier, release_promoter))
                promote_out["succeeded"] = True
            except PolicyDenied as pd:
                promote_out["succeeded"] = False
                promote_out["codes"] = pd.verification.get("codes", [])
                promote_out["primary"] = pd.verification.get("primary")
            except Exception as exc:  # noqa: BLE001
                errors.append(["promote", repr(exc), traceback.format_exc()])

        tr = threading.Thread(target=revoke_worker, name="revoke-worker",
                              daemon=True)
        tp = threading.Thread(target=promote_worker, name="promote-worker",
                              daemon=True)
        tr.start(); tp.start()

        _wait(revoke_persisted, checks, "revoke persisted before release")

        # While the promoter is still parked, revocation must be durable...
        policy, _diag = ws.load_policy_state()
        _check(checks, "revoked issuer visible in durable policy",
               "issuer.ivan" in policy.revoked_ids)
        _check(checks, "main seat frozen durably",
               policy.frozen_seats.get(SEAT_MAIN) == "issuer.ivan")
        # ...and the promoter must not have written any decision yet.
        decision_files = list(ws.decisions_dir.glob("*.json"))
        _check(checks, "no decision written before commit recheck",
               decision_files == [], [p.name for p in decision_files])

        release_promoter.set()
        tp.join(timeout=WAIT); tr.join(timeout=WAIT)
        _check(checks, "promote thread finished", not tp.is_alive())
        _check(checks, "revoke thread finished", not tr.is_alive())
        _check(checks, "worker threads raised no unexpected error",
               not errors, errors)

        _check(checks, "promotion denied after first-persisted revocation",
               promote_out.get("succeeded") is False, promote_out)
        _check(checks, "denial cites ISSUER_REVOKED",
               "ISSUER_REVOKED" in promote_out.get("codes", []),
               promote_out.get("codes"))

        allow_files = [p for p in ws.allow_dir.rglob("*") if p.is_file()]
        _check(checks, "allowed directory stays empty", allow_files == [],
               [str(p.relative_to(ws.allow_dir)) for p in allow_files])

        # -- same-root proxy / clone cannot backfill the frozen seat --------
        proxy = _expect_denied(checks, eng, label="same-root proxy pia",
                               decision_id="ALLOW-RF-PROXY",
                               issuer="proxy.pia",
                               codes={"SAME_ROOT_PROXY_BACKFILL",
                                      "REVOKED_PRINCIPAL_PROXY"})
        _check(checks, "proxy primary is SAME_ROOT_PROXY_BACKFILL",
               proxy.get("primary") == "SAME_ROOT_PROXY_BACKFILL", proxy)

        clone = _expect_denied(checks, eng, label="same-root clone ivan2",
                               decision_id="ALLOW-RF-CLONE",
                               issuer="issuer.ivan2",
                               codes={"SAME_ROOT_PROXY_BACKFILL"})
        _check(checks, "clone denied purely by same-root seat rule",
               clone.get("primary") == "SAME_ROOT_PROXY_BACKFILL", clone)

        # Different root but no governance re-appointment yet -> fail closed.
        _expect_denied(checks, eng, label="un-governed different-root iris",
                       decision_id="ALLOW-RF-IRIS-PRE",
                       issuer="issuer.iris",
                       codes={"SUCCESSOR_NOT_GOVERNED"})

        # Governed re-anchor makes a legitimate successor possible.
        appt = eng.appoint_successor("issuer.iris", SEAT_MAIN)
        _check(checks, "governed successor appointment persisted",
               bool(appt["appointment"].get("gov_sig_b64")))
        ok_iris = eng.promote(
            decision_id="ALLOW-RF-IRIS", source=src, issuer="issuer.iris",
            controllers=["ctrl.alice", "ctrl.bob"], seat=SEAT_MAIN)
        _check(checks, "re-anchored governed successor may promote",
               ok_iris["ok"] is True)

        rec = reconstruct(ws.root)
        _check(checks, "reconstructor allows exactly the governed successor",
               rec["summary"]["allowed"] == 1, rec["summary"])
        _check(checks, "case workspace reconstructs clean",
               rec["clean"] is True, rec["summary"])

    except Exception as exc:  # noqa: BLE001
        return {"id": "revoke_first_durable", "ok": False, "checks": checks,
                "fatal": repr(exc), "traceback": traceback.format_exc()}

    ok = all(c["passed"] for c in checks)
    return {"id": "revoke_first_durable", "ok": ok, "checks": checks}


def _expect_denied(checks: List[Dict[str, Any]], eng: Engine, *, label: str,
                   decision_id: str, issuer: str,
                   codes: set) -> Dict[str, Any]:
    try:
        # A tiny distinct source per attempt keeps digests readable.
        ws = eng.ws
        src = ws.write_artifact(
            decision_id.lower() + ".bin",
            ("bytes-for-" + decision_id).encode())
        eng.promote(decision_id=decision_id, source=src, issuer=issuer,
                    controllers=["ctrl.alice", "ctrl.bob"], seat=SEAT_MAIN)
        _check(checks, f"{label} denied", False, "promotion unexpectedly allowed")
        return {"codes": [], "primary": None}
    except PolicyDenied as pd:
        got = set(pd.verification.get("codes", []))
        overlap = codes & got
        _check(checks, f"{label} denied by policy", True)
        _check(checks, f"{label} carries one of {sorted(codes)}",
               bool(overlap), pd.verification.get("codes"))
        return {"codes": pd.verification.get("codes", []),
                "primary": pd.verification.get("primary")}


# ===========================================================================
# Case 2: directory changed but audit receipt lost
# ===========================================================================

class _DirChangedHooks(PromoteHooks):
    def __init__(self, barrier: threading.Barrier):
        self.barrier = barrier

    def after_dir_changed_unsafe(self, info: Dict[str, Any]) -> None:
        self.barrier.wait(timeout=WAIT)


def _lost_receipt_severity(base: Path, severity: str) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    ws = Workspace(base).initialize(clean=True)
    eng = Engine(ws)
    fname = "hotfix.bin" if severity == "hard" else "patch-signed.bin"
    decision_id = "ALLOW-LR-HARD" if severity == "hard" else "ALLOW-LR-RECEIPT"
    src = ws.write_artifact(fname, b"urgent change that skipped durable commit")

    barrier = threading.Barrier(2)
    done = threading.Event()
    errors: List[Any] = []
    promo_out: Dict[str, Any] = {}

    def promote_worker() -> None:
        try:
            out = eng.promote_with_lost_receipt(
                decision_id=decision_id, source=src, issuer="issuer.nora",
                controllers=["ctrl.alice", "ctrl.bob"],
                rel_path=f"updates/{fname}", seat="SEAT-ISSUER-BACKUP",
                severity=severity,
                hooks=_DirChangedHooks(barrier))
            promo_out.update(out)
        except Exception as exc:  # noqa: BLE001
            errors.append(["promote", repr(exc), traceback.format_exc()])
        finally:
            done.set()

    def revoke_worker() -> None:
        try:
            barrier.wait(timeout=WAIT)
            # An unrelated concurrent revocation, durably committed.
            eng.revoke(decision_id="OLD-CLEARANCE-77",
                       reason="concurrent stale clearance revocation")
        except Exception as exc:  # noqa: BLE001
            errors.append(["revoke", repr(exc), traceback.format_exc()])

    tp = threading.Thread(target=promote_worker, name=f"promote-{severity}",
                          daemon=True)
    tr = threading.Thread(target=revoke_worker, name="revoke-lr", daemon=True)
    tp.start(); tr.start()
    _wait(done, checks, f"{severity} promotion/loss worker finished")
    tp.join(timeout=WAIT); tr.join(timeout=WAIT)
    _check(checks, "threads finished", not tp.is_alive() and not tr.is_alive())
    _check(checks, "no unexpected thread error", not errors, errors)
    _check(checks, "directory was actually changed",
           promo_out.get("dir_changed") is True, promo_out)

    rel = f"updates/{fname}"
    present = (ws.allow_dir / rel).exists()
    _check(checks, "file physically present in allow dir after restart", present)

    rec = reconstruct(ws.root)
    entry = next((f for f in rec["files"] if f["rel_path"] == rel), None)
    _check(checks, "reconstructor inspected the changed file", entry is not None)

    if severity == "hard":
        _check(checks, "hard loss leaves no signed decision",
               promo_out.get("decision_written") is False)
        _check(checks, "orphan classified ORPHAN_NO_DECISION",
               entry and entry["status"] == "ORPHAN_NO_DECISION", entry)
        _check(checks, "orphan is not truly allowed",
               rec["summary"]["allowed"] == 0, rec["summary"])

        q = reconstruct(ws.root, quarantine=True)
        _check(checks, "orphan quarantined (moved, not deleted)",
               q["summary"]["quarantined"] == 1, q["quarantined"])
        after = reconstruct(ws.root)
        _check(checks, "allow dir empty and clean after quarantine",
               after["summary"]["files_present"] == 0 and after["clean"],
               after["summary"])
    else:
        _check(checks, "signed decision record survived",
               promo_out.get("decision_written") is True)
        _check(checks, "receipt loss flagged on allowed entry",
               entry and entry["status"] == "ALLOWED"
               and entry.get("audit_receipt_missing") is True, entry)
        _check(checks, "rebuild still allows via signature record",
               rec["summary"]["allowed"] == 1
               and rec["audit_receipt_gaps"] == 1, rec["summary"])
        _check(checks, "ledger chain itself remains verifiable",
               rec["watermark"]["chain_ok"] is True, rec["watermark"])

        # Corrupt/lower the persisted watermark, then recompute + repair.
        from .util import atomic_write_json
        atomic_write_json(ws.watermark_path,
                          {"seq": 0, "hash": "0" * 64, "updated_at": "stale"})
        repaired = reconstruct(ws.root, update_watermark=True)
        _check(checks, "stale watermark detected and repaired to MATCH",
               repaired["watermark"]["updated"] is True
               and repaired["watermark"]["current_status"] == "MATCH",
               repaired["watermark"])
        _check(checks, "historical watermarks remain re-verifiable",
               repaired["watermark"]["history_ok"] is True,
               repaired["watermark"])

    return {"id": f"lost_receipt_{severity}", "ok": all(c["passed"] for c in checks),
            "severity": severity, "checks": checks}


def case_lost_receipt(base: Path | str) -> Dict[str, Any]:
    base = Path(base)
    hard = _lost_receipt_severity(base / "hard", "hard")
    receipt = _lost_receipt_severity(base / "receipt_only", "receipt_only")
    checks_ok = hard["ok"] and receipt["ok"]
    return {"id": "dir_changed_audit_receipt_lost", "ok": checks_ok,
            "variants": [hard, receipt]}


# ===========================================================================
# Case 3: same number, different digest
# ===========================================================================

def _conflict_subcase(base: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    ws = Workspace(base).initialize(clean=True)
    eng = Engine(ws)
    good = ws.write_artifact("c-good.bin", b"DUP-C canonical good contents")
    evil = ws.write_artifact("c-evil.bin", b"DUP-C EVIL substituted contents!!")

    eng.promote(decision_id="DUP-C", source=good, issuer="issuer.nora",
                controllers=["ctrl.alice", "ctrl.bob"], rel_path="dupc.bin",
                seat="SEAT-ISSUER-BACKUP")
    # A partitioned/confused signer reuses the number for different bytes.
    eng.promote(decision_id="DUP-C", source=evil, issuer="issuer.nora",
                controllers=["ctrl.alice", "ctrl.bob"], rel_path="dupc.bin",
                seat="SEAT-ISSUER-BACKUP", allow_duplicate_id=True)

    rec = reconstruct(ws.root)
    conflict = next((c for c in rec["conflicts"]
                     if c["decision_id"] == "DUP-C"), None)
    _check(checks, "same-id/different-digest conflict detected",
           conflict is not None and len(conflict["digests"]) == 2, conflict)
    entry = next((f for f in rec["files"] if f["rel_path"] == "dupc.bin"), None)
    _check(checks, "on-disk variant blocked as ID_DIGEST_CONFLICT",
           entry and entry["status"] == "ID_DIGEST_CONFLICT", entry)
    _check(checks, "conflicting id authorizes nothing",
           all(a["decision_id"] != "DUP-C" for a in rec["truly_allowed"]))
    return {"id": "same_id_diff_digest_conflict",
            "ok": all(c["passed"] for c in checks), "checks": checks}


class _RacePromoteHooks(PromoteHooks):
    def __init__(self, barrier: threading.Barrier, done: threading.Event):
        self.barrier = barrier
        self.done = done

    def before_linearize(self) -> None:
        self.barrier.wait(timeout=WAIT)

    def after_dir_materialized(self, info: Dict[str, Any]) -> None:
        self.done.set()  # released while commit lock still held; revoker waits


def _race_subcase(base: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    ws = Workspace(base).initialize(clean=True)
    eng = Engine(ws)
    good_bytes = b"DUP-9 legitimately signed build bytes"
    evil_bytes = b"DUP-9 different EVIL digest build!!!!"
    good = ws.write_artifact("dup9-good.bin", good_bytes)
    evil = ws.write_artifact("dup9-evil.bin", evil_bytes)

    # Legitimate pre-existing issuance for DUP-9 / GOOD.
    eng.promote(decision_id="DUP-9", source=good, issuer="issuer.ivan",
                controllers=["ctrl.alice", "ctrl.bob"],
                rel_path="dup9/payload.bin", seat=SEAT_MAIN)
    from .util import sha256_hex
    good_digest = sha256_hex(good_bytes)
    evil_digest = sha256_hex(evil_bytes)
    _check(checks, "fixture digests really differ", good_digest != evil_digest)

    barrier = threading.Barrier(2)
    promote_done = threading.Event()
    errors: List[Any] = []
    promote_out: Dict[str, Any] = {}

    def promote_worker() -> None:
        try:
            r = eng.promote(
                decision_id="DUP-9", source=evil, issuer="issuer.ivan",
                controllers=["ctrl.alice", "ctrl.bob"],
                rel_path="dup9/payload.bin", seat=SEAT_MAIN,
                allow_duplicate_id=True,
                hooks=_RacePromoteHooks(barrier, promote_done))
            promote_out["succeeded"] = True
            promote_out["digest"] = r["record"]["digest"]
        except PolicyDenied as pd:
            promote_out["succeeded"] = False
            promote_out["codes"] = pd.verification.get("codes", [])
        except Exception as exc:  # noqa: BLE001
            errors.append(["promote", repr(exc), traceback.format_exc()])

    def revoke_worker() -> None:
        try:
            barrier.wait(timeout=WAIT)
            # Deterministic order: let the conflicting promotion commit +
            # materialize first, then durably revoke the number.
            promote_done.wait(timeout=WAIT)
            eng.revoke(decision_id="DUP-9", digest=good_digest,
                       reason="number reused with a different digest")
        except Exception as exc:  # noqa: BLE001
            errors.append(["revoke", repr(exc), traceback.format_exc()])

    tp = threading.Thread(target=promote_worker, name="promote-dup",
                          daemon=True)
    tr = threading.Thread(target=revoke_worker, name="revoke-dup", daemon=True)
    tp.start(); tr.start()
    tp.join(timeout=WAIT); tr.join(timeout=WAIT)
    _check(checks, "race threads finished", not tp.is_alive() and not tr.is_alive())
    _check(checks, "no unexpected thread error", not errors, errors)
    _check(checks, "conflicting promotion committed before revoke (scripted)",
           promote_out.get("succeeded") is True
           and promote_out.get("digest") == evil_digest, promote_out)

    on_disk = (ws.allow_dir / "dup9" / "payload.bin").read_bytes()
    _check(checks, "on-disk bytes are the EVIL variant", on_disk == evil_bytes)

    rec = reconstruct(ws.root)
    entry = next((f for f in rec["files"]
                  if f["rel_path"] == "dup9/payload.bin"), None)
    _check(checks, "EVIL variant blocked after number revocation",
           entry and entry["status"] == "BLOCKED:DECISION_REVOKED", entry)
    _check(checks, "DUP-9 authorizes nothing after revocation",
           all(a["decision_id"] != "DUP-9" for a in rec["truly_allowed"]))
    _check(checks, "both digest variants recorded as revoked/invalid",
           any("DECISION_REVOKED" in r["codes"]
               and r["decision_id"] == "DUP-9"
               for r in rec["invalid_records"]),
           rec["invalid_records"])
    return {"id": "same_id_diff_digest_barrier_race",
            "ok": all(c["passed"] for c in checks), "checks": checks}


def case_same_id_diff_digest(base: Path | str) -> Dict[str, Any]:
    base = Path(base)
    conflict = _conflict_subcase(base / "conflict")
    race = _race_subcase(base / "barrier_race")
    return {"id": "same_number_different_digest",
            "ok": conflict["ok"] and race["ok"],
            "subcases": [conflict, race]}


# ===========================================================================
# aggregate entry point
# ===========================================================================

def run_all_barrier_cases(out_dir: Path | str) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = [
        case_revoke_first(out_dir / "01_revoke_first"),
        case_lost_receipt(out_dir / "02_lost_receipt"),
        case_same_id_diff_digest(out_dir / "03_same_id_diff_digest"),
    ]
    total_checks = sum(
        _count_checks(c) for c in cases)
    passed_checks = sum(
        _count_passed(c) for c in cases)
    return {
        "ok": all(c["ok"] for c in cases),
        "cases": cases,
        "checks_total": total_checks,
        "checks_passed": passed_checks,
    }


def _iter_checks(case: Dict[str, Any]):
    for chk in case.get("checks", []):
        yield chk
    for v in case.get("variants", []):
        yield from _iter_checks(v)
    for sc in case.get("subcases", []):
        yield from _iter_checks(sc)


def _count_checks(case: Dict[str, Any]) -> int:
    return sum(1 for _ in _iter_checks(case))


def _count_passed(case: Dict[str, Any]) -> int:
    return sum(1 for c in _iter_checks(case) if c["passed"])
