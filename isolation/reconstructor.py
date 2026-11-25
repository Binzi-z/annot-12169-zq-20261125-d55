"""Rebuild the *truly allowed* artifacts from files + signature records.

This is the heart of the restart story.  It does **not** trust the allowed
directory, a status flag or the persisted watermark.  Instead it:

1. verifies every signed decision record against the pinned synthetic PKI,
   the rule-generation record and the current revocation/appointment state;
2. detects same-id/different-digest conflicts and fails closed;
3. walks the real allowed directory, hashes every file and matches on
   ``(relative path, actual sha256)``;
4. classifies every present file and every grounded-but-missing record;
5. optionally quarantines non-allowed files (move, never delete);
6. independently re-verifies the hash chain and every historical watermark.

The standalone CLI lives in ``reconstruct.py``.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .decision import verify_decision_record
from .ledger import verify_watermarks
from .util import ScanCounters, read_json, read_jsonl, sha256_file
from .workspace import Workspace

NON_ALLOWED_STATUSES = {
    "ORPHAN_NO_DECISION", "DIGEST_MISMATCH", "PATH_BINDING_MISMATCH",
    "ID_DIGEST_CONFLICT",
}


def reconstruct(root: Path | str, *, quarantine: bool = False,
                update_watermark: bool = False,
                require_current_rules: bool = False,
                counters: Optional[ScanCounters] = None) -> Dict[str, Any]:
    ws = Workspace(root)
    counters = counters or ScanCounters()
    trust = ws.load_trust()
    rule_map = ws.verified_rule_map(trust)
    current_gen = ws.current_generation()
    policy, policy_diag = ws.load_policy_state(trust)

    # ------------------------------------------------------------------
    # 1. verify all signed decision records
    # ------------------------------------------------------------------
    record_verdicts: List[Dict[str, Any]] = []
    if ws.decisions_dir.exists():
        for rp in sorted(ws.decisions_dir.glob("*.json")):
            counters.record_files_read += 1
            try:
                rec = read_json(rp)
            except Exception as exc:
                record_verdicts.append({
                    "file": rp.name, "rec": {}, "bind": {},
                    "verdict": {"ok": False, "codes": ["JSON_PARSE_ERROR"],
                                "primary": "JSON_PARSE_ERROR"},
                })
                continue
            verdict = verify_decision_record(
                rec, trust, policy, rule_map,
                current_generation=current_gen,
                require_current=require_current_rules)
            record_verdicts.append({
                "file": rp.name, "rec": rec, "bind": verdict.get("bind", {}),
                "verdict": verdict,
            })

    valid = [rv for rv in record_verdicts if rv["verdict"]["ok"]]
    invalid_records = [{
        "file": rv["file"],
        "decision_id": rv["bind"].get("decision_id"),
        "codes": rv["verdict"]["codes"],
        "primary": rv["verdict"]["primary"],
    } for rv in record_verdicts if not rv["verdict"]["ok"]]

    # ------------------------------------------------------------------
    # 2. same-id / different-digest conflict detection (fail closed)
    # ------------------------------------------------------------------
    by_id: Dict[str, List[Dict[str, Any]]] = {}
    for rv in valid:
        did = rv["bind"].get("decision_id")
        by_id.setdefault(did, []).append(rv)

    conflicts: List[Dict[str, Any]] = []
    conflict_ids = set()
    # authorized key -> representative verdict
    authorized: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for did, rvs in by_id.items():
        digests = sorted({rv["bind"].get("digest") for rv in rvs})
        if len(digests) > 1:
            conflict_ids.add(did)
            conflicts.append({
                "decision_id": did,
                "digests": digests,
                "record_files": [rv["file"] for rv in rvs],
            })
            continue  # unresolved conflict: authorize nothing for this id
        for rv in rvs:
            key = (rv["bind"].get("rel_path"), rv["bind"].get("digest"))
            authorized.setdefault(key, rv)

    # Ledger receipts (used only to flag missing audit receipts).
    ledger_events = read_jsonl(ws.audit_path)
    receipt_files = {
        (e.get("payload") or {}).get("record_file")
        for e in ledger_events if e.get("type") == "allow.committed"
    }

    # ------------------------------------------------------------------
    # 3+4. walk the real allow directory and classify each actual file
    # ------------------------------------------------------------------
    files: List[Dict[str, Any]] = []
    truly_allowed: List[Dict[str, Any]] = []
    seen_exact_keys = set()
    quarantined: List[Dict[str, str]] = []

    allow_dir = ws.allow_dir
    allow_dir.mkdir(parents=True, exist_ok=True)

    for dirpath, dirnames, filenames in os.walk(allow_dir):
        counters.directories_scanned += 1
        dpath = Path(dirpath)
        for name in sorted(filenames):
            if name.endswith(".tmp"):
                continue
            fpath = dpath / name
            counters.artifact_files_hashed += 1
            actual = sha256_file(fpath)
            try:
                counters.bytes_hashed += fpath.stat().st_size
            except OSError:
                pass
            rel = fpath.relative_to(allow_dir).as_posix()

            exact = authorized.get((rel, actual))
            exact_invalid = _find_exact_invalid(
                record_verdicts, rel, actual)
            same_path = [rv for rv in record_verdicts
                         if rv["bind"].get("rel_path") == rel]
            digest_valid = [rv for rv in valid
                            if rv["bind"].get("digest") == actual]
            exact_valid_conflict = any(
                rv["bind"].get("rel_path") == rel
                and rv["bind"].get("digest") == actual
                and rv["bind"].get("decision_id") in conflict_ids
                for rv in valid)

            audit_receipt_missing = False
            if exact is not None:
                status = "ALLOWED"
                seen_exact_keys.add((rel, actual))
                if exact["file"] not in receipt_files:
                    audit_receipt_missing = True
                entry = {
                    "rel_path": rel, "digest": actual,
                    "decision_id": exact["bind"].get("decision_id"),
                    "issuer": exact["bind"].get("issuer"),
                    "controllers": exact["bind"].get("controllers"),
                    "record_file": exact["file"],
                    "audit_receipt_missing": audit_receipt_missing,
                }
                truly_allowed.append(entry)
            elif exact_valid_conflict:
                status = "ID_DIGEST_CONFLICT"
            elif exact_invalid is not None:
                status = "BLOCKED:" + exact_invalid["verdict"]["primary"]
            elif same_path:
                status = "DIGEST_MISMATCH"
            elif digest_valid:
                status = "PATH_BINDING_MISMATCH"
            else:
                status = "ORPHAN_NO_DECISION"

            file_entry = {
                "rel_path": rel, "actual_digest": actual,
                "size": _safe_size(fpath), "status": status,
            }
            if audit_receipt_missing:
                file_entry["audit_receipt_missing"] = True
            files.append(file_entry)

            # ----------------------------------------------------------
            # 5. quarantine anything not truly allowed (move, never delete)
            # ----------------------------------------------------------
            if quarantine and status != "ALLOWED":
                dest = _quarantine_dest(ws.recon_quarantine_dir, rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(fpath), str(dest))
                quarantined.append({
                    "rel_path": rel, "status": status,
                    "moved_to": str(dest.relative_to(ws.root)).replace("\\", "/"),
                })

    # ------------------------------------------------------------------
    # missing: grounded authorizations whose exact bytes are not on disk
    # ------------------------------------------------------------------
    missing: List[Dict[str, Any]] = []
    for (rel, digest), rv in authorized.items():
        if (rel, digest) in seen_exact_keys:
            continue
        present_path = allow_dir / rel
        if present_path.exists():
            note = "PATH_PRESENT_WITH_OTHER_DIGEST"
        else:
            note = "FILE_ABSENT"
        missing.append({
            "rel_path": rel, "expected_digest": digest,
            "decision_id": rv["bind"].get("decision_id"),
            "record_file": rv["file"], "note": note,
        })

    # ------------------------------------------------------------------
    # 6. watermark / history re-verification (+ optional repair)
    # ------------------------------------------------------------------
    watermark = verify_watermarks(
        ws.audit_path, ws.watermark_path, ws.watermark_history_path)
    watermark_updated = False
    if update_watermark and watermark["chain"]["ok"] \
            and watermark["current_status"] in ("STALE", "DIVERGED", "MISSING"):
        led = ws.ledger  # opening a Ledger re-verifies the chain
        led.persist_watermark()
        watermark_updated = True
        watermark = verify_watermarks(
            ws.audit_path, ws.watermark_path, ws.watermark_history_path)

    status_counts: Dict[str, int] = {}
    for f in files:
        status_counts[f["status"]] = status_counts.get(f["status"], 0) + 1

    n_audit_gaps = sum(1 for e in truly_allowed
                       if e.get("audit_receipt_missing"))
    result = {
        "root": str(ws.root),
        "allow_dir": str(ws.allow_dir),
        "truly_allowed": truly_allowed,
        "files": files,
        "missing": missing,
        "conflicts": conflicts,
        "invalid_records": invalid_records,
        "policy_diagnostics": policy_diag,
        "quarantined": quarantined,
        "watermark": {
            "ok": watermark["ok"],
            "chain_ok": watermark["chain"]["ok"],
            "chain_events": watermark["chain"]["events"],
            "current_status": watermark["current_status"],
            "recomputed_head": watermark["recomputed_head"],
            "history_points": watermark["history_points"],
            "history_ok": watermark["history_ok"],
            "updated": watermark_updated,
            "reason": watermark["chain"]["reason"],
        },
        "audit_receipt_gaps": n_audit_gaps,
        "counts": counters.as_dict(),
        "summary": {
            "decision_records": len(record_verdicts),
            "valid_records": len(valid),
            "invalid_records": len(invalid_records),
            "allowed": len(truly_allowed),
            "files_present": len(files),
            "missing_authorizations": len(missing),
            "conflicts": len(conflicts),
            "quarantined": len(quarantined),
            "audit_receipt_gaps": n_audit_gaps,
            "status_counts": status_counts,
        },
    }
    result["clean"] = _is_clean(result)
    return result


def _is_clean(result: Dict[str, Any]) -> bool:
    """A clean reconstruction has every present file allowed, no integrity
    warnings, no audit-receipt gaps and a verifiable watermark/history."""
    s = result["summary"]
    return (
        all(f["status"] == "ALLOWED" for f in result["files"])
        and not result["conflicts"]
        and not result["invalid_records"]
        and not result["missing"]
        and not result["policy_diagnostics"]
        and s.get("audit_receipt_gaps", 0) == 0
        and result["watermark"]["ok"]
    )


def _find_exact_invalid(verdicts: List[Dict[str, Any]], rel: str,
                        digest: str) -> Optional[Dict[str, Any]]:
    for rv in verdicts:
        b = rv["bind"]
        if (not rv["verdict"]["ok"] and b.get("rel_path") == rel
                and b.get("digest") == digest):
            return rv
    return None


def _safe_size(p: Path) -> Optional[int]:
    try:
        return p.stat().st_size
    except OSError:
        return None


def _quarantine_dest(base: Path, rel: str) -> Path:
    dest = base / rel
    if not dest.exists():
        return dest
    stem = dest.stem
    suffix = dest.suffix
    parent = dest.parent
    i = 1
    while True:
        cand = parent / f"{stem}.conflict{i}{suffix}"
        if not cand.exists():
            return cand
        i += 1
