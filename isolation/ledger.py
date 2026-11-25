"""Append-only hash-chained audit ledger and re-verifiable watermarks.

Each ledger line commits to the previous line's hash, so any edit/delete of a
historical event is detectable.  A *watermark* names the contiguous chain head
that has been durably observed.  Every persisted watermark point is appended to
``watermark_history.jsonl``; the separate reconstructor can recompute, for any
historical point, whether its ``(seq, hash)`` matches the chain prefix.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import (append_jsonl, atomic_write_json, now_iso, read_json,
                   read_jsonl, sha256_hex, canonical)

GENESIS_HASH = "0" * 64


def hash_event(body: Dict[str, Any]) -> str:
    return sha256_hex(canonical(body))


def verify_chain(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Verify contiguity, per-event hashes and prev_hash linkage."""
    prev = GENESIS_HASH
    expected_seq = 1
    for idx, rec in enumerate(events):
        seq = rec.get("seq")
        stored_hash = rec.get("hash")
        if seq != expected_seq:
            return {"ok": False, "events": len(events),
                    "break_index": idx, "break_seq": seq,
                    "reason": "SEQ_GAP", "head_seq": expected_seq - 1,
                    "head_hash": prev}
        body = {k: v for k, v in rec.items() if k != "hash"}
        if hash_event(body) != stored_hash:
            return {"ok": False, "events": len(events),
                    "break_index": idx, "break_seq": seq,
                    "reason": "EVENT_HASH_MISMATCH",
                    "head_seq": expected_seq - 1, "head_hash": prev}
        if rec.get("prev_hash") != prev:
            return {"ok": False, "events": len(events),
                    "break_index": idx, "break_seq": seq,
                    "reason": "PREV_HASH_MISMATCH",
                    "head_seq": expected_seq - 1, "head_hash": prev}
        prev = stored_hash
        expected_seq += 1
    return {"ok": True, "events": len(events), "break_index": None,
            "break_seq": None, "reason": None,
            "head_seq": expected_seq - 1, "head_hash": prev}


class Ledger:
    """In-process serialized writer.  Readers should use the static checks."""

    def __init__(self, audit_path: Path, watermark_path: Path,
                 history_path: Path):
        self.audit_path = Path(audit_path)
        self.watermark_path = Path(watermark_path)
        self.history_path = Path(history_path)
        self._lock = threading.RLock()
        events = read_jsonl(self.audit_path)
        chain = verify_chain(events)
        if not chain["ok"]:
            raise ValueError(
                f"refusing to open tampered ledger: {chain['reason']} "
                f"at seq {chain['break_seq']}"
            )
        self._seq = chain["head_seq"]
        self._last_hash = chain["head_hash"] if self._seq else GENESIS_HASH

    def append(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            seq = self._seq + 1
            body = {
                "seq": seq,
                "ts": now_iso(),
                "type": event_type,
                "payload": payload,
                "prev_hash": self._last_hash,
            }
            rec = dict(body)
            rec["hash"] = hash_event(body)
            append_jsonl(self.audit_path, rec)
            self._seq = seq
            self._last_hash = rec["hash"]
            return rec

    def persist_watermark(self) -> Dict[str, Any]:
        with self._lock:
            wm = {
                "seq": self._seq,
                "hash": self._last_hash,
                "updated_at": now_iso(),
            }
            atomic_write_json(self.watermark_path, wm)
            append_jsonl(self.history_path, wm)
            return wm

    @property
    def head(self) -> Dict[str, Any]:
        return {"seq": self._seq, "hash": self._last_hash}


def verify_watermarks(audit_path: Path, watermark_path: Path,
                      history_path: Path) -> Dict[str, Any]:
    """Recompute the chain and re-verify current + every historical mark."""
    events = read_jsonl(audit_path)
    chain = verify_chain(events)
    by_seq = {e.get("seq"): e for e in events}

    current: Optional[Dict[str, Any]] = None
    current_status = "MISSING"
    if Path(watermark_path).exists():
        try:
            current = read_json(watermark_path)
        except Exception:
            current = None
            current_status = "UNREADABLE"
        if current_status != "UNREADABLE":
            if not chain["ok"]:
                current_status = "CHAIN_BROKEN"
            elif not isinstance(current, dict):
                current_status = "UNREADABLE"
            else:
                try:
                    seq = current.get("seq")
                    if (seq == chain["head_seq"]
                            and current.get("hash") == chain["head_hash"]):
                        current_status = "MATCH"
                    elif isinstance(seq, int) and not isinstance(seq, bool) \
                            and seq < chain["head_seq"]:
                        current_status = "STALE"
                    else:
                        current_status = "DIVERGED"
                except TypeError:
                    current_status = "UNREADABLE"

    history_points = read_jsonl(history_path)
    history_checks = []
    history_ok = chain["ok"]
    for point in history_points:
        try:
            seq = point.get("seq")
            ev = by_seq.get(seq) if isinstance(seq, int) else None
            ok = bool(
                chain["ok"] and ev is not None
                and point.get("hash") == ev.get("hash")
            )
            # A historical mark at seq 0 is the genesis mark.
            if seq == 0 and point.get("hash") == GENESIS_HASH and chain["ok"]:
                ok = True
        except Exception:
            ok = False
        history_ok = history_ok and ok
        history_checks.append({
            "seq": point.get("seq") if isinstance(point, dict) else None,
            "hash": point.get("hash") if isinstance(point, dict) else None,
            "ok": ok,
            "updated_at": point.get("updated_at") if isinstance(point, dict) else None,
        })

    return {
        "chain": chain,
        "current_status": current_status,
        "current": current,
        "recomputed_head": {"seq": chain["head_seq"], "hash": chain["head_hash"]},
        "history_points": len(history_checks),
        "history_ok": history_ok,
        "history_checks": history_checks,
        "ok": chain["ok"] and history_ok and current_status in ("MATCH", "MISSING"),
    }
