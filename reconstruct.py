#!/usr/bin/env python3
"""reconstruct - separate tool to rebuild the truly allowed artifacts.

It reads the *actual files* in the allow directory and the *signed decision
records* + synthetic PKI/revocations, and reconstructs ground truth.  It never
trusts the directory listing or the stored watermark.

Examples
--------
  python reconstruct.py --root artifacts/drill
  python reconstruct.py --root artifacts/drill --quarantine
  python reconstruct.py --root artifacts/drill --update-watermark --json

Exit codes: 0 clean; 4 discrepancies found; 2 usage/state error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from isolation.reconstructor import reconstruct   # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconstruct",
        description="Rebuild truly allowed artifacts from files + signatures.")
    p.add_argument("--root", default=str(Path("artifacts") / "drill"))
    p.add_argument("--quarantine", action="store_true",
                   help="move non-allowed files aside (never delete)")
    p.add_argument("--update-watermark", action="store_true",
                   help="recompute and repair a stale/diverged watermark")
    p.add_argument("--current-rules", action="store_true",
                   help="require decisions to bind the current rule generation")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root)
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        return 2

    result = reconstruct(
        root, quarantine=args.quarantine,
        update_watermark=args.update_watermark,
        require_current_rules=args.current_rules)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        s = result["summary"]
        print(f"== reconstruction of {root} ==")
        print(f"decision records      : {s['decision_records']} "
              f"({s['valid_records']} valid, {s['invalid_records']} invalid)")
        print(f"files present/hashed  : {s['files_present']}")
        print(f"truly allowed         : {s['allowed']}")
        print(f"missing authorizations: {s['missing_authorizations']}")
        print(f"id/digest conflicts   : {s['conflicts']}")
        print(f"audit receipt gaps    : {s['audit_receipt_gaps']}")
        print(f"quarantined           : {s['quarantined']}")
        print(f"status counts         : {s['status_counts']}")
        c = result["counts"]
        print(f"actually inspected    : {c['directories_scanned']} dirs, "
              f"{c['artifact_files_hashed']} artifact files, "
              f"{c['record_files_read']} record files")
        wm = result["watermark"]
        print(f"watermark             : {wm['current_status']} "
              f"chain_ok={wm['chain_ok']} events={wm['chain_events']} "
              f"history_points={wm['history_points']} "
              f"history_ok={wm['history_ok']}")
        if result["truly_allowed"]:
            print("-- truly allowed --")
            for a in result["truly_allowed"]:
                gap = " [AUDIT RECEIPT MISSING]" if a.get(
                    "audit_receipt_missing") else ""
                print(f"  ALLOW {a['rel_path']}  {a['digest'][:16]}… "
                      f"({a['decision_id']}){gap}")
        bad = [f for f in result["files"] if f["status"] != "ALLOWED"]
        if bad:
            print("-- not allowed --")
            for f in bad:
                print(f"  {f['status']:<28} {f['rel_path']}")
        print("CLEAN" if result["clean"] else "DISCREPANCIES PRESENT")

    return 0 if result["clean"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
