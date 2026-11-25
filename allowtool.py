#!/usr/bin/env python3
"""allowtool - synthetic isolation release / allow-decision tool (Windows).

Pure Python 3.12 standard library.  All identities and artifacts are local
synthetic drill data.

Examples
--------
  python allowtool.py init
  python allowtool.py promote --id ALLOW-1 --source quarantine/app.bin \\
      --issuer issuer.ivan --controllers ctrl.alice,ctrl.bob --seat SEAT-ISSUER-MAIN
  python allowtool.py revoke --target issuer.ivan --freeze-seat SEAT-ISSUER-MAIN
  python allowtool.py appoint --holder issuer.iris --seat SEAT-ISSUER-MAIN
  python allowtool.py barrier-cases
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from isolation.engine import Engine, PolicyDenied          # noqa: E402
from isolation.pki import SEAT_MAIN                         # noqa: E402
from isolation.scenarios import run_all_barrier_cases       # noqa: E402
from isolation.workspace import Workspace                   # noqa: E402

DEFAULT_ROOT = Path("artifacts") / "drill"


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="allowtool",
        description="Synthetic isolation release tool (stdlib only).")
    p.add_argument("--root", default=str(DEFAULT_ROOT),
                   help="workspace root (default: artifacts/drill)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create synthetic PKI, rules and workspace")

    pr = sub.add_parser("promote", help="issue+commit an allow decision")
    pr.add_argument("--id", required=True, dest="decision_id")
    pr.add_argument("--source", required=True)
    pr.add_argument("--issuer", required=True)
    pr.add_argument("--controllers", required=True,
                    help="comma separated two independent controller ids")
    pr.add_argument("--rel-path", default=None)
    pr.add_argument("--seat", default=None)
    pr.add_argument("--allow-duplicate-id", action="store_true",
                    help=argparse.SUPPRESS)

    rv = sub.add_parser("revoke", help="signed durable revocation")
    rv.add_argument("--target", default=None, dest="target_id")
    rv.add_argument("--decision", default=None, dest="decision_id")
    rv.add_argument("--digest", default=None)
    rv.add_argument("--freeze-seat", default=None)
    rv.add_argument("--reason", default="cli revocation")

    ap = sub.add_parser("appoint", help="governed successor appointment")
    ap.add_argument("--holder", required=True)
    ap.add_argument("--seat", default=SEAT_MAIN)

    wa = sub.add_parser("write-artifact",
                        help="write a synthetic quarantine artifact")
    wa.add_argument("--name", required=True)
    wa.add_argument("--text", required=True)

    bc = sub.add_parser("barrier-cases",
                        help="run the 3 deterministic threaded barrier cases")
    bc.add_argument("--out", default=str(Path("artifacts") / "barrier"))

    sub.add_parser("pubkeys", help="print synthetic public keys")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root)

    if args.cmd == "init":
        ws = Workspace(root).initialize(clean=True)
        print(f"initialized synthetic workspace at {ws.root}")
        print("trust roots:", ", ".join(
            ws.load_trust()["pinned_roots"].keys()))
        return 0

    if args.cmd == "barrier-cases":
        report = run_all_barrier_cases(args.out)
        _print({"ok": report["ok"],
                "checks_passed": f'{report["checks_passed"]}/'
                                 f'{report["checks_total"]}'})
        return 0 if report["ok"] else 5

    ws = Workspace(root)
    if not ws.trust_path.exists():
        print(f"workspace not initialized at {root}; run: allowtool init",
              file=sys.stderr)
        return 2
    eng = Engine(ws)

    if args.cmd == "write-artifact":
        path = ws.write_artifact(args.name, args.text.encode("utf-8"))
        print(str(path))
        return 0

    if args.cmd == "pubkeys":
        trust = ws.load_trust()
        out = {"roots": trust["pinned_roots"],
               "governance": trust["governance"],
               "subjects": {c["subject"]: c["subject_pub"]
                            for c in trust["certs"]}}
        _print(out)
        return 0

    if args.cmd == "promote":
        controllers = [c.strip() for c in args.controllers.split(",") if c.strip()]
        if len(controllers) != 2:
            print("exactly two comma-separated controllers required",
                  file=sys.stderr)
            return 2
        try:
            res = eng.promote(
                decision_id=args.decision_id, source=Path(args.source),
                issuer=args.issuer, controllers=controllers,
                rel_path=args.rel_path, seat=args.seat,
                allow_duplicate_id=args.allow_duplicate_id)
        except PolicyDenied as pd:
            print("PROMOTION DENIED", file=sys.stderr)
            _print(pd.verification)
            return 3
        print("PROMOTED", res["dest"])
        _print({"decision_id": args.decision_id,
                "digest": res["record"]["digest"],
                "ledger_seq": res["ledger_event"]["seq"]})
        return 0

    if args.cmd == "revoke":
        rec = eng.revoke(
            target_id=args.target_id, decision_id=args.decision_id,
            digest=args.digest, freeze_seat=args.freeze_seat,
            reason=args.reason)
        print("REVOKED", rec["record"]["rev_id"], "ledger_seq",
              rec["ledger_event"]["seq"])
        return 0

    if args.cmd == "appoint":
        out = eng.appoint_successor(args.holder, args.seat)
        print("APPOINTED", args.holder, "for", args.seat)
        _print({"appt_id": out["appointment"]["appt_id"]})
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
