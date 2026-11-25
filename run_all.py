#!/usr/bin/env python3
"""run_all - one-command verification + report generator.

Runs, in order:
  1. Ed25519 RFC 8032 self-test;
  2. the fast unittest suite;
  3. the three deterministic two-thread barrier cases;
  4. the exhaustive short-interleaving model;
  5. a clean golden drill workspace;
  6. the sharded 60,000-record partial-vs-full comparison.

Writes ``verification_report.json`` and ``REPORT.md`` at the repository root
(and a JSON copy under ``artifacts/reports/``) using the *actual* measured
counts.  Exits 0 only if every check passes.

Usage:
  python run_all.py              # full run incl. 60k records
  python run_all.py --quick      # small scale dataset instead of 60k
  python run_all.py --skip-unittest
"""

from __future__ import annotations

import argparse
import io
import json
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from isolation import ed25519                       # noqa: E402
from isolation.modelcheck import run_model_check    # noqa: E402
from isolation.pki import SEAT_BACKUP, SEAT_MAIN    # noqa: E402
from isolation.reconstructor import reconstruct     # noqa: E402
from isolation.report import render_markdown        # noqa: E402
from isolation.scenarios import run_all_barrier_cases  # noqa: E402
from isolation.scale import run_scale_comparison    # noqa: E402
from isolation.util import now_iso                  # noqa: E402
from isolation.workspace import Workspace           # noqa: E402
from isolation.engine import Engine                # noqa: E402


def _section(name):
    print("\n" + "=" * 72)
    print(name)
    print("=" * 72)


def run_unittest_suite() -> dict:
    _section("2/6 unittest suite")
    import tests.test_isolation as ti
    suite = unittest.defaultTestLoader.loadTestsFromModule(ti)
    buf = io.StringIO()
    result = unittest.TextTestRunner(
        stream=buf, verbosity=2, failfast=False).run(suite)
    out = buf.getvalue()
    tail = "\n".join(out.splitlines()[-40:])
    print(tail)
    return {
        "ok": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "output_tail": out[-8000:],
    }


def build_golden_drill() -> dict:
    _section("5/6 golden drill workspace (artifacts/drill)")
    ws = Workspace(ROOT / "artifacts" / "drill").initialize(clean=True)
    eng = Engine(ws)

    a1 = ws.write_artifact("hello.txt",
                           "allowed synthetic release hello\n".encode())
    eng.promote(
        decision_id="ALLOW-0001", source=a1, issuer="issuer.ivan",
        controllers=["ctrl.alice", "ctrl.bob"],
        rel_path="docs/hello.txt", seat=SEAT_MAIN)

    a2 = ws.write_artifact("tool.drill",
                           b"DRILL-BINARY-" + bytes(range(32)) * 4)
    eng.promote(
        decision_id="ALLOW-0002", source=a2, issuer="issuer.nora",
        controllers=["ctrl.alice", "ctrl.bob"],
        rel_path="bin/tool.drill", seat=SEAT_BACKUP)

    rec = reconstruct(ws.root)
    print("golden drill summary:", json.dumps(rec["summary"], ensure_ascii=False))
    return {"ok": rec["clean"], "summary": rec["summary"],
            "watermark": rec["watermark"]["current_status"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="use a small scale dataset")
    ap.add_argument("--scale-records", type=int, default=60_000)
    ap.add_argument("--scale-shards", type=int, default=120)
    ap.add_argument("--partial-shards", type=int, default=4)
    ap.add_argument("--skip-unittest", action="store_true")
    ap.add_argument("--force-scale", action="store_true")
    args = ap.parse_args(argv)

    if args.quick:
        args.scale_records = 1_200
        args.scale_shards = 12
        args.partial_shards = 2

    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)

    report: dict = {
        "generated_at": now_iso(),
        "python": sys.version.replace("\n", " "),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }
    timings: dict = {}

    _section("1/6 Ed25519 self-test")
    t = time.perf_counter()
    report["crypto_selftest"] = ed25519.selftest()
    timings["crypto"] = round(time.perf_counter() - t, 2)
    print("crypto ok:", report["crypto_selftest"]["ok"])

    if args.skip_unittest:
        report["unit_tests"] = {"ok": True, "skipped_cli": True}
    else:
        t = time.perf_counter()
        try:
            report["unit_tests"] = run_unittest_suite()
        except Exception as exc:  # noqa: BLE001
            import traceback
            report["unit_tests"] = {
                "ok": False, "fatal": repr(exc),
                "traceback": traceback.format_exc()}
        timings["unittest"] = round(time.perf_counter() - t, 2)

    _section("3/6 barrier cases (two threads + Barrier)")
    t = time.perf_counter()
    try:
        report["barrier"] = run_all_barrier_cases(artifacts / "barrier")
    except Exception as exc:  # noqa: BLE001
        import traceback
        report["barrier"] = {"ok": False, "cases": [], "fatal": repr(exc),
                             "traceback": traceback.format_exc()}
    timings["barrier"] = round(time.perf_counter() - t, 2)
    print("barrier ok:", report["barrier"].get("ok"),
          report["barrier"].get("checks_passed"), "/",
          report["barrier"].get("checks_total"))

    _section("4/6 exhaustive interleaving model")
    t = time.perf_counter()
    try:
        report["model"] = run_model_check()
    except Exception as exc:  # noqa: BLE001
        import traceback
        report["model"] = {"ok": False, "fatal": repr(exc),
                           "traceback": traceback.format_exc()}
    timings["model"] = round(time.perf_counter() - t, 2)
    m = report["model"]
    print(f"model ok={m.get('ok')} "
          f"interleavings={m.get('interleavings_enumerated')} "
          f"prefix_states={m.get('prefix_states_checked')} "
          f"naive_counterexamples={m.get('naive_dir_trust_counterexample_total')}")

    try:
        report["golden_drill"] = build_golden_drill()
    except Exception as exc:  # noqa: BLE001
        import traceback
        report["golden_drill"] = {"ok": False, "fatal": repr(exc),
                                  "traceback": traceback.format_exc()}

    _section("6/6 sharded scale comparison "
             f"({args.scale_records} records / {args.scale_shards} dirs)")
    t = time.perf_counter()
    try:
        report["scale"] = run_scale_comparison(
            artifacts / "scale_runs",
            records=args.scale_records, shards=args.scale_shards,
            partial_shards=args.partial_shards, force=args.force_scale)
    except Exception as exc:  # noqa: BLE001
        import traceback
        report["scale"] = {"ok": False, "fatal": repr(exc),
                           "traceback": traceback.format_exc()}
    timings["scale"] = round(time.perf_counter() - t, 2)
    sc = report["scale"]
    if sc.get("ok"):
        print("partial:", sc["actual_inspected_directories_and_files"]["partial"])
        print("full   :", sc["actual_inspected_directories_and_files"]["full"])
        print("equivalence mismatches:",
              sc["equivalence"]["mismatch_count"])
    else:
        print("SCALE SECTION FAILED:",
              sc.get("fatal")
              or sc.get("equivalence", {}).get("first_mismatches")
              or sc.get("equivalence"))

    report["timings_seconds"] = timings
    report["overall_ok"] = all([
        report["crypto_selftest"].get("ok"),
        report["unit_tests"].get("ok"),
        report["barrier"].get("ok"),
        report["model"].get("ok"),
        report.get("golden_drill", {}).get("ok"),
        report["scale"].get("ok"),
    ])

    json_path = ROOT / "verification_report.json"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    reports_dir = artifacts / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "verification_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    md = render_markdown(report)
    (ROOT / "REPORT.md").write_text(md, encoding="utf-8")
    (reports_dir / "REPORT.md").write_text(md, encoding="utf-8")

    _section("DONE")
    print("overall_ok:", report["overall_ok"])
    print("wrote", json_path)
    print("wrote", ROOT / "REPORT.md")
    print("timings:", timings)
    return 0 if report["overall_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
