"""Fast unittest coverage for the isolation release drill.

Run from the repository root:

    python -m unittest discover -s tests -v
    python tests/test_isolation.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from isolation import ed25519                 # noqa: E402
from isolation.engine import Engine, PolicyDenied   # noqa: E402
from isolation.ledger import Ledger, verify_watermarks  # noqa: E402
from isolation.modelcheck import run_model_check     # noqa: E402
from isolation.pki import SEAT_MAIN           # noqa: E402
from isolation.reconstructor import reconstruct      # noqa: E402
from isolation.scenarios import (case_lost_receipt,   # noqa: E402
                                case_revoke_first,
                                case_same_id_diff_digest)
from isolation.scale import run_scale_comparison     # noqa: E402
from isolation.workspace import Workspace     # noqa: E402

ALICE_BOB = ["ctrl.alice", "ctrl.bob"]
ALICE_CARA = ["ctrl.alice", "ctrl.cara"]  # same root.alpha -> not independent


class TempDrill(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(
            prefix="iso_drill_", ignore_cleanup_errors=True)
        self.base = Path(self._td.name)
        self.ws = Workspace(self.base / "drill").initialize(clean=True)
        self.eng = Engine(self.ws)

    def tearDown(self) -> None:
        try:
            self._td.cleanup()
        except PermissionError:
            pass

    def artifact(self, name: str = "app.bin", data: bytes = b"synthetic bytes"):
        return self.ws.write_artifact(name, data)


class Ed25519Tests(unittest.TestCase):
    def test_rfc_vectors_and_roundtrip(self):
        report = ed25519.selftest()
        self.assertTrue(report["ok"], json.dumps(report, indent=2))


class GoldenPathTests(TempDrill):
    def test_valid_two_controller_decision_is_allowed_and_clean(self):
        src = self.artifact()
        self.eng.promote(
            decision_id="ALLOW-1", source=src, issuer="issuer.ivan",
            controllers=ALICE_BOB, seat=SEAT_MAIN)
        rec = reconstruct(self.ws.root)
        self.assertEqual(rec["summary"]["allowed"], 1)
        self.assertTrue(rec["clean"], rec["summary"])
        self.assertEqual(
            rec["truly_allowed"][0]["controllers"], sorted(ALICE_BOB))

    def test_restart_with_unsigned_orphan_is_denied_then_quarantined(self):
        # The opening incident: bytes appear in allow with no signed decision.
        (self.ws.allow_dir / "mystery.bin").write_bytes(b"re-verified but unsigned")
        rec = reconstruct(self.ws.root)
        self.assertEqual(rec["summary"]["allowed"], 0)
        self.assertFalse(rec["clean"])
        self.assertEqual(rec["files"][0]["status"], "ORPHAN_NO_DECISION")

        q = reconstruct(self.ws.root, quarantine=True)
        self.assertEqual(q["summary"]["quarantined"], 1)
        after = reconstruct(self.ws.root)
        self.assertEqual(after["summary"]["files_present"], 0)
        self.assertTrue(after["clean"])

    def test_tampered_bytes_are_digest_mismatch(self):
        src = self.artifact(data=b"original payload")
        self.eng.promote(
            decision_id="ALLOW-T", source=src, issuer="issuer.ivan",
            controllers=ALICE_BOB, rel_path="app.bin", seat=SEAT_MAIN)
        # Post-issuance substitution at the same path.
        (self.ws.allow_dir / "app.bin").write_bytes(b"tampered payload!!")
        rec = reconstruct(self.ws.root)
        self.assertFalse(rec["clean"])
        self.assertEqual(rec["files"][0]["status"], "DIGEST_MISMATCH")
        self.assertEqual(rec["summary"]["allowed"], 0)

    def test_same_root_controllers_rejected_as_not_independent(self):
        src = self.artifact(name="same-root.bin")
        with self.assertRaises(PolicyDenied) as ctx:
            self.eng.promote(
                decision_id="ALLOW-SR", source=src, issuer="issuer.ivan",
                controllers=ALICE_CARA, seat=SEAT_MAIN)
        joined = " ".join(ctx.exception.verification["codes"])
        self.assertIn("CONTROLLERS_NOT_INDEPENDENT", joined)

    def test_bad_controller_signature_rejected(self):
        # Sign with alice, then corrupt the stored approval signature.
        src = self.artifact(name="badsig.bin")
        res = self.eng.promote(
            decision_id="ALLOW-BS", source=src, issuer="issuer.ivan",
            controllers=ALICE_BOB, seat=SEAT_MAIN)
        path = res["decision_path"]
        doc = json.loads(path.read_text(encoding="utf-8"))
        chars = list(doc["approvals"][1]["sig_b64"])
        chars[10] = "B" if chars[10] != "B" else "C"
        doc["approvals"][1]["sig_b64"] = "".join(chars)
        path.write_text(json.dumps(doc), encoding="utf-8")
        rec = reconstruct(self.ws.root)
        self.assertFalse(rec["clean"])
        self.assertTrue(any("CONTROLLER_SIG_BAD" in c
                            for r in rec["invalid_records"] for c in r["codes"]))


class AntiBackfillTests(TempDrill):
    def test_revoked_issuer_and_same_root_proxy_denied(self):
        self.eng.revoke(target_id="issuer.ivan", freeze_seat=SEAT_MAIN)
        policy, _ = self.ws.load_policy_state()
        self.assertIn("issuer.ivan", policy.revoked_ids)
        self.assertEqual(policy.frozen_seats[SEAT_MAIN], "issuer.ivan")

        for issuer, expected in (
            ("proxy.pia", "SAME_ROOT_PROXY_BACKFILL"),
            ("issuer.ivan2", "SAME_ROOT_PROXY_BACKFILL"),
        ):
            src = self.artifact(name=issuer + ".bin")
            with self.assertRaises(PolicyDenied) as ctx:
                self.eng.promote(
                    decision_id="ALLOW-" + issuer, source=src,
                    issuer=issuer, controllers=ALICE_BOB, seat=SEAT_MAIN)
            self.assertIn(expected, ctx.exception.verification["codes"],
                          ctx.exception.verification["codes"])

    def test_governed_reanchor_successor_allowed(self):
        self.eng.revoke(target_id="issuer.ivan", freeze_seat=SEAT_MAIN)
        src = self.artifact(name="iris-pre.bin")
        with self.assertRaises(PolicyDenied):
            self.eng.promote(
                decision_id="ALLOW-IRIS-PRE", source=src,
                issuer="issuer.iris", controllers=ALICE_BOB, seat=SEAT_MAIN)

        self.eng.appoint_successor("issuer.iris", SEAT_MAIN)
        src2 = self.artifact(name="iris.bin", data=b"iris governed bytes")
        res = self.eng.promote(
            decision_id="ALLOW-IRIS", source=src2, issuer="issuer.iris",
            controllers=ALICE_BOB, seat=SEAT_MAIN)
        self.assertTrue(res["ok"])
        rec = reconstruct(self.ws.root)
        self.assertEqual(rec["summary"]["allowed"], 1)
        self.assertTrue(rec["clean"])

    def test_seat_relabel_cannot_hide_same_root_backfill(self):
        self.eng.revoke(target_id="issuer.ivan", freeze_seat=SEAT_MAIN)
        src = self.artifact(name="relabel.bin")
        with self.assertRaises(PolicyDenied) as ctx:
            self.eng.promote(
                decision_id="ALLOW-RELABEL", source=src,
                issuer="issuer.ivan2", controllers=ALICE_BOB,
                # A different hint must not mask the cert's backfill_seat.
                seat="SEAT-SOMETHING-ELSE")
        self.assertIn("SAME_ROOT_PROXY_BACKFILL",
                      ctx.exception.verification["codes"])

    def test_issuer_cannot_fill_a_controller_seat(self):
        src = self.artifact(name="overlap.bin")
        with self.assertRaises(PolicyDenied) as ctx:
            self.eng.promote(
                decision_id="ALLOW-OVERLAP", source=src,
                issuer="issuer.ivan",
                controllers=["issuer.ivan", "ctrl.bob"], seat=SEAT_MAIN)
        joined = " ".join(ctx.exception.verification["codes"])
        self.assertIn("ISSUER_CONTROLLER_OVERLAP", joined)
        self.assertIn("TWO_DISTINCT_CONTROLLERS_REQUIRED", joined)

        # The role gate itself is enforced directly by the PKI trust view.
        from isolation.pki import TrustView
        ok, why = TrustView(self.ws.load_trust()).controllers_independent(
            "issuer.ivan", "ctrl.bob")
        self.assertFalse(ok)
        self.assertEqual(why, "CONTROLLER_ROLE_INVALID")

    def test_governance_refuses_same_root_appointment(self):
        self.eng.revoke(target_id="issuer.ivan", freeze_seat=SEAT_MAIN)
        with self.assertRaises(PolicyDenied):
            self.eng.appoint_successor("issuer.ivan2", SEAT_MAIN)


class LedgerWatermarkTests(TempDrill):
    def test_chain_and_watermark_verify(self):
        src = self.artifact(name="l.bin")
        self.eng.promote(
            decision_id="ALLOW-L", source=src, issuer="issuer.nora",
            controllers=ALICE_BOB, seat="SEAT-ISSUER-BACKUP")
        rep = verify_watermarks(
            self.ws.audit_path, self.ws.watermark_path,
            self.ws.watermark_history_path)
        self.assertTrue(rep["ok"], rep["current_status"])
        self.assertEqual(rep["current_status"], "MATCH")
        self.assertGreaterEqual(rep["history_points"], 2)

    def test_tampered_event_breaks_chain_and_constructor_refuses(self):
        src = self.artifact(name="t.bin")
        self.eng.promote(
            decision_id="ALLOW-T2", source=src, issuer="issuer.nora",
            controllers=ALICE_BOB, seat="SEAT-ISSUER-BACKUP")

        lines = self.ws.audit_path.read_text(encoding="utf-8").splitlines()
        ev = json.loads(lines[0])
        ev["payload"]["tampered"] = True
        lines[0] = json.dumps(ev, sort_keys=True)
        self.ws.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        rep = verify_watermarks(
            self.ws.audit_path, self.ws.watermark_path,
            self.ws.watermark_history_path)
        self.assertFalse(rep["chain"]["ok"])
        self.assertEqual(rep["chain"]["reason"], "EVENT_HASH_MISMATCH")
        with self.assertRaises(ValueError):
            Ledger(self.ws.audit_path, self.ws.watermark_path,
                   self.ws.watermark_history_path)


class BarrierScenarioTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(
            prefix="iso_barrier_", ignore_cleanup_errors=True)
        self.base = Path(self._td.name)

    def tearDown(self):
        try:
            self._td.cleanup()
        except PermissionError:
            pass

    def _assert_report_ok(self, rep):
        if not rep["ok"]:
            self.fail(json.dumps(rep, ensure_ascii=False, indent=2, default=str))

    def test_case1_revoke_first(self):
        self._assert_report_ok(case_revoke_first(self.base / "c1"))

    def test_case2_lost_receipt(self):
        self._assert_report_ok(case_lost_receipt(self.base / "c2"))

    def test_case3_same_id_diff_digest(self):
        self._assert_report_ok(case_same_id_diff_digest(self.base / "c3"))


class ModelCheckTests(unittest.TestCase):
    def test_exhaustive_model_holds_and_has_teeth(self):
        rep = run_model_check()
        self.assertTrue(rep["ok"], json.dumps(rep, indent=2))
        self.assertEqual(rep["violation_count"], 0)
        self.assertGreater(rep["interleavings_enumerated"], 0)
        self.assertGreater(rep["naive_dir_trust_counterexample_total"], 0)


class ScaleSmallTests(unittest.TestCase):
    def test_partial_equals_full_on_small_sharded_set(self):
        with tempfile.TemporaryDirectory(
                prefix="iso_scale_", ignore_cleanup_errors=True) as td:
            rep = run_scale_comparison(
                Path(td), records=120, shards=6, partial_shards=2,
                progress=lambda *_a, **_k: None)
            self.assertTrue(rep["ok"], json.dumps(
                rep["equivalence"], indent=2))
            self.assertEqual(
                rep["full_scan"]["artifact_files_actually_hashed"], 120)
            self.assertEqual(
                rep["partial_scan"]["artifact_files_actually_hashed"], 40)
            self.assertEqual(rep["equivalence"]["mismatch_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
