"""A small exhaustive model of promote/revoke interleavings.

The model is intentionally tiny: two threads with four and two atomic steps.
It enumerates **every order-preserving interleaving** (a binomial number of
short schedules) for a matrix of fault worlds, and treats *every prefix* as a
possible crash/restart point.  At each prefix it evaluates:

* a reconstruction predicate mirroring :mod:`isolation.reconstructor`
  (a file is truly allowed only when every binding witness is durable); and
* a naive "whatever is in the allowed directory is allowed" predicate.

The exhaustive safety claim is: the witness-based reconstructor returns
``ALLOW`` in **zero** states lacking a witness, while the naive rule is shown
to accept concrete ungrounded states (the restart incident).

The three prompt conditions are covered by worlds/aggregates:
revoke-first-persisted, directory-changed/receipt-lost, and
same-id/different-digest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

P_STEPS_SAFE = ("p_sign", "p_commit", "p_receipt", "p_dir")
P_STEPS_HAZARDOUS = ("p_sign", "p_dir", "p_commit", "p_receipt")
R_STEPS = ("r_revoke", "r_apply")


@dataclass(frozen=True)
class World:
    key: str
    sigs_ok: bool = True
    independent: bool = True
    issuer_ok: bool = True
    rules_current: bool = True
    digest_ok: bool = True
    conflict: bool = False
    revoke_targets_artifact: bool = True


WORLDS: Tuple[World, ...] = (
    World("w1_revoke_targets_issuer_or_decision"),
    World("w2_unrelated_revoke_receipt_loss",
          revoke_targets_artifact=False),
    World("w3_same_id_diff_digest", digest_ok=False),
    World("w3b_unresolved_id_conflict", conflict=True),
    World("neg_same_root_controllers", independent=False),
    World("neg_revoked_same_root_proxy", issuer_ok=False),
    World("neg_retired_rule_generation", rules_current=False),
)


def initial_state() -> Dict[str, Any]:
    return {
        "sign_attempted": False,
        "dir": False,
        "commit": 0,       # 0 absent, 1 durable valid decision, 2 denied
        "receipt": False,
        "rev": False,
        "rev_applied": False,
    }


def step(state: Dict[str, Any], action: str, world: World) -> Dict[str, Any]:
    s = dict(state)
    if action == "p_sign":
        s["sign_attempted"] = True
    elif action == "p_dir":
        s["dir"] = True
    elif action == "p_commit":
        revoke_blocks = s["rev"] and world.revoke_targets_artifact
        valid = (
            s["sign_attempted"] and world.sigs_ok and world.independent
            and world.issuer_ok and world.rules_current
            and not revoke_blocks
        )
        s["commit"] = 1 if valid else 2
    elif action == "p_receipt":
        if s["commit"] == 1:
            s["receipt"] = True
    elif action == "r_revoke":
        s["rev"] = True
    elif action == "r_apply":
        s["rev_applied"] = True
        if s["rev"] and world.revoke_targets_artifact:
            s["dir"] = False  # revocation removes/invalidates the copy
    else:
        raise ValueError(action)
    return s


def witnesses_durable(s: Dict[str, Any], w: World) -> bool:
    """Independent statement of everything an ALLOW verdict must rest on."""
    return (
        s["commit"] == 1
        and s["sign_attempted"]
        and w.sigs_ok and w.independent and w.issuer_ok
        and w.rules_current and w.digest_ok and not w.conflict
        and not (s["rev"] and w.revoke_targets_artifact)
    )


def decide(s: Dict[str, Any], w: World) -> Dict[str, Any]:
    """Mirror of the real reconstructor's classification."""
    if not s["dir"]:
        verdict = "NO_FILE"
    elif s["commit"] != 1 or not (
            w.sigs_ok and w.independent and w.issuer_ok
            and w.rules_current):
        verdict = "ORPHAN_OR_INVALID_SIGNATURE"
    elif s["rev"] and w.revoke_targets_artifact:
        verdict = "BLOCKED_REVOCATION"
    elif not w.digest_ok:
        verdict = "DIGEST_MISMATCH"
    elif w.conflict:
        verdict = "ID_DIGEST_CONFLICT"
    else:
        verdict = "ALLOW"
    audit_gap = verdict == "ALLOW" and not s["receipt"]
    return {"verdict": verdict, "audit_receipt_missing": audit_gap}


def all_shuffles(p_steps: Tuple[str, ...], r_steps: Tuple[str, ...]
                 ) -> List[List[str]]:
    """All order-preserving interleavings of p_steps and r_steps."""
    out: List[List[str]] = []

    def rec(i: int, j: int, acc: List[str]) -> None:
        if i == len(p_steps) and j == len(r_steps):
            out.append(list(acc))
            return
        if i < len(p_steps):
            acc.append(p_steps[i]); rec(i + 1, j, acc); acc.pop()
        if j < len(r_steps):
            acc.append(r_steps[j]); rec(i, j + 1, acc); acc.pop()

    rec(0, 0, [])
    return out


def run_model_check() -> Dict[str, Any]:
    violations: List[Dict[str, Any]] = []
    naive_examples: List[Dict[str, Any]] = []
    naive_counterexample_total = 0
    visited_states = set()

    interleavings = 0
    prefix_states = 0
    revoke_first_denied = 0
    receipt_only_allows = 0
    hard_orphan_states = 0
    mismatch_deny_states = 0

    for protocol, p_steps in (("real_safe_order", P_STEPS_SAFE),
                              ("hazardous_dir_first", P_STEPS_HAZARDOUS)):
        shuffles = all_shuffles(p_steps, R_STEPS)
        for w in WORLDS:
            for shuffle in shuffles:
                interleavings += 1
                s = initial_state()
                # initial prefix
                prefixes: List[Tuple[List[str], Dict[str, Any]]] = [([], s)]
                for k, action in enumerate(shuffle, 1):
                    s = step(s, action, w)
                    prefixes.append((shuffle[:k], s))

                for prefix_actions, st in prefixes:
                    prefix_states += 1
                    visited_states.add(_state_key(st))
                    d = decide(st, w)
                    witness = witnesses_durable(st, w)

                    # Consistency / safety invariant (biconditional).
                    if d["verdict"] == "ALLOW" and not witness:
                        violations.append({
                            "kind": "ALLOW_WITHOUT_WITNESS",
                            "world": w.key, "protocol": protocol,
                            "prefix": prefix_actions, "state": st,
                        })
                    if st["dir"] and witness and d["verdict"] != "ALLOW":
                        violations.append({
                            "kind": "GROUNDED_FILE_DENIED",
                            "world": w.key, "protocol": protocol,
                            "prefix": prefix_actions, "state": st,
                            "decision": d,
                        })

                    # Naive directory-trust counterexamples.
                    if st["dir"] and not witness:
                        naive_counterexample_total += 1
                        if len(naive_examples) < 3:
                            naive_examples.append({
                                "world": w.key, "protocol": protocol,
                                "prefix": prefix_actions,
                                "naive_verdict": "ALLOW_BECAUSE_IN_DIR",
                                "safe_verdict": d["verdict"],
                            })

                    # Aggregates for the three named conditions.
                    if (w.revoke_targets_artifact and st["rev"]
                            and st["commit"] == 2):
                        revoke_first_denied += 1
                    if (d["verdict"] == "ALLOW"
                            and d["audit_receipt_missing"]):
                        receipt_only_allows += 1
                    if st["dir"] and st["commit"] != 1:
                        hard_orphan_states += 1
                    if (not w.digest_ok or w.conflict) and st["dir"] \
                            and d["verdict"] != "ALLOW":
                        mismatch_deny_states += 1

                # Schedule-level revoke-first assertion: if r_revoke precedes
                # p_commit in a targeting world, commit must be denied.
                if w.revoke_targets_artifact:
                    idx_rev = shuffle.index("r_revoke")
                    idx_commit = shuffle.index("p_commit")
                    if idx_rev < idx_commit:
                        final = s
                        if final["commit"] != 2:
                            violations.append({
                                "kind": "REVOKE_FIRST_NOT_DENIED",
                                "world": w.key, "protocol": protocol,
                                "shuffle": shuffle, "final": final,
                            })

    # Teeth check: the naive rule MUST have observable counterexamples in the
    # hazardous protocol, otherwise the model is not exploring the window.
    naive_has_counterexample = naive_counterexample_total > 0

    ok = (
        not violations
        and naive_has_counterexample
        and revoke_first_denied > 0
        and receipt_only_allows > 0
        and hard_orphan_states > 0
        and mismatch_deny_states > 0
    )

    return {
        "ok": ok,
        "worlds": len(WORLDS),
        "protocols": 2,
        "shuffles_per_family": len(all_shuffles(P_STEPS_HAZARDOUS, R_STEPS)),
        "interleavings_enumerated": interleavings,
        "prefix_states_checked": prefix_states,
        "distinct_abstract_states": len(visited_states),
        "revoke_first_denied_observations": revoke_first_denied,
        "receipt_only_allow_with_audit_gap_states": receipt_only_allows,
        "hard_loss_orphan_states": hard_orphan_states,
        "digest_conflict_denied_dir_states": mismatch_deny_states,
        "naive_dir_trust_counterexample_total": naive_counterexample_total,
        "naive_dir_trust_first_examples": naive_examples,
        "violations": violations[:10],
        "violation_count": len(violations),
    }


def _state_key(s: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        s["sign_attempted"], s["dir"], s["commit"], s["receipt"],
        s["rev"], s["rev_applied"],
    )


if __name__ == "__main__":  # pragma: no cover
    import json
    print(json.dumps(run_model_check(), ensure_ascii=False, indent=2))
