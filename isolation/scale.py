"""60,000-record sharded simulation: partial revocation vs full scan.

This is the scale/equivalence apparatus requested separately from the
cryptographically signed drill decisions.  It generates *real* (tiny) artifact
files spread across shard directories plus one signed-attestation record line
per artifact, then compares:

* a **partial/local** reconstruction that inspects only the directories hit by
  a local revocation batch; and
* a **full** reconstruction over every shard directory.

The per-record statuses for the partial slice must be identical to the same
records' statuses in the full run.  Actual directories and files inspected are
counted during the walk/hash (never estimated).

Bulk attestations use fast HMAC-SHA256 tags from two independent simulated
controller keys; the security-critical drill path uses real Ed25519
signatures (see :mod:`isolation.ed25519` / :mod:`isolation.decision`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .util import (ScanCounters, append_jsonl, canonical, read_jsonl,
                   sha256_hex, sha256_file, atomic_write_json, read_json)

SIM_DOMAIN = b"SCALE-SIM-ALLOW/v1\n"
KEY_A = hashlib.sha256(b"sim-independent-controller-A").digest()
KEY_B = hashlib.sha256(b"sim-independent-controller-B-roots-x").digest()

DEFAULT_RECORDS = 60_000
DEFAULT_SHARDS = 120          # 500 records/files per directory
DEFAULT_PARTIAL_SHARDS = 4    # local revocation touches 4 directories


def _tags(core: Dict[str, Any]) -> Tuple[str, str]:
    msg = SIM_DOMAIN + canonical(core)
    return (hmac.new(KEY_A, msg, hashlib.sha256).hexdigest(),
            hmac.new(KEY_B, msg, hashlib.sha256).hexdigest())


def _verify_tags(rec: Dict[str, Any]) -> bool:
    mac1 = rec.get("mac1")
    mac2 = rec.get("mac2")
    core = {k: v for k, v in rec.items() if k not in ("mac1", "mac2")}
    a, b = _tags(core)
    return hmac.compare_digest(a, mac1 or "") and hmac.compare_digest(b, mac2 or "")


def shard_name(i: int) -> str:
    return f"shard_{i:03d}"


def generate_scale(root: Path | str, records: int = DEFAULT_RECORDS,
                   shards: int = DEFAULT_SHARDS, force: bool = False,
                   progress: Optional[Callable[[str], None]] = print
                   ) -> Dict[str, Any]:
    root = Path(root)
    per_shard = records // shards
    if per_shard * shards != records:
        raise ValueError("records must be divisible by shards")
    manifest_path = root / "scale_manifest.json"
    if not force and manifest_path.exists():
        man = read_json(manifest_path)
        if man.get("records") == records and man.get("shards") == shards \
                and man.get("complete"):
            if progress:
                progress(f"scale dataset already present at {root}; reuse")
            return {"generated": False, **man}

    shards_root = root / "shards"
    if shards_root.exists():
        # Never let shards from a previous --shards value inflate counts.
        shutil.rmtree(shards_root, ignore_errors=True)
    shards_root.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    total_files = 0
    for s in range(shards):
        sdir = shards_root / shard_name(s)
        sdir.mkdir(parents=True, exist_ok=True)
        lines: List[Dict[str, Any]] = []
        for j in range(per_shard):
            n = s * per_shard + j
            rec_id = f"REC-{s:03d}-{j:05d}"
            fname = f"a_{j:05d}.bin"
            payload = (f"SIMULATED-{rec_id}-".encode() * 4)[:160]
            fpath = sdir / fname
            fpath.write_bytes(payload)
            digest = sha256_hex(payload)
            core = {
                "rec_id": rec_id,
                "shard": shard_name(s),
                "file": fname,
                "gen": 1,
                "digest": digest,
            }
            m1, m2 = _tags(core)
            lines.append({**core, "mac1": m1, "mac2": m2})
            total_files += 1
        # One record file per directory (JSONL) keeps 60k-record generation
        # and inspection fast while remaining genuinely "分目录".
        with open(sdir / "records.jsonl", "w", encoding="utf-8",
                  newline="\n") as fh:
            for rec in lines:
                fh.write(json.dumps(rec, ensure_ascii=False,
                                    separators=(",", ":"), sort_keys=True))
                fh.write("\n")
        if progress and (s + 1) % 20 == 0:
            progress(f"  generated {total_files}/{records} files "
                     f"across {s + 1}/{shards} dirs")

    elapsed = time.perf_counter() - t0
    manifest = {
        "complete": True, "records": records, "shards": shards,
        "per_shard": per_shard, "artifact_files": total_files,
        "elapsed_seconds": round(elapsed, 3),
    }
    atomic_write_json(manifest_path, manifest)
    return {"generated": True, **manifest}


def write_local_revocations(root: Path | str,
                            partial_shards: int = DEFAULT_PARTIAL_SHARDS
                            ) -> Dict[str, Any]:
    """Revoke every 5th record inside the locally affected shard dirs."""
    root = Path(root)
    manifest = read_json(root / "scale_manifest.json")
    per_shard = manifest["per_shard"]
    rev_path = root / "revocations.jsonl"
    revoked: List[Dict[str, str]] = []
    revoked_ids: Set[str] = set()
    for s in range(partial_shards):
        for j in range(per_shard):
            if j % 5 != 0:
                continue
            rec_id = f"REC-{s:03d}-{j:05d}"
            # digest is filled from the generated record for a stronger bind.
            revoked.append({"rec_id": rec_id, "shard": shard_name(s)})
            revoked_ids.add(rec_id)
    # enrich with digests
    digest_by_id = _index_record_digests(root, range(partial_shards))
    for r in revoked:
        r["digest"] = digest_by_id.get(r["rec_id"], "")
    rev_path.write_text("", encoding="utf-8")
    for r in revoked:
        append_jsonl(rev_path, r)
    return {"revocation_file": str(rev_path), "revoked": len(revoked),
            "revoked_ids": sorted(revoked_ids)}


def _index_record_digests(root: Path, shard_range) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for s in shard_range:
        for rec in read_jsonl(root / "shards" / shard_name(s) / "records.jsonl"):
            out[rec["rec_id"]] = rec["digest"]
    return out


def load_revoked_ids(root: Path | str) -> Set[str]:
    p = Path(root) / "revocations.jsonl"
    return {r["rec_id"] for r in read_jsonl(p)}


def scan(root: Path | str, *, only_shards: Optional[List[str]] = None,
         verify_macs: bool = True) -> Dict[str, Any]:
    """Inspect selected shard directories (or all) and classify every file."""
    root = Path(root)
    shards_root = root / "shards"
    counters = ScanCounters()
    revoked_ids = load_revoked_ids(root)

    if only_shards is None:
        shard_dirs = sorted(p for p in shards_root.iterdir() if p.is_dir())
    else:
        shard_dirs = [shards_root / name for name in only_shards]

    statuses: Dict[str, str] = {}
    per_shard: Dict[str, Dict[str, int]] = {}
    mac_verified = 0
    allowed = revoked = invalid = orphan = 0

    for sdir in shard_dirs:
        if not sdir.is_dir():
            continue
        counters.directories_scanned += 1
        name = sdir.name
        counts = {"files": 0, "allowed": 0, "revoked": 0,
                  "invalid": 0, "orphan": 0}
        records_by_file: Dict[str, Dict[str, Any]] = {}
        record_path = sdir / "records.jsonl"
        if record_path.exists():
            counters.record_files_read += 1
            for rec in read_jsonl(record_path):
                records_by_file[rec["file"]] = rec

        for fpath in sorted(sdir.glob("*.bin")):
            counters.artifact_files_hashed += 1
            counters.bytes_hashed += fpath.stat().st_size
            counts["files"] += 1
            rec = records_by_file.get(fpath.name)
            if rec is None:
                status = "ORPHAN"
                orphan += 1; counts["orphan"] += 1
            else:
                actual = sha256_file(fpath)
                mac_ok = (not verify_macs) or _verify_tags(rec)
                if mac_ok:
                    mac_verified += 1
                if actual != rec["digest"] or not mac_ok:
                    status = "INVALID_DIGEST_OR_MAC"
                    invalid += 1; counts["invalid"] += 1
                elif rec["rec_id"] in revoked_ids:
                    status = "REVOKED"
                    revoked += 1; counts["revoked"] += 1
                else:
                    status = "ALLOWED"
                    allowed += 1; counts["allowed"] += 1
                statuses[rec["rec_id"]] = status
        per_shard[name] = counts

    return {
        "statuses": statuses,
        "per_shard": per_shard,
        "mac_verified": mac_verified,
        "totals": {
            "allowed": allowed, "revoked": revoked,
            "invalid": invalid, "orphan": orphan,
        },
        "counters": counters.as_dict(),
        "shard_directories": counters.directories_scanned,
    }


def run_scale_comparison(base: Path | str, *, records: int = DEFAULT_RECORDS,
                         shards: int = DEFAULT_SHARDS,
                         partial_shards: int = DEFAULT_PARTIAL_SHARDS,
                         force: bool = False,
                         progress: Optional[Callable[[str], None]] = print
                         ) -> Dict[str, Any]:
    root = Path(base) / f"scale-{records}"
    gen = generate_scale(root, records=records, shards=shards,
                         force=force, progress=progress)
    rev = write_local_revocations(root, partial_shards=partial_shards)

    target_names = [shard_name(i) for i in range(partial_shards)]
    target_ids: Set[str] = set()
    per = records // shards
    for s in range(partial_shards):
        for j in range(per):
            target_ids.add(f"REC-{s:03d}-{j:05d}")

    t0 = time.perf_counter()
    partial = scan(root, only_shards=target_names)
    t_partial = time.perf_counter() - t0

    t0 = time.perf_counter()
    full = scan(root)
    t_full = time.perf_counter() - t0

    mismatches: List[Dict[str, Any]] = []
    for rid in sorted(target_ids):
        ps = partial["statuses"].get(rid)
        fs = full["statuses"].get(rid)
        if ps != fs:
            mismatches.append({"rec_id": rid, "partial": ps, "full": fs})

    slice_full = {rid: full["statuses"].get(rid) for rid in target_ids}
    slice_revoked = sum(1 for st in slice_full.values() if st == "REVOKED")
    slice_allowed = sum(1 for st in slice_full.values() if st == "ALLOWED")

    ok = (
        not mismatches
        and partial["counters"]["artifact_files_hashed"]
            == partial_shards * per
        and full["counters"]["artifact_files_hashed"] == records
        and full["shard_directories"] == shards
        and partial["shard_directories"] == partial_shards
        and slice_revoked == rev["revoked"]
    )

    return {
        "ok": ok,
        "root": str(root),
        "parameters": {
            "records": records, "shards": shards,
            "files_per_shard": per, "partial_shards": partial_shards,
        },
        "generation": {k: v for k, v in gen.items() if k != "root"},
        "revocations": {"count": rev["revoked"],
                        "file": Path(rev["revocation_file"]).name},
        "partial_scan": {
            "seconds": round(t_partial, 3),
            "shard_directories_actually_inspected":
                partial["shard_directories"],
            "directories_counted":
                partial["counters"]["directories_scanned"],
            "artifact_files_actually_hashed":
                partial["counters"]["artifact_files_hashed"],
            "record_files_read": partial["counters"]["record_files_read"],
            "total_files_inspected":
                partial["counters"]["total_files_inspected"],
            "totals": partial["totals"],
        },
        "full_scan": {
            "seconds": round(t_full, 3),
            "shard_directories_actually_inspected":
                full["shard_directories"],
            "directories_counted":
                full["counters"]["directories_scanned"],
            "artifact_files_actually_hashed":
                full["counters"]["artifact_files_hashed"],
            "record_files_read": full["counters"]["record_files_read"],
            "total_files_inspected":
                full["counters"]["total_files_inspected"],
            "mac_records_verified": full["mac_verified"],
            "totals": full["totals"],
        },
        "equivalence": {
            "records_compared": len(target_ids),
            "mismatch_count": len(mismatches),
            "first_mismatches": mismatches[:10],
            "slice_revoked": slice_revoked,
            "slice_allowed": slice_allowed,
            "claim": ("partial local reconstruction equals the matching "
                      "slice of the full reconstruction"),
        },
        "actual_inspected_directories_and_files": {
            "partial": (
                f"{partial['counters']['directories_scanned']} dirs, "
                f"{partial['counters']['artifact_files_hashed']} artifact "
                f"files + {partial['counters']['record_files_read']} "
                f"record files"
            ),
            "full": (
                f"{full['counters']['directories_scanned']} dirs, "
                f"{full['counters']['artifact_files_hashed']} artifact "
                f"files + {full['counters']['record_files_read']} "
                f"record files"
            ),
        },
    }
