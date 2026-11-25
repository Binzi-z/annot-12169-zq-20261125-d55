"""Canonical encoding, hashing and durable filesystem helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable

KB = 1024
MB = 1024 * KB


def now_iso() -> str:
    """UTC timestamp used inside synthetic records."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def sha256_file(path: os.PathLike | str, buf_size: int = MB) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(buf_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical(obj: Any) -> bytes:
    """Deterministic canonical JSON bytes used for every signature/hash."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def domain_bytes(domain: str, obj: Dict[str, Any]) -> bytes:
    """Domain-separated signing bytes: ``DOMAIN\\n<canonical-json>``."""
    return domain.encode("ascii") + b"\n" + canonical(obj)


def atomic_write_bytes(path: os.PathLike | str, data: bytes,
                       fsync: bool = True) -> None:
    """Write *data* atomically via a unique temp file + ``os.replace``.

    The temp file is created in the destination directory so the replace is
    atomic on the same NTFS volume.  File contents are flushed/fsynced before
    the rename; this is the durable-commit primitive the drill relies on.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            if fsync:
                os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: os.PathLike | str, obj: Any,
                      pretty: bool = True, fsync: bool = True) -> None:
    if pretty:
        text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    else:
        text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                          sort_keys=True)
    atomic_write_bytes(path, text.encode("utf-8"), fsync=fsync)


def read_json(path: os.PathLike | str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def append_jsonl(path: os.PathLike | str, obj: Dict[str, Any],
                 fsync: bool = True) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n"
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())


def read_jsonl(path: os.PathLike | str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with open(p, "r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"bad JSONL at {p}:{ln}: {exc}") from exc
    return out


def safe_rel_path(rel: str) -> str:
    """Canonicalize a bound relative path and reject traversal/absolute paths.

    Returns a forward-slash POSIX-style relative path.  Raises ValueError for
    absolute/drive paths or any ``..`` parent segment so a signed decision
    cannot materialize outside the allowed directory.
    """
    text = str(rel).replace("\\", "/")
    if text.startswith("/"):
        raise ValueError(f"absolute path not allowed: {rel!r}")
    if len(text) >= 2 and text[1] == ":":
        raise ValueError(f"drive-qualified path not allowed: {rel!r}")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"parent traversal not allowed: {rel!r}")
    return "/".join(parts)


def iter_files(root: os.PathLike | str) -> Iterable[Path]:
    """Yield every file under *root* (non-recursive helper built on os.walk)."""
    base = Path(root)
    if not base.exists():
        return
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            yield Path(dirpath) / name


class ScanCounters:
    """Mutable counts of what a reconstruction pass actually inspected."""

    def __init__(self) -> None:
        self.directories_scanned = 0
        self.artifact_files_hashed = 0
        self.record_files_read = 0
        self.bytes_hashed = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "directories_scanned": self.directories_scanned,
            "artifact_files_hashed": self.artifact_files_hashed,
            "record_files_read": self.record_files_read,
            "bytes_hashed": self.bytes_hashed,
            "total_files_inspected": (
                self.artifact_files_hashed + self.record_files_read
            ),
        }
