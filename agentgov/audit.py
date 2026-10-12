"""Append-only, hash-chained audit trail. Editing any past entry breaks the chain."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_entries(entries: list[dict[str, Any]]) -> bool:
    prev = GENESIS
    for index, entry in enumerate(entries):
        if entry.get("seq") != index or entry.get("prev") != prev or entry.get("hash") != _digest(entry):
            return False
        prev = entry["hash"]
    return True


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = []
        if self._path and self._path.exists():
            lines = self._path.read_text(encoding="utf-8").splitlines()
            self._entries = [json.loads(line) for line in lines if line.strip()]

    def record(self, event: str, actor: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "seq": len(self._entries),
                "ts": time.time(),
                "event": event,
                "actor": actor,
                "data": data,
                "prev": self._entries[-1]["hash"] if self._entries else GENESIS,
            }
            entry["hash"] = _digest(entry)
            self._entries.append(entry)
            if self._path:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return copy.deepcopy(entry)

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._entries)

    def verify(self) -> bool:
        return verify_entries(self.entries())
