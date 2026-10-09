"""Tiny HTTP client with an on-disk JSON cache. Stdlib only, so the tool
installs anywhere a Python 3.11 interpreter exists."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "rempart/0.1 (+https://github.com/Houssam2510/rempart)"


def home() -> Path:
    base = os.environ.get("REMPART_HOME") or os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "rempart")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def cache_dir() -> Path:
    p = home() / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_path(key: str) -> Path | None:
    try:
        return cache_dir() / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
    except OSError:
        return None  # an unwritable cache must never block a lookup


def get_json(url: str, *, ttl: int = 86_400, timeout: int = 30, data: Any = None) -> Any:
    key = url + ("|" + json.dumps(data, sort_keys=True) if data is not None else "")
    path = _cache_path(key)
    if path is not None and path.is_file() and time.time() - path.stat().st_mtime < ttl:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
        payload = json.loads(resp.read().decode("utf-8"))
    if path is not None:
        try:
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass
    return payload


class NetworkError(RuntimeError):
    pass


def safe_get_json(url: str, **kw: Any) -> Any:
    try:
        return get_json(url, **kw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise NetworkError(f"{url}: {exc}") from exc
