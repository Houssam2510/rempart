"""Package-level reachability: is a vulnerable dependency actually used?

A lockfile lists hundreds of transitive packages, most of which your code
never touches directly. This module answers two cheaper-than-call-graph
questions that already separate signal from noise:

* direct:   is the package declared in a manifest you maintain?
* imported: does any source file import it?

Imported and direct findings keep their full weight; transitive packages that
nothing imports are marked `not-imported` and their confidence is reduced
(never suppressed: a library you do use may still call the vulnerable code).
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from typing import Callable, Iterable

# PyPI distribution name -> importable module, where they differ.
PY_MODULE_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "scikit-learn": "sklearn", "python-dateutil": "dateutil",
    "opencv-python": "cv2", "opencv-python-headless": "cv2", "psycopg2-binary": "psycopg2", "psycopg-binary": "psycopg",
    "pyjwt": "jwt", "python-dotenv": "dotenv", "protobuf": "google", "pymongo": "pymongo", "python-multipart": "multipart",
    "attrs": "attr", "msgpack-python": "msgpack", "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome", "pyopenssl": "OpenSSL",
    "google-cloud-storage": "google", "azure-storage-blob": "azure", "python-jose": "jose", "markdown": "markdown",
    "setuptools": "setuptools", "typing-extensions": "typing_extensions", "llama-index": "llama_index",
}

_JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*|import\s+)['"]([^'"./][^'"]*)['"]""")
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w]*)[\w.]*\s+import|import\s+([A-Za-z_][\w]*))", re.M)
_GO_IMPORT = re.compile(r'"([\w.\-]+\.[a-z]{2,}/[^"]+)"')


def _npm_name(spec: str) -> str:
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def imported_names(files: Iterable[str], read: Callable[[str], str | None]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"npm": set(), "PyPI": set(), "Go": set()}
    for rel in files:
        if rel.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".astro")):
            text = read(rel) or ""
            out["npm"].update(_npm_name(m.group(1)).replace("node:", "") for m in _JS_IMPORT.finditer(text))
        elif rel.endswith(".py"):
            text = read(rel) or ""
            out["PyPI"].update((m.group(1) or m.group(2)).lower() for m in _PY_IMPORT.finditer(text))
        elif rel.endswith(".go"):
            text = read(rel) or ""
            out["Go"].update(m.group(1) for m in _GO_IMPORT.finditer(text))
    return out


def direct_dependencies(files: Iterable[str], read: Callable[[str], str | None]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"npm": set(), "PyPI": set(), "Go": set()}
    for rel in files:
        base = os.path.basename(rel)
        text = None
        try:
            if base == "package.json" and "node_modules/" not in rel:
                data = json.loads(read(rel) or "{}")
                for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    out["npm"].update((data.get(key) or {}).keys())
            elif re.fullmatch(r"requirements[\w.\-]*\.txt", base):
                text = read(rel) or ""
                out["PyPI"].update(m.group(1).lower() for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)", text))
            elif base == "pyproject.toml":
                data = tomllib.loads(read(rel) or "")
                deps = list((data.get("project") or {}).get("dependencies") or [])
                for group in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
                    deps += list(group)
                deps += list(((data.get("tool") or {}).get("poetry") or {}).get("dependencies", {}).keys())
                out["PyPI"].update(re.split(r"[\s<>=!~\[;]", d, maxsplit=1)[0].lower() for d in deps if d)
            elif base == "go.mod":
                text = read(rel) or ""
                out["Go"].update(m.group(1) for m in re.finditer(r"(?m)^\s*(?:require\s+)?([\w.\-]+\.[a-z]{2,}/\S+)\s+v\S+\s*$", text))
        except (ValueError, tomllib.TOMLDecodeError):
            continue
    return out


def py_module(dist: str) -> str:
    d = dist.lower()
    return PY_MODULE_ALIASES.get(d, d.replace("-", "_").replace(".", "_")).lower()


def classify(ecosystem: str, name: str, imported: dict[str, set[str]], direct: dict[str, set[str]]) -> tuple[bool | None, bool | None]:
    """Return (is_direct, is_imported); None when the ecosystem is not analysed."""
    if ecosystem == "npm":
        return name in direct["npm"], name in imported["npm"]
    if ecosystem == "PyPI":
        return name.lower() in direct["PyPI"], py_module(name) in imported["PyPI"]
    if ecosystem == "Go":
        return name in direct["Go"], any(i == name or i.startswith(name + "/") for i in imported["Go"])
    return None, None
