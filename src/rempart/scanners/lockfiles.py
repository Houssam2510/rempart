"""Lockfile and manifest parsers. Each returns (ecosystem, name, version, line).

Ecosystem names follow the OSV schema (case-sensitive): npm, PyPI, Go,
crates.io, RubyGems, Packagist, Maven.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from typing import Callable, Iterator


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    path: str
    line: int


def _line_finder(text: str) -> Callable[[str, str], int]:
    lines = text.splitlines()

    def find(name: str, version: str) -> int:
        for i, ln in enumerate(lines, 1):
            if name in ln and version in ln:
                return i
        for i, ln in enumerate(lines, 1):
            if name in ln:
                return i
        return 1

    return find


def _split_spec(spec: str) -> tuple[str, str]:
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3')."""
    idx = spec.rfind("@")
    if idx <= 0:
        return spec, ""
    return spec[:idx], spec[idx + 1:]


def parse_package_lock(path: str, text: str) -> Iterator[Package]:
    data = json.loads(text)
    find = _line_finder(text)
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if version:
                yield Package("npm", name, version, path, find(f'"{key}"', ""))
        return

    def walk(deps: dict[str, dict]) -> Iterator[Package]:
        for name, meta in deps.items():
            if isinstance(meta, dict) and meta.get("version"):
                yield Package("npm", name, meta["version"], path, find(f'"{name}"', meta["version"]))
                yield from walk(meta.get("dependencies") or {})

    yield from walk(data.get("dependencies") or {})


def parse_pnpm_lock(path: str, text: str) -> Iterator[Package]:
    find = _line_finder(text)
    in_packages = False
    for raw in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", raw):
            in_packages = raw.startswith("packages")
            continue
        if raw and not raw.startswith(" "):
            in_packages = False
            continue
        if not in_packages:
            continue
        m = re.match(r"^  ['\"]?/?([^'\":\s][^'\":]*?)['\"]?:\s*$", raw)
        if not m:
            continue
        key = re.sub(r"\(.*\)$", "", m.group(1))
        if "@" in key[1:]:
            name, version = _split_spec(key)
        elif "/" in key:  # lockfile v5: /name/1.2.3
            name, _, version = key.rpartition("/")
        else:
            continue
        if name and version and re.match(r"^\d", version):
            yield Package("npm", name, version, path, find(key, ""))


def parse_yarn_lock(path: str, text: str) -> Iterator[Package]:
    lines = text.splitlines()
    current: str | None = None
    current_line = 1
    for i, raw in enumerate(lines, 1):
        if raw and not raw.startswith((" ", "#")) and raw.rstrip().endswith(":"):
            first = raw.rstrip(":").split(",")[0].strip().strip('"')
            first = re.sub(r"@(?:npm|patch|workspace|portal|link|file):.*$", "", first)
            name, _ = _split_spec(first)
            current, current_line = (name if name and not name.startswith("__") else None), i
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', raw)
        if m and current:
            if "workspace" not in m.group(1):
                yield Package("npm", current, m.group(1), path, current_line)
            current = None


def parse_requirements(path: str, text: str) -> Iterator[Package]:
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+\-!]+)", line)
        if m:
            yield Package("PyPI", m.group(1), m.group(2), path, i)


def _toml_packages(path: str, text: str, ecosystem: str) -> Iterator[Package]:
    data = tomllib.loads(text)
    find = _line_finder(text)
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source")
        if isinstance(source, dict) and ("editable" in source or "virtual" in source or "path" in source):
            continue
        if name and version:
            yield Package(ecosystem, name, str(version), path, find(f'name = "{name}"', ""))


def parse_poetry_lock(path: str, text: str) -> Iterator[Package]:
    yield from _toml_packages(path, text, "PyPI")


def parse_cargo_lock(path: str, text: str) -> Iterator[Package]:
    yield from _toml_packages(path, text, "crates.io")


def parse_pipfile_lock(path: str, text: str) -> Iterator[Package]:
    data = json.loads(text)
    find = _line_finder(text)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = (meta or {}).get("version", "")
            if v.startswith("=="):
                yield Package("PyPI", name, v[2:], path, find(f'"{name}"', ""))


def parse_go_mod(path: str, text: str) -> Iterator[Package]:
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)", line) if (in_block or line.startswith("require ")) else None
        if m:
            yield Package("Go", m.group(1), m.group(2), path, i)


def parse_gemfile_lock(path: str, text: str) -> Iterator[Package]:
    in_specs = False
    for i, raw in enumerate(text.splitlines(), 1):
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and raw and not raw.startswith(" "):
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)\s]+)\)$", raw) if in_specs else None
        if m:
            yield Package("RubyGems", m.group(1), m.group(2).split("-")[0], path, i)


def parse_composer_lock(path: str, text: str) -> Iterator[Package]:
    data = json.loads(text)
    find = _line_finder(text)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), str(pkg.get("version", "")).lstrip("v")
            if name and version and not version.startswith("dev-"):
                yield Package("Packagist", name, version, path, find(f'"{name}"', ""))


def parse_gradle_lockfile(path: str, text: str) -> Iterator[Package]:
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"^([\w.\-]+):([\w.\-]+):([\w.\-]+)=", raw)
        if m:
            yield Package("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), path, i)


PARSERS: dict[str, Callable[[str, str], Iterator[Package]]] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "gradle.lockfile": parse_gradle_lockfile,
}


def parser_for(basename: str) -> Callable[[str, str], Iterator[Package]] | None:
    if basename in PARSERS:
        return PARSERS[basename]
    if re.fullmatch(r"requirements[\w.\-]*\.txt|constraints[\w.\-]*\.txt", basename):
        return parse_requirements
    return None
