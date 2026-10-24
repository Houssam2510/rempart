"""What a file is for, decided from its path (and, for minified code, its shape).

    app       code and configuration that ship (the default)
    test      tests, fixtures, mocks (engine.TEST_PATH, unchanged behaviour)
    dev       development-only configuration: settings/dev*.py, *.local.* / *.dev.* files,
              .env.development, compose files that run a development server or mount the
              source tree, local database init scripts (*initdb.d/), seeds
    example   examples/, samples/, demo(s)/, sandbox/, playground/, code under docs/
    vendored  third-party code copied into the repository: vendor/, third_party/,
              external/, a lib/ or vendor/ folder under static/public/assets, *.bundle.js,
              *.umd.js, *.min.js, and JavaScript/CSS whose lines are minified
    docs      prose: .md, .mdx, .rst, .txt, .adoc

Effects (AUDIT.md R4), applied by the engine after the scanners ran:
- vendored: code, data, quality, performance and AI findings are dropped (not your code);
  secrets and dependency findings stay.
- docs: code, data, quality and performance findings are dropped (a sentence that quotes
  `sslmode=disable` is not a database connection); secrets and AI-instruction findings stay.
- dev and example: every finding loses one severity level, except credentials in a
  provider's own format in a dev file (an AWS key in local settings is still a live key).
  Secrets in example paths are lowered once by the secrets scanner itself, never twice.
- none of these files can feed an attack path: correlation only uses `app` files.
These are heuristics on names and layout; they are stated here so they can be argued with.
"""

from __future__ import annotations

import re

from rempart.models import Finding

_VENDORED = re.compile(
    r"(?i)(?:^|/)(?:vendor|vendors|third[_-]?party|thirdparty|external|bower_components|node_modules)/"
    r"|(?:^|/)(?:static|public|assets|www|wwwroot)/(?:[^/]+/)*(?:lib|libs|vendor)/"
    r"|\.(?:bundle|umd|min|pack|chunk)\.(?:[cm]?js|css)$")
_DOCS = re.compile(r"(?i)\.(?:md|mdx|rst|txt|adoc|asciidoc)$")
_DEV = re.compile(
    r"(?i)(?:^|/)settings/(?:dev|development|local|test)\w*\.py$|(?:^|/)settings_(?:dev|development|local)\w*\.py$"
    r"|(?:^|/)(?:dev|local|development)_settings\.py$"
    r"|\.(?:local|dev|development)\.(?:ya?ml|json|toml|ini|conf|cfg|py|[cm]?js|ts)$|(?:^|/)\.env\.(?:dev|development|local)$"
    r"|(?:^|/)[^/]*initdb\.d/|(?:^|/)seeds?/"
    r"|(?:^|/)(?:docker-)?compose[\w.-]*(?:dev|local|override|test)[\w.-]*\.ya?ml$")
_EXAMPLE = re.compile(r"(?i)(?:^|/)(?:examples?|samples?|demos?|sandbox|playground|docs?)/")
_COMPOSE = re.compile(r"(?i)(?:^|/)(?:docker-)?compose[\w.-]*\.ya?ml$")
# a compose file that runs a development server or bind-mounts the source tree is a dev stack
_COMPOSE_DEV = re.compile(
    r"(?im)runserver|--reload\b|flask\s+run|(?:npm|yarn|pnpm)\s+(?:run\s+)?dev\b|nodemon|rails\s+s(?:erver)?\b|webpack(?:-dev)?-server|\bvite\b"
    r"|^\s*-\s*['\"]?\.{1,2}(?:/[\w.-]*)*:/")
_MINIFIABLE = re.compile(r"(?i)\.(?:[cm]?js|css)$")


def classify(path: str, text: str | None = None) -> str:
    from rempart.engine import is_test_path

    if "://" in path or path.startswith(("image:", "scanner:")):
        return "app"
    if _VENDORED.search(path):
        return "vendored"
    if text and _MINIFIABLE.search(path):
        lines = text.splitlines()
        if lines and max(len(x) for x in lines) > 1000 and sum(len(x) for x in lines) / len(lines) > 200:
            return "vendored"
    if _DOCS.search(path):
        return "docs"
    if is_test_path(path):
        return "test"
    if _DEV.search(path) or (text is not None and _COMPOSE.search(path) and _COMPOSE_DEV.search(text)):
        return "dev"
    if _EXAMPLE.search(path):
        return "example"
    return "app"


_DROP = {"vendored": {"code", "data", "quality", "performance", "ai"}, "docs": {"code", "data", "quality", "performance"}}


def _provider_secret(f: Finding) -> bool:
    return f.rule.domain == "secrets" and f.rule.id.startswith("SEC-") and f.rule.id not in ("SEC-GENERIC", "SEC-ENV-COMMITTED")


def apply(findings: list[Finding], read) -> tuple[list[Finding], int]:
    """Classify each finding's file and apply the effects above. Returns (kept, dropped)."""
    kinds: dict[str, str] = {}
    kept: list[Finding] = []
    for f in findings:
        if f.path not in kinds:
            kinds[f.path] = classify(f.path, read(f.path) if f.line >= 0 and "://" not in f.path else None)
        kind = kinds[f.path]
        if f.rule.domain in _DROP.get(kind, ()):
            continue
        if kind != "app":
            f.extra["file_kind"] = kind
        # the secrets scanner already lowers example, docs and test paths itself: never twice
        already = kind == "example" and f.rule.domain == "secrets"
        if kind in ("dev", "example") and not already and f.severity is not None and not _provider_secret(f) and f.verification != "live-secret":
            f.severity = f.severity.lower()
            f.learned_note = (f.learned_note + "; " if f.learned_note else "") + f"{kind} file: one level lower"
        kept.append(f)
    return kept, len(findings) - len(kept)


def chainable(f: Finding) -> bool:
    """Only shipped code and configuration can be a stage of an attack path."""
    return f.extra.get("file_kind", "app") == "app"
