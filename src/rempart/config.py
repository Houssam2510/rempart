"""Project configuration, read from `.rempart.toml` at the scan root.

    exclude = ["fixtures/**", "docs/**"]
    disable = ["QUAL-COMPLEXITY"]
    fail_on = "high"

    [severity]
    "DOCKER-NO-HEALTHCHECK" = "info"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from rempart.models import Severity


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    disable: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    fail_on: Severity | None = None
    include_tests: bool = False
    prod_only: bool = False  # ignore packages only used to build or test

    @classmethod
    def load(cls, root: Path) -> "Config":
        path = root / ".rempart.toml"
        if not path.is_file():
            return cls()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        cfg = cls(
            exclude=[str(p) for p in data.get("exclude", [])],
            disable={str(r) for r in data.get("disable", [])},
            severity_overrides={str(k): Severity.parse(str(v)) for k, v in data.get("severity", {}).items()},
        )
        cfg.include_tests = bool(data.get("include_tests", False))
        cfg.prod_only = bool(data.get("prod_only", False))
        if "fail_on" in data:
            cfg.fail_on = Severity.parse(str(data["fail_on"]))
        return cfg
