"""Refresh the lists of popular packages used by SUPPLY-TYPOSQUAT (AUDIT.md R6).

    python scripts/update_popular.py

A name is only suspicious when it is one edit away from a very popular package and is
not popular itself. Both lists come from download rankings, not from hand-picked names:

    PyPI  hugovk/top-pypi-packages: the 15,000 most downloaded projects of the last 30 days
    npm   wooorm/npm-high-impact: packages with the most downloads or dependents
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "rempart" / "data"
PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"


def fetch(url: str) -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "rempart-update-popular"}), timeout=60) as r:
        return r.read().decode("utf-8")


def write(name: str, source: str, note: str, names: list[str]) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    header = [f"# source: {source}", f"# retrieved: {today}", f"# {note}", "# most popular first; regenerate with scripts/update_popular.py"]
    (OUT / name).write_text("\n".join(header + names) + "\n", encoding="utf-8")
    print(f"{name}: {len(names)} names")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    pypi = json.loads(fetch(PYPI))
    write("popular_pypi.txt", PYPI, f"ranking updated {pypi.get('last_update', '?')}, by downloads",
          [re.sub(r"[-_.]+", "-", row["project"]).lower() for row in pypi["rows"]])
    npm = re.findall(r"'([^']+)'", fetch(NPM))
    write("popular_npm.txt", NPM, "by downloads or dependents", npm)


if __name__ == "__main__":
    main()
