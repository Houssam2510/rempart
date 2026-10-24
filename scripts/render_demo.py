"""Render docs/assets/demo-scan.png from a real scan of examples/vulnerable-app.

    pip install pillow
    python scripts/render_demo.py [--font DejaVuSansMono.ttf --bold DejaVuSansMono-Bold.ttf]

The README calls the image "real output": it is redrawn from the console output of
`rempart scan examples/vulnerable-app --offline --no-history` each time this runs, never
edited by hand. Only the header and the attack-path section are drawn, and long lines are
cut at the image width, as a terminal would.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "demo-scan.png"
FONTS = "/usr/share/fonts/truetype/dejavu"

BG, BAR, FG, DIM, ACCENT = "#11131f", "#181b2e", "#f2f2f7", "#8b90a7", "#b4a6ff"
LINK = "#3fd08f"
BADGE = {"CRIT": "#d92d2d", "HIGH": "#e8590c", "MED": "#e6b400", "LOW": "#2a78d6"}
COUNT = {"critical": "#ff6b6b", "high": "#ff9f43", "medium": "#ffd43b", "low": "#4dabf7", "info": DIM}

WIDTH, PAD, SIZE, LINE = 2080, 44, 30, 50


def scan_output() -> list[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "COLUMNS": "400", "NO_COLOR": "1"}
    proc = subprocess.run([sys.executable, "-m", "rempart", "scan", "examples/vulnerable-app", "--offline", "--no-history"],
                          cwd=ROOT, capture_output=True, text=True, env=env)
    lines = proc.stdout.splitlines()
    end = next((i for i, x in enumerate(lines) if x.startswith("■") and "attack-path" not in x), len(lines))
    return [x.replace(str(ROOT) + "/", "./") for x in lines[:end]]


def fit(draw: ImageDraw.ImageDraw, text: str, font, width: int) -> str:
    if draw.textlength(text, font=font) <= width:
        return text
    while text and draw.textlength(text + "…", font=font) > width:
        text = text[:-1]
    return text + "…"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", default=f"{FONTS}/DejaVuSansMono.ttf")
    ap.add_argument("--bold", default=f"{FONTS}/DejaVuSansMono-Bold.ttf")
    args = ap.parse_args()
    regular, bold = ImageFont.truetype(args.font, SIZE), ImageFont.truetype(args.bold, SIZE)
    lines = [x for x in scan_output() if x.strip()]

    height = 110 + PAD + LINE * (len(lines) + 4)
    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, WIDTH, 100), fill=BAR)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse((40 + i * 38, 38, 64 + i * 38, 62), fill=c)
    d.text((190, 32), "$ rempart scan examples/vulnerable-app --offline", font=regular, fill=ACCENT)

    y, right = 140, WIDTH - PAD
    for raw in lines:
        text = raw.strip()
        indent = PAD + (len(raw) - len(raw.lstrip())) * 15
        m = re.match(r"(CRIT|HIGH|MED|LOW)\s+(.*?)\s{2,}(\S+:\d+)$", text)
        if text.startswith("Rempart"):
            d.text((PAD, y), text, font=bold, fill=FG)
        elif text.startswith("Posture score"):
            score, _, grade = text.partition("grade")
            d.text((indent, y), score.strip(), font=bold, fill=FG)
            x = indent + d.textlength(score.strip() + "  ", font=bold)
            label = f"grade{grade}"
            w = d.textlength(label, font=bold)
            d.rounded_rectangle((x - 12, y - 6, x + w + 12, y + 40), 6, fill=BADGE["CRIT"])
            d.text((x, y), label, font=bold, fill="#ffffff")
        elif re.match(r"\d+ critical", text):
            x = indent
            for part in re.findall(r"\d+ \w+", text):
                d.text((x, y), part, font=regular, fill=COUNT.get(part.split()[1], FG))
                x += d.textlength(part + "  ", font=regular)
        elif text.startswith("■"):
            d.text((PAD, y), text, font=bold, fill=ACCENT)
        elif m:
            sev, title, where = m.groups()
            w = d.textlength(sev, font=bold)
            d.rounded_rectangle((indent - 14, y - 8, indent + w + 14, y + 42), 6, fill=BADGE[sev])
            d.text((indent, y), sev, font=bold, fill="#ffffff")
            x = indent + w + 40
            d.text((x, y), title, font=bold, fill=FG)
            d.text((x + d.textlength(title + "  ", font=bold), y), where, font=regular, fill=DIM)
        elif text.startswith("linked:"):
            d.text((indent, y), fit(d, text, regular, right - indent), font=regular, fill=LINK)
        elif text.startswith("id "):
            d.text((indent, y), text, font=regular, fill=DIM)
        else:
            d.text((indent, y), fit(d, text, regular, right - indent), font=regular, fill=DIM if "scanner(s)" in text else FG)
        y += LINE + (14 if text.startswith(("id ", "■")) or "info" in text else 0)
    img = img.crop((0, 0, WIDTH, y + PAD))
    img.save(OUT, optimize=True)
    print(f"{OUT.relative_to(ROOT)}: {img.width}x{img.height}")


if __name__ == "__main__":
    main()
