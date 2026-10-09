from rempart.reporters.console import render_console
from rempart.reporters.formats import render_html, render_json, render_markdown, render_sarif

RENDERERS = {"json": render_json, "sarif": render_sarif, "md": render_markdown, "markdown": render_markdown, "html": render_html}

__all__ = ["RENDERERS", "render_console"]
