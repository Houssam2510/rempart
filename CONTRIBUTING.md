# Contributing

```bash
git clone https://github.com/Houssam2510/rempart && cd rempart
pip install -e .
python -m unittest discover -s tests -t .
rempart scan .                     # Rempart must keep passing its own scan
```

A new rule needs, in the same change:

1. A `rule(...)` declaration with CWE, OWASP 2025 category and remediation.
2. A positive test, and a negative test for the closest safe look-alike.
3. An entry in `docs/RULES.md` (`rempart rules --markdown > docs/RULES.md`) and, if it covers a new threat, in `docs/THREAT_CATALOG.md`.

Test fixtures that look like credentials must be assembled at runtime (see `tests/helpers.py`) so the repository never contains a literal token.
