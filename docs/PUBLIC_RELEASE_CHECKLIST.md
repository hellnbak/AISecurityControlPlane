# Public Release Checklist

Before publishing to GitHub:

- [ ] Run `pytest -q`.
- [ ] Run `python -m compileall -q app endpoint`.
- [ ] Run a secret scan such as `gitleaks detect --source . --verbose`.
- [ ] Confirm `.env`, local databases, pycache, and runtime spool files are not committed.
- [ ] Review `LICENSE`, `LICENSE_SUMMARY.md`, `COMMERCIAL-LICENSE.md`, and `TRADEMARKS.md` with counsel.
- [ ] Confirm README describes this as source-available, not OSI open source.
- [ ] Confirm hosted-web controls are documented as best-effort.
- [ ] Create a public-preview tag, for example `v0.6.0-public-preview`.
