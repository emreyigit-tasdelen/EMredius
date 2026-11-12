# Contributing

Thanks for your interest in EMREDIUS. Issues and pull requests are welcome.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -q tests/test_core.py
```

The full suite (`python -m pytest -q tests`) is meant to run on Linux; on Windows it is slow and a few tests that need Linux accounts fail.

## Conventions

- A new feature is a new blueprint (`emredius/blueprints/<menu>/`), a service (`emredius/services/<menu>.py`), a Jinja template and a test. Use `python scripts/new_menu.py <name> "<Title>"` for the skeleton.
- HTML belongs in Jinja templates, SQL must be parameterized, user input must be escaped, and every route must pass the authorization check.
- Do not add dependencies without a clear need; pin versions in `requirements.txt`.
- Never commit secrets, `.env` files or databases. Run `gitleaks dir .` before opening a pull request.
- Every change comes with a relevant test. New source files carry the AGPL-3.0 header used in the existing files.

## Pull requests

Keep a pull request focused on one change, describe what and why, and make sure the tests you touched pass. By contributing you agree that your contribution is licensed under the GNU AGPL v3.0.

Documentation is bilingual: the README is available in English and Turkish, and deeper technical documents under `docs/` are in Turkish.
