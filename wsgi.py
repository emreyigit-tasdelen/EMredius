# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""gunicorn entry point: `gunicorn -c gunicorn.conf.py wsgi:app`."""
from emredius import create_app

app = create_app()

if __name__ == "__main__":  # development only
    app.run(host="127.0.0.1", port=5100)
