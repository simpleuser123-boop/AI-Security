"""Production WSGI entrypoint for the Web/API service.

Gunicorn imports ``app`` from this module.  Keep ``python -m web.app`` as the
local development entrypoint so the development server path remains unchanged.
"""
from __future__ import annotations

from web.app import create_app

app, socketio = create_app()
application = app
