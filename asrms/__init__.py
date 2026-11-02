import os
import secrets
import ipaddress
from urllib.parse import urlsplit

from flask import Flask, abort, request, session

from asrms.database import init_app
from asrms.routes import register_routes


def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
        instance_relative_config=True,
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("ASRMS_SECRET_KEY") or secrets.token_hex(32),
        DATABASE="instance/asrms.sqlite3",
        NMAP_PATH=None,
        NMAP_TIMEOUT=45,
        NMAP_VERSION_TIMEOUT=90,
        MAX_SCAN_PORTS=100,
        MONITOR_POLL_SECONDS=5,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
    )
    if test_config:
        app.config.update(test_config)

    @app.before_request
    def protect_local_requests():
        try:
            remote = ipaddress.ip_address(request.remote_addr or "127.0.0.1")
        except ValueError:
            abort(403)
        hostname = (urlsplit(f"//{request.host}").hostname or "").lower()
        if not remote.is_loopback or hostname not in {"127.0.0.1", "localhost", "::1"}:
            abort(403)
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        if request.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
            expected = session.get("_csrf_token", "")
            supplied = request.headers.get("X-ASRMS-CSRF", "")
            if not expected or not secrets.compare_digest(expected, supplied):
                abort(403, description="Missing or invalid CSRF token.")
            origin = request.headers.get("Origin")
            if origin and urlsplit(origin).hostname not in {"127.0.0.1", "localhost", "::1"}:
                abort(403, description="Cross-origin API requests are not allowed.")

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": lambda: session.get("_csrf_token", "")}

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    init_app(app)
    register_routes(app)
    return app
