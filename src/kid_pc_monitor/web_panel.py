"""Parent web panel for Kid PC Monitor."""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from kid_pc_monitor.paths import (
    config_dir,
    package_dir,
    resolve_tls_cert_paths,
    static_dir,
    template_dir,
)
from kid_pc_monitor.remote_client import (
    AgentLogsUnavailable,
    format_minutes_duration,
    format_seconds_duration,
    get_agent_logs,
    get_default_scan_network,
    inspect_pc,
    parse_scan_subnet,
    perform_action,
    refresh_discovered_entry,
    scan_for_servers,
)

PANEL_USERNAME = "Kid PC Monitor"
AUTH_FILE = "web_panel_auth.json"
SESSION_AUTH_KEY = "panel_authenticated"
CSRF_SESSION_KEY = "_csrf_token"


def _csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _csrf_valid() -> bool:
    expected = session.get(CSRF_SESSION_KEY)
    if not expected:
        return False
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return bool(supplied) and secrets.compare_digest(expected, supplied)


def _safe_next_url(target: str | None) -> str:
    if not target:
        return url_for("index")
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    if test.scheme not in ("http", "https"):
        return url_for("index")
    if test.netloc and test.netloc != ref.netloc:
        return url_for("index")
    return target


def _auth_path() -> Path:
    """Return the auth file to read; prefer canonical config_dir, then legacy package dir."""
    canonical = config_dir() / AUTH_FILE
    if canonical.is_file():
        return canonical
    legacy = package_dir() / AUTH_FILE
    if legacy.is_file():
        return legacy
    return canonical


def _auth_save_path() -> Path:
    """Where new passwords are written (always under the user config directory)."""
    path = config_dir() / AUTH_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _stored_password_hash(record: dict | None) -> str | None:
    if not record:
        return None
    value = record.get("password_hash")
    return value if isinstance(value, str) and value else None


def _panel_secret_key(record: dict | None) -> str | None:
    if not record:
        return None
    key = record.get("secret_key")
    return key if isinstance(key, str) and len(key) >= 16 else None


def _verify_password(record: dict, password: str) -> bool:
    stored = _stored_password_hash(record)
    if not stored:
        return False
    return check_password_hash(stored, password)


def load_auth_record() -> dict | None:
    path = _auth_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def password_is_configured() -> bool:
    return _stored_password_hash(load_auth_record()) is not None


def save_password(password: str) -> None:
    record = load_auth_record() or {}
    secret_key = _panel_secret_key(record) or secrets.token_hex(32)
    path = _auth_save_path()
    path.write_text(
        json.dumps(
            {
                "secret_key": secret_key,
                "password_hash": generate_password_hash(password, method="scrypt"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(template_dir()),
        static_folder=str(static_dir()),
    )
    record = load_auth_record()
    app.secret_key = (
        os.environ.get("KID_PC_MONITOR_SECRET")
        or _panel_secret_key(record)
        or secrets.token_hex(32)
    )

    @app.before_request
    def require_csrf_on_post() -> None:
        if request.method == "POST" and not _csrf_valid():
            abort(400)

    @app.context_processor
    def inject_panel_context() -> dict[str, Any]:
        return {
            "password_protected": password_is_configured(),
            "panel_auth": session.get(SESSION_AUTH_KEY, False),
            "panel_username": PANEL_USERNAME,
            "format_minutes_duration": format_minutes_duration,
            "format_seconds_duration": format_seconds_duration,
            "csrf_token": _csrf_token,
        }

    def login_required(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if password_is_configured() and not session.get(SESSION_AUTH_KEY):
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not password_is_configured():
            return redirect(url_for("index"))
        if request.method == "POST":
            record = load_auth_record()
            password = request.form.get("password", "")
            if record and _verify_password(record, password):
                session[SESSION_AUTH_KEY] = True
                return redirect(_safe_next_url(request.form.get("next")))
            flash("Incorrect password.", "error")
        next_arg = request.args.get("next", "")
        safe_next = next_arg if _safe_next_url(next_arg) == next_arg else ""
        return render_template("login.html", next=safe_next)

    @app.route("/logout")
    def logout():
        session.pop(SESSION_AUTH_KEY, None)
        return redirect(url_for("index"))

    @app.route("/set-password", methods=["GET", "POST"])
    def set_password():
        if password_is_configured() and not session.get(SESSION_AUTH_KEY):
            return redirect(url_for("login", next=url_for("set_password")))
        changing = password_is_configured()
        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("password_confirm", "")
            record = load_auth_record()
            if changing and (
                not record or not _verify_password(record, request.form.get("current_password", ""))
            ):
                flash("Current password is incorrect.", "error")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
            elif password != confirm:
                flash("Passwords do not match.", "error")
            else:
                save_password(password)
                record = load_auth_record()
                panel_key = _panel_secret_key(record)
                if panel_key:
                    app.secret_key = panel_key
                session[SESSION_AUTH_KEY] = True
                flash("Password saved.", "success")
                return redirect(url_for("index"))
        return render_template("set_password.html", changing=changing)

    @app.route("/")
    @login_required
    def index():
        pcs = session.get("discovered_pcs", {})
        return render_template(
            "index.html",
            pcs=pcs,
            last_scan=session.get("last_scan"),
            last_scan_network=session.get("last_scan_network"),
            scan_subnet=session.get("scan_subnet", ""),
            scan_error=session.get("scan_error"),
            default_subnet=str(get_default_scan_network()),
        )

    @app.route("/scan", methods=["POST"])
    @login_required
    def scan():
        subnet_arg = request.form.get("subnet", "").strip()
        session.pop("scan_error", None)
        try:
            _network, label = parse_scan_subnet(subnet_arg or None)
            discovered = scan_for_servers(subnet=subnet_arg or None)
            for ip, entry in discovered.items():
                try:
                    info = inspect_pc(ip)
                    entry.update(info)
                except ConnectionError:
                    entry["reachable"] = True
            session["discovered_pcs"] = discovered
            session["last_scan"] = datetime.now()
            session["last_scan_network"] = label
            session["scan_subnet"] = subnet_arg
        except ValueError as exc:
            session["scan_error"] = str(exc)
        return redirect(url_for("index"))

    @app.route("/control/<ip>")
    @login_required
    def control(ip: str):
        pcs = session.get("discovered_pcs", {})
        if ip in pcs:
            refresh_discovered_entry(ip, pcs[ip])
            session["discovered_pcs"] = pcs
            pc_info = pcs[ip]
            if pc_info.get("reachable", True):
                try:
                    pc_info = inspect_pc(ip)
                    pcs[ip].update(pc_info)
                    session["discovered_pcs"] = pcs
                except ConnectionError:
                    pc_info = pcs[ip]
                    pc_info["reachable"] = False
        else:
            try:
                pc_info = inspect_pc(ip)
            except ConnectionError:
                pc_info = {
                    "hostname": f"PC at {ip}",
                    "reachable": False,
                }
        return render_template("control.html", ip=ip, pc_info=pc_info)

    @app.route("/logs/<ip>")
    @login_required
    def agent_logs(ip: str):
        hostname = f"PC at {ip}"
        pcs = session.get("discovered_pcs", {})
        if ip in pcs:
            hostname = pcs[ip].get("hostname", hostname)
        log_text = ""
        log_path = ""
        truncated = False
        error_message = None
        try:
            result = get_agent_logs(ip)
            log_path = result.path
            truncated = result.truncated
            log_text = "\n".join(result.lines)
            if not log_text:
                log_text = "(log file is empty)"
        except AgentLogsUnavailable as exc:
            error_message = str(exc)
        except ConnectionError as exc:
            error_message = str(exc)
        return render_template(
            "logs.html",
            ip=ip,
            hostname=hostname,
            log_text=log_text,
            log_path=log_path,
            truncated=truncated,
            error_message=error_message,
        )

    @app.route("/daily_settings/<ip>")
    @login_required
    def daily_settings(ip: str):
        try:
            pc_info = inspect_pc(ip)
        except ConnectionError:
            flash("Could not reach that PC.", "error")
            return redirect(url_for("index"))
        return render_template("daily_settings.html", ip=ip, pc_info=pc_info)

    @app.route("/action", methods=["POST"])
    @login_required
    def action():
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip")
        action_name = payload.get("action")
        if not ip or not action_name:
            return {"success": False, "response": "Missing ip or action"}

        ok, response = perform_action(ip, action_name, payload)
        return {"success": ok, "response": response}

    return app


def main() -> None:
    host = os.environ.get("KID_PC_MONITOR_HOST", "0.0.0.0")
    port = int(os.environ.get("KID_PC_MONITOR_PORT", "5000"))
    app = create_app()
    tls = resolve_tls_cert_paths()
    scheme = "https" if tls else "http"
    print(f"Kid PC Monitor web panel on {scheme}://{host}:{port}")
    if tls:
        print(
            "TLS enabled. iOS Safari password autofill requires the certificate "
            "authority to be trusted on your phone."
        )
    run_kwargs: dict[str, Any] = {"host": host, "port": port, "debug": False}
    if tls:
        run_kwargs["ssl_context"] = tls
    app.run(**run_kwargs)


if __name__ == "__main__":
    main()
