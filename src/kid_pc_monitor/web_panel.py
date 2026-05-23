"""Parent web panel for Kid PC Monitor."""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from functools import wraps
from hashlib import scrypt
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from kid_pc_monitor.paths import config_dir, template_dir
from kid_pc_monitor.remote_client import (
    format_minutes_duration,
    format_seconds_duration,
    get_default_scan_network,
    inspect_pc,
    parse_scan_subnet,
    refresh_discovered_entry,
    scan_for_servers,
    send_command,
)

PANEL_USERNAME = "Kid PC Monitor"
AUTH_FILE = "web_panel_auth.json"
SESSION_AUTH_KEY = "panel_authenticated"


def _auth_path() -> Path:
    return config_dir() / AUTH_FILE


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return json.dumps(
        {
            "salt": salt.hex(),
            "hash": digest.hex(),
        }
    )


def _verify_password(stored: str, password: str) -> bool:
    try:
        payload = json.loads(stored)
        salt = bytes.fromhex(payload["salt"])
        expected = bytes.fromhex(payload["hash"])
    except (json.JSONDecodeError, KeyError, ValueError):
        return False
    digest = scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return secrets.compare_digest(digest, expected)


def load_auth_record() -> dict | None:
    path = _auth_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def password_is_configured() -> bool:
    record = load_auth_record()
    return bool(record and record.get("password_hash"))


def save_password(password: str) -> None:
    path = _auth_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"password_hash": _hash_password(password)}, indent=2),
        encoding="utf-8",
    )


def create_app() -> Flask:
    app = Flask(__name__, template_folder=str(template_dir()))
    app.secret_key = os.environ.get("KID_PC_MONITOR_SECRET") or secrets.token_hex(32)

    @app.context_processor
    def inject_panel_context() -> dict[str, Any]:
        return {
            "password_protected": password_is_configured(),
            "panel_auth": session.get(SESSION_AUTH_KEY, False),
            "panel_username": PANEL_USERNAME,
            "format_minutes_duration": format_minutes_duration,
            "format_seconds_duration": format_seconds_duration,
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
            if record and _verify_password(record["password_hash"], password):
                session[SESSION_AUTH_KEY] = True
                next_url = request.form.get("next") or url_for("index")
                return redirect(next_url)
            flash("Incorrect password.", "error")
        return render_template(
            "login.html",
            next=request.args.get("next", ""),
        )

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
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
            elif password != confirm:
                flash("Passwords do not match.", "error")
            else:
                save_password(password)
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

    @app.route("/scan")
    @login_required
    def scan():
        subnet_arg = request.args.get("subnet", "").strip()
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

    @app.route("/defaults/<ip>")
    @login_required
    def defaults(ip: str):
        try:
            pc_info = inspect_pc(ip)
        except ConnectionError:
            flash("Could not reach that PC.", "error")
            return redirect(url_for("index"))
        return render_template("defaults.html", ip=ip, pc_info=pc_info)

    @app.route("/action", methods=["POST"])
    @login_required
    def action():
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip")
        action_name = payload.get("action")
        if not ip or not action_name:
            return {"success": False, "response": "Missing ip or action"}

        command = _action_to_command(action_name, payload)
        if command is None:
            return {"success": False, "response": f"Unknown action: {action_name}"}

        ok, response = send_command(ip, command)
        return {"success": ok, "response": response}

    return app


def _action_to_command(action_name: str, payload: dict[str, Any]) -> str | None:
    if action_name == "lock":
        return "LOCK"
    if action_name == "shutdown":
        return "SHUTDOWN"
    if action_name == "message":
        return f"MESSAGE:{payload.get('message', '')}"
    if action_name == "extend_time":
        return f"EXTEND_TIME:{int(payload['minutes'])}"
    if action_name == "clear_manual_lock":
        return "CLEAR_MANUAL_LOCK"
    if action_name == "clear_extensions":
        return "CLEAR_EXTENSIONS"
    if action_name == "set_daily_limit":
        minutes = payload.get("minutes")
        if minutes is None or minutes == "":
            return "CLEAR_USAGE_LIMIT"
        return f"SET_DAILY_LIMIT:{int(minutes)}"
    if action_name == "set_bed_time":
        return f"SET_BED_TIME:{payload['time']}"
    if action_name == "clear_bed_time":
        return "CLEAR_LOCK_TIMES"
    if action_name == "set_wake_time":
        return f"SET_WAKE_TIME:{payload['time']}"
    if action_name == "clear_usage_limit":
        return "CLEAR_USAGE_LIMIT"
    if action_name == "clear_lock_times":
        return "CLEAR_LOCK_TIMES"
    if action_name == "clear_all":
        return "CLEAR_ALL"
    return None


def main() -> None:
    host = os.environ.get("KID_PC_MONITOR_HOST", "0.0.0.0")
    port = int(os.environ.get("KID_PC_MONITOR_PORT", "5000"))
    app = create_app()
    print(f"Kid PC Monitor web panel on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
