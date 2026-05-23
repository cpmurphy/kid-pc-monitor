from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import json
import os
import secrets
import socket
import threading
import ipaddress
import time
from datetime import datetime
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from kid_pc_monitor.paths import config_dir, template_dir
from kid_pc_monitor.remote_client import (
    get_default_scan_network,
    get_local_ip,
    get_lock_times,
    get_wake_time,
    get_manual_lock,
    get_time_remaining,
    get_usage_limit,
    parse_scan_subnet,
    refresh_discovered_entry,
    scan_for_servers as discover_servers,
    send_command,
)

_TEMPLATE_DIR = template_dir()
_AUTH_DIR = config_dir()

app = Flask(__name__, template_folder=str(_TEMPLATE_DIR))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

AUTH_FILE = _AUTH_DIR / "web_panel_auth.json"
_LEGACY_AUTH_FILE = Path(__file__).resolve().parent.parent / "web_panel_auth.json"


def _migrate_legacy_auth_file() -> None:
    if _LEGACY_AUTH_FILE.is_file() and not AUTH_FILE.is_file():
        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        AUTH_FILE.write_bytes(_LEGACY_AUTH_FILE.read_bytes())


_migrate_legacy_auth_file()
SESSION_AUTH_KEY = "panel_auth"
PANEL_LOGIN_USERNAME = "Kids PC Control Panel"


def read_auth_file():
    if not AUTH_FILE.is_file():
        return {}
    try:
        return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def write_auth_file(data):
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = AUTH_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, AUTH_FILE)


def get_stored_password_hash():
    h = read_auth_file().get("password_hash")
    return h if isinstance(h, str) and h else None


def password_is_configured():
    return get_stored_password_hash() is not None


def sync_secret_key_from_disk():
    data = read_auth_file()
    sk = data.get("secret_key")
    if isinstance(sk, str) and len(sk) >= 16:
        app.secret_key = sk
    else:
        app.secret_key = secrets.token_hex(32)


sync_secret_key_from_disk()


def safe_next_path(next_param):
    if not next_param or not isinstance(next_param, str):
        return url_for("index")
    n = next_param.strip()
    if not n.startswith("/") or n.startswith("//"):
        return url_for("index")
    return n

# Store discovered PCs
discovered_pcs = {}
last_scan_time = None
last_scan_network = None


def scan_for_servers(port=9999, subnet=None):
    """Scan a network for PCs running the control server."""
    global discovered_pcs, last_scan_time, last_scan_network

    _network, network_label = parse_scan_subnet(subnet)
    discovered_pcs = discover_servers(port=port, subnet=subnet)
    last_scan_time = datetime.now()
    last_scan_network = network_label
    return discovered_pcs



@app.before_request
def require_panel_password():
    if request.endpoint == "static" or request.endpoint is None:
        return None
    if not password_is_configured():
        return None
    if session.get(SESSION_AUTH_KEY):
        return None
    if request.endpoint == "login":
        return None
    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not password_is_configured():
        return redirect(url_for("index"))
    if session.get(SESSION_AUTH_KEY):
        return redirect(url_for("index"))
    if request.method == "POST":
        pwd = request.form.get("password", "")
        ph = get_stored_password_hash()
        if ph and check_password_hash(ph, pwd):
            session.clear()
            session[SESSION_AUTH_KEY] = True
            return redirect(safe_next_path(request.form.get("next")))
        flash("Incorrect password.", "error")
    next_path = safe_next_path(request.form.get("next") or request.args.get("next"))
    return render_template(
        "login.html",
        next=next_path,
        panel_username=PANEL_LOGIN_USERNAME,
    )


@app.route("/logout")
def logout():
    session.pop(SESSION_AUTH_KEY, None)
    if password_is_configured():
        return redirect(url_for("login"))
    return redirect(url_for("index"))


@app.route("/set-password", methods=["GET", "POST"])
def set_password():
    if password_is_configured() and not session.get(SESSION_AUTH_KEY):
        return redirect(url_for("login", next=request.path))

    if request.method == "POST":
        p1 = request.form.get("password", "")
        p2 = request.form.get("password_confirm", "")
        if len(p1) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif p1 != p2:
            flash("Passwords do not match.", "error")
        else:
            data = read_auth_file()
            secret_key = data.get("secret_key")
            if not isinstance(secret_key, str) or len(secret_key) < 16:
                secret_key = secrets.token_hex(32)
            data["secret_key"] = secret_key
            data["password_hash"] = generate_password_hash(p1)
            write_auth_file(data)
            app.secret_key = secret_key
            session.clear()
            session[SESSION_AUTH_KEY] = True
            flash("Password saved. Use it to sign in on other devices or browsers.", "success")
            return redirect(url_for("index"))

    changing = password_is_configured()
    return render_template(
        "set_password.html",
        changing=changing,
        panel_username=PANEL_LOGIN_USERNAME,
    )


@app.route('/')
def index():
    """Main page showing all discovered PCs"""
    for ip in list(discovered_pcs.keys()):
        refresh_discovered_entry(ip, discovered_pcs[ip])

    return render_template(
        'index.html',
        pcs=discovered_pcs,
        last_scan=last_scan_time,
        last_scan_network=last_scan_network,
        default_subnet=str(get_default_scan_network()),
        scan_subnet=request.args.get('subnet', ''),
        scan_error=request.args.get('error'),
        password_protected=password_is_configured(),
        panel_auth=bool(session.get(SESSION_AUTH_KEY))
    )


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan for PCs and redirect to main page"""
    subnet = request.args.get('subnet') or request.form.get('subnet')
    try:
        scan_for_servers(subnet=subnet)
    except ValueError as exc:
        return redirect(url_for('index', error=str(exc), subnet=subnet or ''))
    return redirect(url_for('index', subnet=subnet or ''))


@app.route('/control/<ip>')
def control(ip):
    """Control page for a specific PC"""
    if ip in discovered_pcs:
        pc_info = discovered_pcs[ip]
    else:
        pc_info = {'hostname': 'Unknown', 'status': 'unknown'}
    refresh_discovered_entry(ip, pc_info)
    if ip in discovered_pcs:
        discovered_pcs[ip] = pc_info

    if not pc_info.get('reachable'):
        return render_template(
            'control.html',
            ip=ip,
            pc_info=pc_info,
            password_protected=password_is_configured(),
            panel_auth=bool(session.get(SESSION_AUTH_KEY)),
        )

    usage_limit = get_usage_limit(ip)
    pc_info['usage_limit'] = usage_limit

    pc_info['manual_lock_active'] = get_manual_lock(ip)

    lock_times = get_lock_times(ip)
    pc_info['lock_times'] = lock_times

    wake_time = get_wake_time(ip)
    pc_info['wake_time'] = wake_time

    time_remaining = get_time_remaining(ip)
    pc_info['time_remaining'] = time_remaining

    return render_template('control.html', ip=ip, pc_info=pc_info,
                           password_protected=password_is_configured(),
                           panel_auth=bool(session.get(SESSION_AUTH_KEY)))


@app.route('/action', methods=['POST'])
def action():
    """Execute an action on a PC"""
    data = request.json
    ip = data.get('ip')
    action_type = data.get('action')

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Action request: {action_type} for {ip}")

    if action_type == 'lock':
        success, response = send_command(ip, "LOCK")
        if success and ip in discovered_pcs:
            discovered_pcs[ip]['locked'] = True
    elif action_type == 'shutdown':
        success, response = send_command(ip, "SHUTDOWN")
    elif action_type == 'message':
        message = data.get('message', '')
        success, response = send_command(ip, f"MESSAGE:{message}")
    elif action_type == 'set_limit':
        minutes = data.get('minutes', 120)
        success, response = send_command(ip, f"SET_LIMIT:{minutes}")
    elif action_type == 'add_lock_time':
        lock_time = data.get('time', '21:00')
        success, response = send_command(ip, f"ADD_LOCK_TIME:{lock_time}")
    elif action_type == 'set_wake_time':
        wake_time = data.get('time', '07:00')
        success, response = send_command(ip, f"SET_WAKE_TIME:{wake_time}")
    elif action_type == 'clear_usage_limit':
        success, response = send_command(ip, "CLEAR_USAGE_LIMIT")
    elif action_type == 'clear_lock_times':
        success, response = send_command(ip, "CLEAR_LOCK_TIMES")
    elif action_type == 'clear_manual_lock':
        success, response = send_command(ip, "CLEAR_MANUAL_LOCK")
    elif action_type == 'clear_all':
        success, response = send_command(ip, "CLEAR_ALL")
    else:
        success, response = False, "Unknown action"

    return jsonify({'success': success, 'response': response})


def main() -> None:
    print("Performing initial scan...")
    scan_for_servers()

    print("\nWeb Control Panel starting...")
    print(f"Access from your phone at: http://{get_local_ip()}:5000")
    print("Or from this PC at: http://localhost:5000")

    app.run(host='0.0.0.0', port=5000, debug=False)


if __name__ == '__main__':
    main()
