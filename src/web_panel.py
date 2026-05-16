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

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=_TEMPLATE_DIR)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

AUTH_FILE = Path(__file__).resolve().parent / "web_panel_auth.json"
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

# Custom PC names (optional) - Add your kids' PC names here
CUSTOM_PC_NAMES = {
    # Example: '192.168.1.105': 'Tommy\'s Laptop',
    # Example: '192.168.1.112': 'Sarah\'s Desktop',
}

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def check_pc_status(ip, port=9999):
    """Check if a PC is locked"""
    try:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking status of {ip}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"GET_STATUS")
        status = s.recv(1024).decode().strip()
        s.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Status of {ip}: {status}")
        return status
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error checking {ip}: {e}")
        return "UNKNOWN"

def get_current_user(ip, port=9999):
    """Get the current username logged in on the kid PC (as reported by the agent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"GET_CURRENT_USER")
        username = s.recv(1024).decode().strip()
        s.close()
        return username
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error getting user from {ip}: {e}")
        return None

def get_usage_limit(ip, port=9999):
    """Get the current usage limit in minutes"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"GET_USAGE_LIMIT")
        limit = s.recv(1024).decode().strip()
        s.close()
        return None if limit == "None" else int(limit)
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error getting limit from {ip}: {e}")
        return None

def get_lock_times(ip, port=9999):
    """Get scheduled lock times"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"GET_LOCK_TIMES")
        times = s.recv(1024).decode().strip()
        s.close()
        return None if times == "None" else times.split(',')
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error getting lock times from {ip}: {e}")
        return None

def get_time_remaining(ip, port=9999):
    """Get time remaining until next lock"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"GET_TIME_REMAINING")
        remaining = s.recv(1024).decode().strip()
        s.close()
        return remaining
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error getting time remaining from {ip}: {e}")
        return None

def scan_for_servers(port=9999):
    """Scan the local network for PCs running the control server"""
    global discovered_pcs, last_scan_time
    local_ip = get_local_ip()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    discovered_pcs = {}
    
    def check_host(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((str(ip), port))
            s.close()
            if result == 0:
                # Try to get hostname from the PC directly
                hostname = CUSTOM_PC_NAMES.get(str(ip), None)
                if not hostname:
                    try:
                        # First try to get name from the control server
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(1)
                        s2.connect((str(ip), port))
                        s2.send(b"GET_NAME")
                        hostname = s2.recv(1024).decode().strip()
                        s2.close()
                        if not hostname:
                            raise Exception("Empty name")
                    except:
                        try:
                            # Fallback to system hostname resolution
                            hostname = socket.gethostbyaddr(str(ip))[0]
                            hostname = hostname.split('.')[0].upper()
                        except:
                            hostname = f"PC at {ip}"
                
                discovered_pcs[str(ip)] = {
                    'hostname': hostname,
                    'status': 'online',
                    'locked': False,  # Will update in separate check
                    'last_seen': datetime.now()
                }
        except:
            pass
    
    threads = []
    for ip in network.hosts():
        t = threading.Thread(target=check_host, args=(ip,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    last_scan_time = datetime.now()
    return discovered_pcs

def send_command(host, command, port=9999):
    """Send a command to the remote PC"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((host, port))
        client.send(command.encode())
        response = client.recv(1024)
        client.close()
        return True, response.decode()
    except Exception as e:
        return False, str(e)


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
    # Update lock status and current user for all PCs
    for ip in discovered_pcs:
        status = check_pc_status(ip)
        discovered_pcs[ip]['locked'] = (status == "LOCKED")

        # Get current user
        username = get_current_user(ip)
        if username:
            discovered_pcs[ip]['current_user'] = username

    return render_template('index.html',
                         pcs=discovered_pcs,
                         last_scan=last_scan_time,
                         password_protected=password_is_configured(),
                         panel_auth=bool(session.get(SESSION_AUTH_KEY)))

@app.route('/scan')
def scan():
    """Scan for PCs and redirect to main page"""
    scan_for_servers()
    return redirect(url_for('index'))

@app.route('/control/<ip>')
def control(ip):
    """Control page for a specific PC"""
    pc_info = discovered_pcs.get(ip, {'hostname': 'Unknown', 'status': 'unknown'})
    # Check current lock status
    status = check_pc_status(ip)
    pc_info['locked'] = (status == "LOCKED")

    # Get current user
    username = get_current_user(ip)
    if username:
        pc_info['current_user'] = username

    # Get current limits and time remaining (always update, even if None)
    usage_limit = get_usage_limit(ip)
    pc_info['usage_limit'] = usage_limit  # Update even if None to clear old values

    lock_times = get_lock_times(ip)
    pc_info['lock_times'] = lock_times  # Update even if None to clear old values

    time_remaining = get_time_remaining(ip)
    pc_info['time_remaining'] = time_remaining  # Update even if None

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
        # Update our local status immediately
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
    elif action_type == 'clear_usage_limit':
        success, response = send_command(ip, "CLEAR_USAGE_LIMIT")
    elif action_type == 'clear_lock_times':
        success, response = send_command(ip, "CLEAR_LOCK_TIMES")
    elif action_type == 'clear_all':
        success, response = send_command(ip, "CLEAR_ALL")
    else:
        success, response = False, "Unknown action"

    return jsonify({'success': success, 'response': response})

if __name__ == '__main__':
    # Do initial scan
    print("Performing initial scan...")
    scan_for_servers()
    
    # Start the web server
    print(f"\nWeb Control Panel starting...")
    print(f"Access from your phone at: http://{get_local_ip()}:5000")
    print(f"Or from this PC at: http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
