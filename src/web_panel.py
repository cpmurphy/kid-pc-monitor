from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime

from remote_client import (
    check_pc_status,
    get_current_user,
    get_default_scan_network,
    get_local_ip,
    get_lock_times,
    get_time_remaining,
    get_usage_limit,
    parse_scan_subnet,
    scan_for_servers as discover_servers,
    send_command,
)

_APP_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _APP_DIR / "templates"

app = Flask(__name__, template_folder=str(_TEMPLATE_DIR))

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


@app.route('/')
def index():
    """Main page showing all discovered PCs"""
    for ip in discovered_pcs:
        status = check_pc_status(ip)
        discovered_pcs[ip]['locked'] = (status == "LOCKED")

        username = get_current_user(ip)
        if username:
            discovered_pcs[ip]['current_user'] = username

    return render_template(
        'index.html',
        pcs=discovered_pcs,
        last_scan=last_scan_time,
        last_scan_network=last_scan_network,
        default_subnet=str(get_default_scan_network()),
        scan_subnet=request.args.get('subnet', ''),
        scan_error=request.args.get('error'),
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
    pc_info = discovered_pcs.get(ip, {'hostname': 'Unknown', 'status': 'unknown'})
    status = check_pc_status(ip)
    pc_info['locked'] = (status == "LOCKED")

    username = get_current_user(ip)
    if username:
        pc_info['current_user'] = username

    usage_limit = get_usage_limit(ip)
    pc_info['usage_limit'] = usage_limit

    lock_times = get_lock_times(ip)
    pc_info['lock_times'] = lock_times

    time_remaining = get_time_remaining(ip)
    pc_info['time_remaining'] = time_remaining

    return render_template('control.html', ip=ip, pc_info=pc_info)


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
    print("Performing initial scan...")
    scan_for_servers()

    print("\nWeb Control Panel starting...")
    print(f"Access from your phone at: http://{get_local_ip()}:5000")
    print("Or from this PC at: http://localhost:5000")

    app.run(host='0.0.0.0', port=5000, debug=False)
