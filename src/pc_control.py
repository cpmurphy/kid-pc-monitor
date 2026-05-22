import math
import os
import sys
import time
import datetime
import ctypes
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, date as ddate, time as dtime
import subprocess
from ctypes import wintypes
import getpass
import json

import logging
from pathlib import Path

# Must match scripts/install.py FIREWALL_RULE_DISPLAY_NAME
_FIREWALL_RULE_DISPLAY_NAME = "Kid PC Monitor Agent (TCP 9999)"

try:
    from lock_policy import lock_decision, minutes_until_lock, should_monitor_user
except ImportError:
    from src.lock_policy import lock_decision, minutes_until_lock, should_monitor_user

# ============================================
# CONFIGURATION
# ============================================

# List of Windows usernames to monitor (leave empty to monitor all users)
# Example: MONITORED_USERS = ['Tommy', 'Sarah', 'kid1']
MONITORED_USERS = []

# List of Windows usernames to EXEMPT from monitoring (parents/admins)
# Example: EXEMPT_USERS = ['pavel', 'Mom', 'Dad', 'Administrator']
EXEMPT_USERS = []

# If both lists are empty, ALL users will be monitored
# If MONITORED_USERS has entries, ONLY those users are monitored
# If EXEMPT_USERS has entries, everyone EXCEPT those users is monitored

# ============================================

# Set up per-user data directory for log + state.
# Lives under the running user's profile so the agent can write even when
# installed system-wide (e.g. C:\ProgramData\KidPCMonitor) from an admin
# account while running in a non-admin child's session.
data_dir = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'KidPCMonitor'
data_dir.mkdir(parents=True, exist_ok=True)

log_file = data_dir / 'pc_control.log'
AGENT_PORT = 9999

def _log_level_from_env() -> int:
    raw = os.environ.get('KID_PC_MONITOR_LOG_LEVEL', 'INFO').strip().upper()
    return getattr(logging, raw, logging.INFO)


def _configure_logging():
    """Append to the per-user log (do not truncate — empty logs make debugging hard)."""
    level = _log_level_from_env()
    root = logging.getLogger()
    root.setLevel(level)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    ))
    root.addHandler(handler)
    return level

_log_level = _configure_logging()
logger = logging.getLogger('kid_pc_monitor')


def _run_powershell_json(script: str):
    """Run a PowerShell snippet that prints a single JSON object; return dict or None."""
    try:
        out = subprocess.check_output(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).strip()
        if not out:
            return None
        return json.loads(out)
    except (subprocess.SubprocessError, json.JSONDecodeError, ValueError) as exc:
        logger.debug("PowerShell diagnostic failed: %s", exc)
        return None


def log_connectivity_diagnostics():
    """
    Log Windows network profile and firewall rule state.

    Helps explain unreachable agents when the PC is online but classified as a
    Public network (installer firewall rule is Private+Domain by default).
    """
    if sys.platform != 'win32':
        return

    primary_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
    except OSError:
        pass

    logger.info(
        "Connectivity check: pid=%s user=%s primary_ip=%s python=%s log=%s level=%s",
        os.getpid(),
        getpass.getuser(),
        primary_ip or "none",
        sys.executable,
        log_file,
        logging.getLevelName(_log_level),
    )

    on_public = False
    profiles = _run_powershell_json(
        "@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias, IPv4Connectivity, NetworkCategory) | "
        "ConvertTo-Json -Compress"
    )
    if profiles is None:
        logger.warning("Could not read Windows network profiles (Get-NetConnectionProfile)")
    elif isinstance(profiles, dict):
        profiles = [profiles]
    if profiles:
        for entry in profiles:
            logger.info(
                "Network profile: interface=%s connectivity=%s category=%s",
                entry.get('InterfaceAlias', '?'),
                entry.get('IPv4Connectivity', '?'),
                entry.get('NetworkCategory', '?'),
            )
        def _is_public(category):
            if category in (0, '0'):
                return True
            return str(category).lower() == 'public'

        on_public = any(_is_public(p.get('NetworkCategory')) for p in profiles)
        if on_public:
            logger.warning(
                "At least one interface is Public. The installer "
                "firewall rule allows inbound TCP %s only on Private/Domain "
                "unless you chose to include Public. Remote scans and pc_cli "
                "will fail until the network is Private or the rule includes Public.",
                AGENT_PORT,
            )

    rule = _run_powershell_json(
        f"$r = Get-NetFirewallRule -DisplayName '{_FIREWALL_RULE_DISPLAY_NAME}' "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if (-not $r) { @{{found=$false}} | ConvertTo-Json -Compress } "
        "else { "
        "@{{found=$true; enabled=$r.Enabled; profile=$r.Profile; "
        "program=($r | Get-NetFirewallApplicationFilter).Program; "
        "localPort=($r | Get-NetFirewallPortFilter).LocalPort}} | "
        "ConvertTo-Json -Compress "
        "}"
    )
    if rule is None:
        logger.warning("Could not query Windows Firewall rule for the agent")
    elif not rule.get('found'):
        logger.warning(
            "No firewall rule named %r — inbound TCP 9999 may be blocked. "
            "Re-run scripts/install.py as administrator.",
            _FIREWALL_RULE_DISPLAY_NAME,
        )
    else:
        profile_mask = int(rule.get('profile') or 0)
        profile_names = []
        if profile_mask & 1:
            profile_names.append('Domain')
        if profile_mask & 2:
            profile_names.append('Private')
        if profile_mask & 4:
            profile_names.append('Public')
        logger.info(
            "Firewall rule: enabled=%s profiles=%s (%s) program=%s localPort=%s",
            rule.get('enabled'),
            profile_mask,
            ','.join(profile_names) or 'none',
            rule.get('program'),
            rule.get('localPort'),
        )
        if on_public and not (profile_mask & 4):
            logger.warning(
                "Network is Public but the firewall rule does not include the "
                "Public profile — LAN clients cannot reach TCP %s. Set the home "
                "network to Private in Windows Settings, or re-run scripts/install.py "
                "and allow Public networks.",
                AGENT_PORT,
            )
        program = rule.get('program') or ''
        if program and os.path.normcase(sys.executable) != os.path.normcase(program):
            logger.warning(
                "Firewall rule program %r does not match this process %r — "
                "inbound connections may be blocked.",
                program,
                sys.executable,
            )

class PCTimeControl:
    def __init__(self):
        self.lock_times = []
        self.usage_limit = None
        self.manual_lock_active = False
        # Accumulated active-use seconds for today (session active + unlocked).
        # Advanced by tick_accumulator() while the kid is actually on the PC,
        # so locked or backgrounded time doesn't burn their allowance.
        self.accumulated_seconds = 0.0
        self.accumulated_date = datetime.now().date()
        # Wall-clock of the most recent observed active+unlocked tick, or None
        # if the previous tick was paused. Used to credit elapsed seconds
        # between consecutive active ticks while ignoring paused gaps.
        self.last_tick_at = None
        # Throttle for periodic save_state() calls inside run_monitor.
        self.last_persist_at = None
        self.is_locked = False
        self.last_activity = datetime.now()
        self.current_user = getpass.getuser()
        self.state_file = str(data_dir / 'pc_control_state.json')
        self.logger = logging.getLogger('PCTimeControl')
        self.warnings_sent = set()  # Track which warnings have been sent
        self.warning_intervals = [15, 5, 1]  # Warning times in minutes before lock
        self.warnings_date = datetime.now().date()  # Reset warnings_sent at midnight rollover

        # Log which user we're running as
        if self.should_monitor_user():
            self.logger.info(f"Monitoring enabled for user: {self.current_user}")
            print(f"[{datetime.now():%H:%M:%S}] Monitoring user: {self.current_user}")
        else:
            self.logger.info(f"User {self.current_user} is EXEMPT from monitoring")
            print(f"[{datetime.now():%H:%M:%S}] User {self.current_user} is EXEMPT - no restrictions will apply")

        # Load previous state if exists
        self.load_state()

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_activity, daemon=True)
        self.monitor_thread.start()

    def should_monitor_user(self):
        """Check if current user should be monitored based on configuration"""
        return should_monitor_user(self.current_user, MONITORED_USERS, EXEMPT_USERS)

    def load_state(self):
        """Load saved state from JSON file"""
        try:
            if not os.path.exists(self.state_file):
                self.logger.info("No state file at %s", self.state_file)
                return

            with open(self.state_file, 'r') as f:
                state = json.load(f)

            self.logger.info(
                "State file %s: %s",
                self.state_file,
                json.dumps(state, sort_keys=True),
            )

            # Restore lock times
            if 'lock_times' in state:
                self.lock_times = [dtime(*map(int, t.split(':'))) for t in state['lock_times']]

            # Restore usage limit
            if 'usage_limit' in state:
                self.usage_limit = state['usage_limit']

            # Restore persistent manual lock requested by the parent.
            self.manual_lock_active = bool(state.get('manual_lock_active', False))

            # Restore accumulated active-use counter, but only if it's for today.
            current_date = datetime.now().date()
            if 'accumulated_date' in state:
                saved_date = ddate.fromisoformat(state['accumulated_date'])
                if saved_date < current_date:
                    self.logger.info(
                        "Accumulated counter in file was for %s; reset to 0 for today (%s)",
                        saved_date.isoformat(),
                        current_date.isoformat(),
                    )
                    print(f"[{datetime.now():%H:%M:%S}] Usage timer reset for new day")
                    self.accumulated_seconds = 0.0
                    self.accumulated_date = current_date
                else:
                    self.accumulated_seconds = float(state.get('accumulated_seconds', 0.0))
                    self.accumulated_date = saved_date

            lock_times_label = (
                ",".join(f"{lt.hour:02d}:{lt.minute:02d}" for lt in self.lock_times)
                or "none"
            )
            self.logger.info(
                "State applied: lock_times=[%s] usage_limit=%s manual_lock=%s "
                "accumulated_min=%.1f accumulated_date=%s",
                lock_times_label,
                self.usage_limit,
                self.manual_lock_active,
                self.accumulated_seconds / 60,
                self.accumulated_date.isoformat(),
            )
            print(f"[{datetime.now():%H:%M:%S}] Loaded previous settings from {self.state_file}")
        except Exception as e:
            self.logger.error("Error loading state: %s", e, exc_info=True)
            print(f"[{datetime.now():%H:%M:%S}] Could not load previous state: {e}")

    def save_state(self):
        """Save current state to JSON file"""
        try:
            state = {
                'lock_times': [f"{lt.hour:02d}:{lt.minute:02d}" for lt in self.lock_times],
                'usage_limit': self.usage_limit,
                'manual_lock_active': self.manual_lock_active,
                'accumulated_seconds': round(self.accumulated_seconds, 3),
                'accumulated_date': self.accumulated_date.isoformat(),
                'current_user': self.current_user
            }

            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)

            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error("Error saving state: %s", e, exc_info=True)

    def check_if_locked(self):
        """
        Returns True if LogonUI.exe is running in *this* session — i.e.
        our session is locked.

        Filtering by session matters when another user is logged in via
        fast user switching: their locked/disconnected session also runs
        LogonUI.exe, which would otherwise make us falsely report LOCKED.
        """
        try:
            kernel32 = ctypes.windll.kernel32
            sid = ctypes.c_ulong()
            ok = kernel32.ProcessIdToSessionId(
                kernel32.GetCurrentProcessId(), ctypes.byref(sid)
            )
            session_filter = f'/FI "SESSION eq {sid.value}" ' if ok else ''
            out = subprocess.check_output(
                f'tasklist /FI "IMAGENAME eq LogonUI.exe" {session_filter}/NH',
                shell=True,
                text=True
            )
            return "LogonUI.exe" in out
        except Exception as e:
            self.logger.error("Error checking lock state (LogonUI): %s", e, exc_info=True)
            return False

    def session_is_active(self):
        """
        True if our session is the active console session AND not locked.

        Used by tick_accumulator to advance the usage counter only while the
        kid is actually on the PC — not while their session is locked or has
        been backgrounded by fast user switching.
        """
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            our_sid = ctypes.c_ulong()
            ok = kernel32.ProcessIdToSessionId(
                kernel32.GetCurrentProcessId(), ctypes.byref(our_sid)
            )
            if not ok:
                # Can't tell which session we're in; fall back to lock check
                # alone so we don't silently stop counting.
                return not self.check_if_locked()
            active_sid = kernel32.WTSGetActiveConsoleSessionId()
            # 0xFFFFFFFF means "no session is currently attached to the console"
            # (e.g. between logoff and next logon).
            if active_sid == 0xFFFFFFFF or active_sid != our_sid.value:
                return False
            return not self.check_if_locked()
        except Exception as e:
            self.logger.error("Error checking session active state: %s", e, exc_info=True)
            return not self.check_if_locked()

    def tick_accumulator(self):
        """
        Advance the active-use counter by the seconds elapsed since the last
        active tick. Reset at local midnight. Called once per second from
        run_monitor.
        """
        now = datetime.now()

        if now.date() != self.accumulated_date:
            self.logger.info(
                "Midnight rollover: resetting accumulated counter "
                "(was %.1f min for %s)",
                self.accumulated_seconds / 60,
                self.accumulated_date.isoformat(),
            )
            self.accumulated_seconds = 0.0
            self.accumulated_date = now.date()
            self.last_tick_at = None

        if self.should_monitor_user() and self.session_is_active():
            if self.last_tick_at is not None:
                delta = (now - self.last_tick_at).total_seconds()
                # Clamp to (0, 60): negative means clock went backwards;
                # >60 means the loop stalled or we resumed from sleep, in
                # which case we don't want to credit the whole gap.
                if 0 < delta < 60:
                    self.accumulated_seconds += delta
            self.last_tick_at = now
        else:
            self.last_tick_at = None

    def monitor_activity(self):
        """Monitor lock/unlock status"""
        while True:
            actual_locked = self.check_if_locked()

            # Detect unlock
            if self.is_locked and not actual_locked:
                self.is_locked = False
                print(f"[{datetime.now().strftime('%H:%M:%S')}] PC has been unlocked (detected by activity)")

            # Detect manual lock (not by our script)
            elif not self.is_locked and actual_locked:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] PC has been locked (detected)")

            time.sleep(3)  # Check every 3 seconds

    def add_scheduled_lock(self, hour, minute):
        """Add a time when the PC should be locked"""
        self.lock_times.append(dtime(hour, minute))

    def set_usage_limit(self, minutes):
        """Set maximum usage time in minutes"""
        self.usage_limit = minutes

    def show_message(self, message, title="PC Time Control"):
        """Display a message using tkinter"""
        def display():
            root = None
            try:
                root = tk.Tk()
                root.withdraw()  # Hide the main window
                root.attributes('-topmost', True)  # Make it appear on top

                # Auto-close after 60 seconds to prevent hanging
                root.after(60000, root.destroy)

                messagebox.showwarning(title, message)
            except Exception as e:
                self.logger.error(f"Error showing message: {e}")
                print(f"[{datetime.now():%H:%M:%S}] Error showing message: {e}")
            finally:
                if root:
                    try:
                        root.quit()
                        root.destroy()
                    except Exception:
                        pass  # Already destroyed

        # Run in a separate thread to avoid blocking
        threading.Thread(target=display, daemon=True).start()

    def lock_pc(self):
        """Lock the Windows PC"""
        try:
            self.is_locked = True
            ctypes.windll.user32.LockWorkStation()
            self.logger.info("PC locked successfully")
        except Exception as e:
            self.logger.error(f"Error locking PC: {e}")
            print(f"[{datetime.now():%H:%M:%S}] Error locking PC: {e}")

    def shutdown_pc(self, seconds=60):
        """Shutdown PC with warning"""
        try:
            os.system(f'shutdown /s /t {seconds} /c "Computer will shutdown in {seconds} seconds"')
            self.logger.info(f"Shutdown initiated ({seconds}s)")
        except Exception as e:
            self.logger.error(f"Error initiating shutdown: {e}")
            print(f"[{datetime.now():%H:%M:%S}] Error shutting down: {e}")

    def cancel_shutdown(self):
        """Cancel pending shutdown"""
        os.system('shutdown /a')

    def get_time_remaining(self):
        """Calculate minutes remaining until lock. Returns None if no limit set."""
        return minutes_until_lock(
            now=datetime.now(),
            lock_times=self.lock_times,
            usage_limit=self.usage_limit,
            accumulated_minutes=self.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.manual_lock_active,
        )

    def check_and_send_warnings(self):
        """Check if warnings should be sent and send them"""
        # Clear sent-warning memory at local midnight so the 15/5/1-minute
        # warnings fire again for the next day if the agent has been running
        # continuously across the rollover.
        today = datetime.now().date()
        if today != self.warnings_date:
            self.warnings_sent.clear()
            self.warnings_date = today

        time_remaining = self.get_time_remaining()

        if time_remaining is None or time_remaining <= 0:
            return

        # Fire the smallest applicable threshold first so a kid with only a
        # few minutes left doesn't get a misleading "15 minutes" popup. Once
        # a smaller threshold fires, mark the larger thresholds as also-sent
        # — those longer warning windows never applied to this session and
        # would just be noise if they fired later.
        for warning_mins in sorted(self.warning_intervals):
            warning_key = f"{warning_mins}min"
            if warning_key in self.warnings_sent:
                continue
            if time_remaining > warning_mins:
                continue

            self.warnings_sent.add(warning_key)
            for larger in self.warning_intervals:
                if larger > warning_mins:
                    self.warnings_sent.add(f"{larger}min")

            actual_mins = max(1, math.ceil(time_remaining))
            unit = "minute" if actual_mins == 1 else "minutes"
            msg = f"⚠️ Computer will lock in {actual_mins} {unit}!"

            self.show_message(msg, "Warning")
            self.logger.info(
                "Warning sent: %d %s remaining (threshold %d)",
                actual_mins, unit, warning_mins,
            )
            print(f"[{datetime.now():%H:%M:%S}] Warning: {actual_mins} {unit} until lock")
            break

    def currently_in_lock_window(self):
        """
        Return (locked, reason) for whether the agent should currently be
        enforcing a lock. Treats each scheduled lock_time as the start of a
        window that runs until midnight of the same local day, so a child who
        signs in after the bedtime minute still gets locked out. Usage-limit
        enforcement is a simple "minutes-used >= limit" check.
        """
        decision = lock_decision(
            now=datetime.now(),
            lock_times=self.lock_times,
            usage_limit=self.usage_limit,
            accumulated_minutes=self.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.manual_lock_active,
        )
        return decision.should_lock, decision.reason

    def run_monitor(self):
        """
        Main monitoring loop. Continuously re-issues LockWorkStation while a
        lock window is active so a child who unlocks the screen with their
        password is immediately re-locked.
        """
        print("PC Time Control is running...")
        last_logged_reason = None
        while True:
            self.tick_accumulator()
            self.check_and_send_warnings()

            locked, reason = self.currently_in_lock_window()
            if locked and not self.check_if_locked():
                if reason != last_logged_reason:
                    self.logger.info(f"Locking PC: {reason}")
                    print(f"[{datetime.now():%H:%M:%S}] Locking PC: {reason}")
                    last_logged_reason = reason
                self.lock_pc()
            elif not locked:
                last_logged_reason = None

            # Persist the accumulator periodically so a crash or power loss
            # doesn't hand the kid a free reset of their daily usage.
            now = datetime.now()
            if self.last_persist_at is None or (now - self.last_persist_at).total_seconds() >= 60:
                self.save_state()
                self.last_persist_at = now

            time.sleep(1)

# Simple Remote Control Server
class RemoteControlServer:
    def __init__(self, port=9999, timeout=60):
        """
        Initialize the remote control server.
        
        Args:
            port (int): Port number to listen on (default: 9999)
            timeout (int): Socket timeout in seconds (default: 60)
        """
        self.port = port
        self.timeout = timeout
        self.pc_control = None
        self.running = False
        self.server_socket = None
        self.clients = {}
        self.client_id_counter = 0
        self.last_primary_ip = None
        self.listener_ready = threading.Event()
        self.logger = logging.getLogger('RemoteControlServer')

    def get_primary_ip(self):
        """Return the primary IPv4 address, or None while networking is down."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return None

    def close_sockets(self):
        """Close active client and listener sockets without changing run intent."""
        for client_id, client_info in list(self.clients.items()):
            try:
                client_info['socket'].close()
            except Exception as e:
                self.logger.error(f"Error closing client socket {client_id}: {e}")
            del self.clients[client_id]

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing server socket: {e}")
            self.server_socket = None

    def check_for_ip_change(self):
        """Return True when the primary IP changed and the listener should restart."""
        current_ip = self.get_primary_ip()
        if current_ip != self.last_primary_ip:
            self.logger.warning(
                "Primary IP changed from %s to %s; restarting TCP listener",
                self.last_primary_ip or "none",
                current_ip or "none",
            )
            print(
                f"[{datetime.now():%H:%M:%S}] Network address changed "
                f"({self.last_primary_ip or 'none'} -> {current_ip or 'none'}); "
                "restarting server"
            )
            self.last_primary_ip = current_ip
            log_connectivity_diagnostics()
            return True
        return False

    def start_server(self, pc_control):
        """Start the remote control server and recover from network/socket changes."""
        self.pc_control = pc_control
        self.running = True
        restart_delay = 1

        while self.running:
            self.listener_ready.clear()
            try:
                self.last_primary_ip = self.get_primary_ip()
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.settimeout(5)  # Allow periodic health checks.
                self.server_socket.bind(('0.0.0.0', self.port))
                self.server_socket.listen(5)
                self.listener_ready.set()

                self.logger.info(
                    "Listening on 0.0.0.0:%s (primary IP: %s)",
                    self.port,
                    self.last_primary_ip or "unknown",
                )
                restart_delay = 1

                while self.running:
                    try:
                        client_socket, client_address = self.server_socket.accept()
                        client_socket.settimeout(self.timeout)

                        client_id = self.client_id_counter
                        self.client_id_counter += 1

                        self.logger.info(
                            "Client connected from %s (id=%s)",
                            client_address[0],
                            client_id,
                        )

                        # Start a new thread for each client
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, client_address, client_id),
                            daemon=True
                        )
                        self.clients[client_id] = {
                            'thread': client_thread,
                            'socket': client_socket,
                            'address': client_address
                        }
                        client_thread.start()

                    except socket.timeout:
                        if self.check_for_ip_change():
                            break
                        continue
                    except OSError as e:
                        if self.running:
                            self.logger.warning(
                                "Accept failed; restarting listener: %s", e, exc_info=True
                            )
                        break
                    except Exception as e:
                        if self.running:
                            self.logger.error(
                                "Accept error; restarting listener: %s", e, exc_info=True
                            )
                        break

            except Exception as e:
                if self.running:
                    self.logger.error(
                        "Listener bind/start failed; retry in %ss: %s",
                        restart_delay,
                        e,
                        exc_info=True,
                    )
            finally:
                self.close_sockets()

            if self.running:
                time.sleep(restart_delay)
                restart_delay = min(restart_delay * 2, 30)

        self.logger.info("Server stopped")

    def handle_client(self, client_socket, client_address, client_id):
        """Handle communication with a connected client."""
        try:
            while self.running:
                try:
                    data = client_socket.recv(1024).decode().strip()
                    if not data:
                        break  # Client disconnected
                        
                    self.logger.debug(
                        "Command from %s (ID: %s): %s", client_address, client_id, data
                    )
                    response = self.process_command(data)
                    
                    if response is not None:
                        client_socket.sendall(response.encode())
                        
                except socket.timeout:
                    # Send keepalive
                    client_socket.sendall(b"ALIVE")
                    continue
                except Exception as e:
                    self.logger.error(
                        "Client %s error: %s", client_id, e, exc_info=True
                    )
                    break
                    
        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            self.logger.debug("Client %s (ID: %s) disconnected", client_address, client_id)

    def process_command(self, command):
        """Process incoming commands and return responses."""
        try:
            if command == "LOCK":
                self.pc_control.manual_lock_active = True
                self.pc_control.save_state()
                self.pc_control.lock_pc()
                return "Manual lock enabled; PC locked"
                
            elif command == "SHUTDOWN":
                self.pc_control.shutdown_pc()
                return "PC Shutting down"
                
            elif command == "GET_NAME":
                import platform
                return platform.node()

            elif command == "GET_CURRENT_USER":
                return self.pc_control.current_user

            elif command == "GET_USAGE_LIMIT":
                if self.pc_control.usage_limit:
                    return str(self.pc_control.usage_limit)
                return "None"

            elif command == "GET_MANUAL_LOCK":
                return "YES" if self.pc_control.manual_lock_active else "NO"

            elif command == "GET_LOCK_TIMES":
                if self.pc_control.lock_times:
                    times = [f"{lt.hour:02d}:{lt.minute:02d}" for lt in self.pc_control.lock_times]
                    return ",".join(times)
                return "None"

            elif command == "GET_TIME_REMAINING":
                remaining = self.pc_control.get_time_remaining()
                if remaining is not None:
                    return f"{int(remaining)} minutes"
                return "No limits set"

            elif command == "GET_STATUS":
                actual_locked = self.pc_control.check_if_locked()
                if actual_locked != self.pc_control.is_locked:
                    self.pc_control.is_locked = actual_locked
                    self.logger.debug(
                        "Status query: %s", 'LOCKED' if actual_locked else 'UNLOCKED'
                    )
                return "LOCKED" if actual_locked else "UNLOCKED"
                
            elif command.startswith("MESSAGE:"):
                msg = command.split(":", 1)[1]
                self.pc_control.show_message(msg)
                return "Message sent"
                
            elif command.startswith("SET_LIMIT:"):
                try:
                    minutes = int(command.split(":", 1)[1])
                    self.pc_control.set_usage_limit(minutes)
                    # Setting a new limit gives the kid a fresh budget from now.
                    self.pc_control.accumulated_seconds = 0.0
                    self.pc_control.accumulated_date = datetime.now().date()
                    self.pc_control.last_tick_at = None
                    self.pc_control.warnings_sent.clear()  # Clear warnings for new limit
                    self.pc_control.save_state()  # Save state after setting limit
                    return f"Usage limit set to {minutes} minutes"
                except ValueError:
                    return "Invalid limit value"

            elif command.startswith("ADD_LOCK_TIME:"):
                try:
                    time_str = command.split(":", 1)[1]
                    hour, minute = map(int, time_str.split(":"))
                    self.pc_control.add_scheduled_lock(hour, minute)
                    self.pc_control.save_state()  # Save state after adding lock time
                    return f"Lock time added: {hour:02d}:{minute:02d}"
                except ValueError:
                    return "Invalid time format (use HH:MM)"
                    
            elif command.startswith("EXTEND_TIME:"):
                try:
                    minutes = int(command.split(":", 1)[1])
                    if self.pc_control.usage_limit:
                        self.pc_control.usage_limit += minutes
                        self.pc_control.save_state()  # Save state after extending time
                        return f"Extended time by {minutes} minutes"
                    return "No time limit set to extend"
                except ValueError:
                    return "Invalid time value"

            elif command == "CLEAR_USAGE_LIMIT":
                self.pc_control.usage_limit = None
                self.pc_control.save_state()
                self.logger.info("Usage limit cleared")
                return "Usage limit cleared"

            elif command == "CLEAR_LOCK_TIMES":
                self.pc_control.lock_times = []
                self.pc_control.warnings_sent.clear()  # Clear warnings too
                self.pc_control.save_state()
                self.logger.info("All scheduled lock times cleared")
                return "All scheduled lock times cleared"

            elif command == "CLEAR_MANUAL_LOCK":
                self.pc_control.manual_lock_active = False
                self.pc_control.save_state()
                self.logger.info("Manual lock cleared")
                return "Manual lock cleared"

            elif command == "CLEAR_ALL":
                self.pc_control.usage_limit = None
                self.pc_control.lock_times = []
                self.pc_control.manual_lock_active = False
                self.pc_control.warnings_sent.clear()
                self.pc_control.save_state()
                self.logger.info("All limits and locks cleared")
                return "All limits and locks cleared"

            elif command == "HELP":
                return (
                    "Available commands:\n"
                    "LOCK - Lock the PC and keep it locked until CLEAR_ALL\n"
                    "SHUTDOWN - Shutdown the PC\n"
                    "GET_NAME - Get PC name\n"
                    "GET_CURRENT_USER - Get current Windows username\n"
                    "GET_STATUS - Check if PC is locked\n"
                    "GET_USAGE_LIMIT - Get current usage limit\n"
                    "GET_MANUAL_LOCK - Check if manual lock enforcement is active\n"
                    "GET_LOCK_TIMES - Get scheduled lock times\n"
                    "GET_TIME_REMAINING - Get time until next lock\n"
                    "MESSAGE:<text> - Show popup message\n"
                    "SET_LIMIT:<minutes> - Set usage limit\n"
                    "ADD_LOCK_TIME:HH:MM - Add scheduled lock\n"
                    "EXTEND_TIME:<minutes> - Extend usage time\n"
                    "CLEAR_USAGE_LIMIT - Remove usage limit\n"
                    "CLEAR_LOCK_TIMES - Remove all scheduled locks\n"
                    "CLEAR_MANUAL_LOCK - Remove manual lock enforcement\n"
                    "CLEAR_ALL - Clear all limits, scheduled locks, and manual lock"
                )
                
            else:
                return "Unknown command (try HELP)"
                
        except Exception as e:
            self.logger.error("Command processing error: %s", e, exc_info=True)
            return f"Error processing command: {e}"

    def stop_server(self):
        """Stop the server and clean up resources."""
        self.running = False
        self.close_sockets()

    def __del__(self):
        """Destructor to ensure proper cleanup."""
        self.stop_server()

# Main
if __name__ == "__main__":
    script_path = os.path.abspath(__file__)

    def check_port_availability(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
            return True
        except socket.error:
            return False

    logger.info(
        "Agent process starting (pid=%s, user=%s, script=%s)",
        os.getpid(), getpass.getuser(), script_path,
    )
    log_connectivity_diagnostics()

    if not check_port_availability(AGENT_PORT):
        logger.error(
            "Port %s already in use — another KidPCMonitor instance is probably "
            "already running. Exiting duplicate startup.",
            AGENT_PORT,
        )
        sys.exit(1)

    # Create control instance
    control = PCTimeControl()
    
    # Enforce usage limits, bedtimes, and warnings (separate from the TCP server)
    enforcement_thread = threading.Thread(target=control.run_monitor, daemon=True)
    enforcement_thread.start()

    # Start remote control server
    remote = RemoteControlServer()
    server_thread = threading.Thread(target=remote.start_server, args=(control,))
    server_thread.daemon = True
    server_thread.start()
    
    if not remote.listener_ready.wait(timeout=10):
        logger.error(
            "TCP listener did not start on port %s within 10s — check %s",
            AGENT_PORT,
            log_file,
        )
        control.show_message(
            "Failed to start network server!\n"
            "Check firewall settings and try again.",
            "Server Error"
        )
        sys.exit(1)

    logger.info(
        "Agent running (enforcement + TCP %s on 0.0.0.0). "
        "Verbose command logging: set KID_PC_MONITOR_LOG_LEVEL=DEBUG",
        remote.port,
    )
    print("Server is running. Press Ctrl+C to stop.")
    
    try:
        # Keep main thread alive while server runs
        while remote.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        remote.stop_server()
        server_thread.join(2)  # Wait up to 2 seconds for thread to finish
        print("Server stopped.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sys.exit(0)
