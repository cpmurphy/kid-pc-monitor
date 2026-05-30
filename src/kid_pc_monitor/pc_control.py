import math
import os
import sys
import time
import socket
import threading
from datetime import datetime, time as dtime
import getpass

import logging
from pathlib import Path

from kid_pc_monitor import agent_protocol
from kid_pc_monitor import shared_secret
from kid_pc_monitor.agent_state import (
    AgentStateStore,
    DailySettings,
    RuntimeState,
    effective_daily_allowance_minutes,
    reset_runtime_for_new_period,
    runtime_state_is_current,
)
from kid_pc_monitor.host_platform import HostPlatform, get_default_platform
from kid_pc_monitor.network import get_primary_ipv4
from kid_pc_monitor.lock_policy import (
    DEFAULT_WAKE_TIME,
    enforcement_state,
    format_access_status,
    lock_decision,
    minutes_until_lock,
    parse_time_hhmm,
    should_monitor_user,
    usage_period_date,
)

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

# Morning unlock for bedtime curfews and daily usage reset (HH:MM local time).
# Overridden by wake_time in pc_control_state.json (set at install).
DEFAULT_WAKE_UP_TIME = DEFAULT_WAKE_TIME

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


def log_connectivity_diagnostics(platform: HostPlatform) -> None:
    """Delegate OS-specific network/firewall diagnostics to the platform layer."""
    platform.log_connectivity_diagnostics(
        logger,
        agent_port=AGENT_PORT,
        log_file=str(log_file),
        log_level_name=logging.getLevelName(_log_level),
        python_executable=sys.executable,
    )


class PCTimeControl:
    def __init__(
        self,
        platform: HostPlatform | None = None,
        *,
        monitored_users: list[str] | None = None,
        exempt_users: list[str] | None = None,
        data_directory: Path | None = None,
        start_background_threads: bool = True,
    ):
        self.platform = platform or get_default_platform()
        self.monitored_users = (
            MONITORED_USERS if monitored_users is None else monitored_users
        )
        self.exempt_users = EXEMPT_USERS if exempt_users is None else exempt_users

        self.daily = DailySettings(
            bed_time=None,
            wake_time=DEFAULT_WAKE_UP_TIME,
            allowance=None,
        )
        self.runtime = RuntimeState(
            timestamp=datetime.now(),
            accumulated_seconds=0.0,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        # Wall-clock of the most recent observed active+unlocked tick, or None
        # if the previous tick was paused. Used to credit elapsed seconds
        # between consecutive active ticks while ignoring paused gaps.
        self.last_tick_at = None
        # Throttle for periodic save_state() calls inside run_monitor.
        self.last_persist_at = None
        self.is_locked = False
        self.last_activity = datetime.now()
        self.current_user = getpass.getuser()
        base_dir = data_directory or data_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        self.state_store = AgentStateStore(base_dir, current_user=self.current_user)
        self.logger = logging.getLogger('PCTimeControl')
        self.warnings_sent = set()  # Track which warnings have been sent
        self.warning_intervals = [15, 5, 1]  # Warning times in minutes before lock
        self.warnings_date = None

        # Log which user we're running as
        if self.should_monitor_user():
            self.logger.info(f"Monitoring enabled for user: {self.current_user}")
            print(f"[{datetime.now():%H:%M:%S}] Monitoring user: {self.current_user}")
        else:
            self.logger.info(f"User {self.current_user} is EXEMPT from monitoring")
            print(f"[{datetime.now():%H:%M:%S}] User {self.current_user} is EXEMPT - no restrictions will apply")

        # Load previous state if exists
        self.load_state()
        self.warnings_date = usage_period_date(datetime.now(), self.daily.wake_time)

        if start_background_threads:
            self.monitor_thread = threading.Thread(
                target=self.monitor_activity, daemon=True
            )
            self.monitor_thread.start()
        else:
            self.monitor_thread = None

    def should_monitor_user(self):
        """Check if current user should be monitored based on configuration"""
        return should_monitor_user(
            self.current_user, self.monitored_users, self.exempt_users
        )

    def load_state(self):
        """Load saved daily settings and runtime state from JSON files."""
        try:
            self.daily, self.runtime = self.state_store.load()
            bed_label = (
                f"{self.daily.bed_time.hour:02d}:{self.daily.bed_time.minute:02d}"
                if self.daily.bed_time is not None
                else "none"
            )
            effective = effective_daily_allowance_minutes(self.daily, self.runtime)
            self.logger.info(
                "State applied: bed_time=%s wake_time=%02d:%02d daily_allowance=%s "
                "effective_allowance=%s manual_lock=%s accumulated_min=%.1f "
                "extension_sec=%s",
                bed_label,
                self.daily.wake_time.hour,
                self.daily.wake_time.minute,
                self.daily.allowance,
                effective,
                self.runtime.manual_lock_active,
                self.runtime.accumulated_seconds / 60,
                self.runtime.cumulative_extension_seconds,
            )
            print(
                f"[{datetime.now():%H:%M:%S}] Loaded settings from "
                f"{self.state_store.data_directory}"
            )
        except Exception as e:
            self.logger.error("Error loading state: %s", e, exc_info=True)
            print(f"[{datetime.now():%H:%M:%S}] Could not load previous state: {e}")

    def save_state(self):
        """Save daily settings and runtime state to JSON files."""
        try:
            self.state_store.save(self.daily, self.runtime)
            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error("Error saving state: %s", e, exc_info=True)

    def _effective_usage_allowance_minutes(self) -> float | None:
        return effective_daily_allowance_minutes(self.daily, self.runtime)

    def check_if_locked(self) -> bool:
        """True when this session's workstation is locked (OS-specific)."""
        return self.platform.check_session_locked()

    def session_is_active(self) -> bool:
        """True when this session is the active console and not locked."""
        return self.platform.session_is_active()

    def tick_accumulator(self):
        """
        Advance the active-use counter by the seconds elapsed since the last
        active tick. Reset at wake_time each day. Called once per second from
        run_monitor.
        """
        now = datetime.now()
        wake_time = self.daily.wake_time

        if not runtime_state_is_current(self.runtime, wake_time, now):
            self.logger.info(
                "Wake-time rollover (%02d:%02d): resetting daily runtime state "
                "(was %.1f min used, %s extension sec)",
                wake_time.hour,
                wake_time.minute,
                self.runtime.accumulated_seconds / 60,
                self.runtime.cumulative_extension_seconds,
            )
            reset_runtime_for_new_period(self.runtime, now)
            self.last_tick_at = None

        # Never credit usage while a lock window is active (bedtime curfew or
        # manual lock). Accurate session detection already covers this, but a
        # brief detection flicker during curfew must not inflate usage.
        in_lock_window, _ = self.currently_in_lock_window()

        if (
            self.should_monitor_user()
            and self.session_is_active()
            and not in_lock_window
        ):
            if self.last_tick_at is not None:
                delta = (now - self.last_tick_at).total_seconds()
                # Clamp to (0, 60): negative means clock went backwards;
                # >60 means the loop stalled or we resumed from sleep, in
                # which case we don't want to credit the whole gap.
                if 0 < delta < 60:
                    self.runtime.accumulated_seconds += delta
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

    def set_bed_time(self, hour: int, minute: int) -> None:
        """Set the nightly bedtime curfew start."""
        self.daily.bed_time = dtime(hour, minute)

    def clear_bed_time(self) -> None:
        self.daily.bed_time = None

    def set_wake_time(self, hour: int, minute: int) -> None:
        """Set the daily morning unlock time (end of bedtime curfew)."""
        self.daily.wake_time = dtime(hour, minute)
        self.warnings_date = usage_period_date(datetime.now(), self.daily.wake_time)

    def set_daily_allowance(self, minutes: int | None) -> None:
        """Set the default daily screen-time allowance in minutes."""
        self.daily.allowance = minutes

    def extend_time(self, minutes: int) -> None:
        """Add temporary extra allowance for the current usage period."""
        self.runtime.cumulative_extension_seconds += minutes * 60
        self.runtime.manual_lock_active = False

    def clear_extensions(self) -> None:
        self.runtime.cumulative_extension_seconds = 0

    def show_message(self, message, title="PC Time Control"):
        """Display a message to the logged-in user (OS-specific UI)."""
        self.platform.show_message(message, title=title)

    def lock_pc(self):
        """Lock the workstation for this session."""
        try:
            self.is_locked = True
            self.platform.lock_workstation()
        except Exception as e:
            self.logger.error(f"Error locking PC: {e}")
            print(f"[{datetime.now():%H:%M:%S}] Error locking PC: {e}")

    def shutdown_pc(self, seconds=60):
        """Shutdown PC with warning."""
        try:
            self.platform.shutdown(seconds)
            self.logger.info(f"Shutdown initiated ({seconds}s)")
        except Exception as e:
            self.logger.error(f"Error initiating shutdown: {e}")
            print(f"[{datetime.now():%H:%M:%S}] Error shutting down: {e}")

    def cancel_shutdown(self):
        """Cancel pending shutdown."""
        self.platform.cancel_shutdown()

    def get_time_remaining(self):
        """Calculate minutes remaining until lock. Returns None if no allowance set."""
        return minutes_until_lock(
            now=datetime.now(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.runtime.manual_lock_active,
            wake_time=self.daily.wake_time,
        )

    def check_and_send_warnings(self):
        """Check if warnings should be sent and send them"""
        # Clear sent-warning memory at wake_time so the 15/5/1-minute warnings
        # fire again for the next usage period if the agent runs continuously.
        today = usage_period_date(datetime.now(), self.daily.wake_time)
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
        window that runs until wake_time, so a child who signs in after bedtime
        or before wake is still locked out. Usage-allowance enforcement is a
        simple "minutes-used >= allowance" check for the current wake-to-wake day.
        """
        decision = lock_decision(
            now=datetime.now(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.runtime.manual_lock_active,
            wake_time=self.daily.wake_time,
        )
        return decision.should_lock, decision.reason

    def enforcement_lock_state(self) -> tuple[bool, str | None]:
        """Return schedule/limit enforcement without considering manual lock."""
        return enforcement_state(
            now=datetime.now(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            wake_time=self.daily.wake_time,
        )

    def get_access_status(self) -> str:
        """Brief access status for the parent panel."""
        enforcement_active, enforcement_reason = self.enforcement_lock_state()
        return format_access_status(
            manual_lock=self.runtime.manual_lock_active,
            enforcement_active=enforcement_active,
            enforcement_reason=enforcement_reason,
            screen_locked=self.check_if_locked(),
        )

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
        # The shared secret authenticates every protocol v2 frame.  It is
        # loaded lazily so a freshly installed agent reflects a secret added
        # after the process started.
        self._shared_secret = None

    def get_shared_secret(self):
        """Return the configured shared secret, loading and caching it once."""
        if self._shared_secret is None:
            self._shared_secret = shared_secret.load_shared_secret()
        return self._shared_secret

    def get_primary_ip(self):
        """Return the primary IPv4 address, or None while networking is down."""
        return get_primary_ipv4()

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
            if self.pc_control is not None:
                log_connectivity_diagnostics(self.pc_control.platform)
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

                        self.logger.debug(
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
        """Handle communication with a connected client using protocol v2."""
        try:
            while self.running:
                try:
                    body = agent_protocol.read_frame(client_socket)
                except agent_protocol.ConnectionClosedBeforeFrame as e:
                    # A bare TCP probe (e.g. the panel's reachability check)
                    # connects and closes without sending a frame. Benign.
                    self.logger.debug("Client %s closed before sending a frame: %s", client_id, e)
                    break
                except agent_protocol.ProtocolError as e:
                    self.logger.warning("Client %s framing error: %s", client_id, e)
                    break
                self.logger.debug(
                    "Structured request from %s (ID: %s)", client_address, client_id
                )
                secret = self.get_shared_secret()
                if not secret:
                    self.logger.error(
                        "No shared secret configured; cannot authenticate "
                        "client %s. Re-run the installer to set one.",
                        client_id,
                    )
                    break
                response = agent_protocol.handle_request(
                    self.pc_control, body, secret=secret
                )
                try:
                    client_socket.sendall(agent_protocol.encode_frame(response))
                except OSError as e:
                    self.logger.warning(
                        "Client %s send error: %s", client_id, e
                    )
                    break

        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            self.logger.debug("Client %s (ID: %s) disconnected", client_address, client_id)

    def stop_server(self):
        """Stop the server and clean up resources."""
        self.running = False
        self.close_sockets()

    def __del__(self):
        """Destructor to ensure proper cleanup."""
        self.stop_server()

# Main
def main() -> int:
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
    platform = get_default_platform()
    log_connectivity_diagnostics(platform)

    if not check_port_availability(AGENT_PORT):
        logger.error(
            "Port %s already in use — another KidPCMonitor instance is probably "
            "already running. Exiting duplicate startup.",
            AGENT_PORT,
        )
        return 1

    # Create control instance
    control = PCTimeControl(platform=platform)

    # Enforce usage allowance, bedtime, and warnings (separate from the TCP server)
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
        return 1

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
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
