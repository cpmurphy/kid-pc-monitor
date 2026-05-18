import os
import sys
import time
import datetime
import ctypes
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, time as dtime
import subprocess
from ctypes import wintypes
import getpass
import json

import logging
from pathlib import Path

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

def _configure_logging():
    """Append to the per-user log (do not truncate — empty logs make debugging hard)."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    ))
    root.addHandler(handler)

_configure_logging()
logger = logging.getLogger('kid_pc_monitor')

class PCTimeControl:
    def __init__(self):
        self.lock_times = []
        self.usage_limit = None
        self.manual_lock_active = False
        self.start_time = datetime.now()
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
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)

                # Restore lock times
                if 'lock_times' in state:
                    self.lock_times = [dtime(*map(int, t.split(':'))) for t in state['lock_times']]

                # Restore usage limit
                if 'usage_limit' in state:
                    self.usage_limit = state['usage_limit']

                # Restore persistent manual lock requested by the parent.
                self.manual_lock_active = bool(state.get('manual_lock_active', False))

                # Restore start time (for usage tracking)
                if 'start_time' in state:
                    saved_start_time = datetime.fromisoformat(state['start_time'])
                    current_date = datetime.now().date()
                    saved_date = saved_start_time.date()

                    # If start_time is from a previous day, reset it to today
                    if saved_date < current_date:
                        self.start_time = datetime.now()
                        self.logger.info(f"Start time was from {saved_date}, reset to today")
                        print(f"[{datetime.now():%H:%M:%S}] Usage timer reset for new day")
                    else:
                        self.start_time = saved_start_time

                self.logger.info(f"State loaded: {len(self.lock_times)} lock times, usage limit: {self.usage_limit}")
                print(f"[{datetime.now():%H:%M:%S}] Loaded previous settings from {self.state_file}")
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
            print(f"[{datetime.now():%H:%M:%S}] Could not load previous state: {e}")

    def save_state(self):
        """Save current state to JSON file"""
        try:
            state = {
                'lock_times': [f"{lt.hour:02d}:{lt.minute:02d}" for lt in self.lock_times],
                'usage_limit': self.usage_limit,
                'manual_lock_active': self.manual_lock_active,
                'start_time': self.start_time.isoformat(),
                'current_user': self.current_user
            }

            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)

            self.logger.info("State saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")

    def check_if_locked(self):
        """
        Returns True if LogonUI.exe is present (screen locked),
        False otherwise.
        """
        try:
            out = subprocess.check_output(
                'tasklist /FI "IMAGENAME eq LogonUI.exe" /NH',
                shell=True,
                text=True
            )
            locked = "LogonUI.exe" in out
            # print(f"[{datetime.now():%H:%M:%S}] LogonUI.exe running? {locked}")
            return locked
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}] Error checking LogonUI: {e}")
            # fallback to whatever you had before (or assume unlocked)
            return False

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
            start_time=self.start_time,
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

        if time_remaining is None:
            return

        # Check each warning interval
        for warning_mins in self.warning_intervals:
            warning_key = f"{warning_mins}min"

            # If we're within the warning window and haven't sent this warning yet
            if time_remaining <= warning_mins and warning_key not in self.warnings_sent:
                self.warnings_sent.add(warning_key)

                if warning_mins == 1:
                    msg = "⚠️ Computer will lock in 1 minute!"
                else:
                    msg = f"⚠️ Computer will lock in {warning_mins} minutes!"

                self.show_message(msg, "Warning")
                self.logger.info(f"Warning sent: {warning_mins} minutes remaining")
                print(f"[{datetime.now():%H:%M:%S}] Warning: {warning_mins} minutes until lock")

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
            start_time=self.start_time,
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
        self.logger = logging.getLogger('RemoteControlServer')

    def start_server(self, pc_control):
        """Start the remote control server."""
        self.pc_control = pc_control
        self.running = True
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(5)  # Allow periodic checks for self.running
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            self.logger.info(f"Server started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_socket.settimeout(self.timeout)
                    
                    client_id = self.client_id_counter
                    self.client_id_counter += 1
                    
                    self.logger.info(f"New connection from {client_address} (ID: {client_id})")
                    
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
                    continue  # Normal timeout for checking self.running
                except Exception as e:
                    self.logger.error(f"Accept error: {e}")
                    break
                
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.stop_server()
            self.logger.info("Server stopped")

    def handle_client(self, client_socket, client_address, client_id):
        """Handle communication with a connected client."""
        try:
            while self.running:
                try:
                    data = client_socket.recv(1024).decode().strip()
                    if not data:
                        break  # Client disconnected
                        
                    self.logger.info(f"Received from {client_address} (ID: {client_id}): {data}")
                    response = self.process_command(data)
                    
                    if response is not None:
                        client_socket.sendall(response.encode())
                        
                except socket.timeout:
                    # Send keepalive
                    client_socket.sendall(b"ALIVE")
                    continue
                except Exception as e:
                    self.logger.error(f"Client {client_id} error: {e}")
                    break
                    
        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            self.logger.info(f"Client {client_address} (ID: {client_id}) disconnected")

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
                    self.logger.info(f"Status changed to: {'LOCKED' if actual_locked else 'UNLOCKED'}")
                return "LOCKED" if actual_locked else "UNLOCKED"
                
            elif command.startswith("MESSAGE:"):
                msg = command.split(":", 1)[1]
                self.pc_control.show_message(msg)
                return "Message sent"
                
            elif command.startswith("SET_LIMIT:"):
                try:
                    minutes = int(command.split(":", 1)[1])
                    self.pc_control.set_usage_limit(minutes)
                    self.pc_control.start_time = datetime.now()  # Reset start time when setting new limit
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
                    "CLEAR_ALL - Clear all limits, scheduled locks, and manual lock"
                )
                
            else:
                return "Unknown command (try HELP)"
                
        except Exception as e:
            self.logger.error(f"Command processing error: {e}")
            return f"Error processing command: {e}"

    def stop_server(self):
        """Stop the server and clean up resources."""
        self.running = False
        
        # Close all client connections
        for client_id, client_info in list(self.clients.items()):
            try:
                client_info['socket'].close()
            except Exception as e:
                self.logger.error(f"Error closing client socket {client_id}: {e}")
            del self.clients[client_id]

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing server socket: {e}")
            self.server_socket = None

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

    if not check_port_availability(9999):
        logger.error(
            "Port 9999 already in use — another KidPCMonitor instance is probably "
            "already running. Exiting duplicate startup."
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
    
    # Verify server started
    time.sleep(1)  # Give server time to start
    if not remote.running:
        logger.error("Remote control server failed to start on port 9999")
        control.show_message(
            "Failed to start network server!\n"
            "Check firewall settings and try again.",
            "Server Error"
        )
        sys.exit(1)

    logger.info("Agent running (enforcement loop + TCP server on port 9999)")
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
