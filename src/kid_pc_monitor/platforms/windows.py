"""Windows implementation of HostPlatform."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import tkinter as tk
from ctypes import wintypes
from tkinter import messagebox

import getpass

from kid_pc_monitor.host_platform import HostPlatform
from kid_pc_monitor.network import get_primary_ipv4

# Must match scripts/install.py FIREWALL_RULE_DISPLAY_NAME
_FIREWALL_RULE_DISPLAY_NAME = "Kid PC Monitor Agent (TCP 9999)"
_INVALID_HANDLE_VALUE = ctypes.c_size_t(-1).value
_TH32CS_SNAPPROCESS = 0x00000002
_MAX_PATH = 260


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * _MAX_PATH),
    ]


def _subprocess_creationflags() -> int:
    if sys.platform == "win32":
        return 0x08000000  # CREATE_NO_WINDOW
    return 0


def _run_powershell_json(script: str) -> dict | list | None:
    """Run a PowerShell snippet that prints a single JSON object; return dict or None."""
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
            creationflags=_subprocess_creationflags(),
        ).strip()
        if not out:
            return None
        return json.loads(out)
    except (subprocess.SubprocessError, json.JSONDecodeError, ValueError) as exc:
        logging.getLogger("kid_pc_monitor").debug("PowerShell diagnostic failed: %s", exc)
        return None


def _current_session_id() -> int | None:
    kernel32 = ctypes.windll.kernel32
    sid = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(
        kernel32.GetCurrentProcessId(), ctypes.byref(sid)
    ):
        return None
    return sid.value


def _process_exists_in_session(image_name: str, session_id: int | None) -> bool:
    """Return True when image_name is running in session_id (or any session if None)."""
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot in (0, _INVALID_HANDLE_VALUE):
        return False

    target = image_name.lower()
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return False
        while True:
            if entry.szExeFile.lower() == target:
                if session_id is None:
                    return True
                pid_sid = wintypes.DWORD()
                if kernel32.ProcessIdToSessionId(
                    entry.th32ProcessID, ctypes.byref(pid_sid)
                ) and pid_sid.value == session_id:
                    return True
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return False


class WindowsHostPlatform(HostPlatform):
    """Windows session lock, shutdown, messaging, and firewall diagnostics."""

    def check_session_locked(self) -> bool:
        """
        True if LogonUI.exe is running in this session.

        Filtering by session avoids false LOCKED when another user's session
        is locked under fast user switching. Uses Toolhelp APIs so the agent
        does not spawn a visible console every monitoring tick.
        """
        try:
            return _process_exists_in_session("LogonUI.exe", _current_session_id())
        except Exception as exc:
            logging.getLogger("PCTimeControl").error(
                "Error checking lock state (LogonUI): %s", exc, exc_info=True
            )
            return False

    def session_is_active(self) -> bool:
        """True if our session is the active console session and not locked."""
        try:
            kernel32 = ctypes.windll.kernel32
            our_sid = ctypes.c_ulong()
            ok = kernel32.ProcessIdToSessionId(
                kernel32.GetCurrentProcessId(), ctypes.byref(our_sid)
            )
            if not ok:
                return not self.check_session_locked()
            active_sid = kernel32.WTSGetActiveConsoleSessionId()
            if active_sid == 0xFFFFFFFF or active_sid != our_sid.value:
                return False
            return not self.check_session_locked()
        except Exception as exc:
            logging.getLogger("PCTimeControl").error(
                "Error checking session active state: %s", exc, exc_info=True
            )
            return not self.check_session_locked()

    def lock_workstation(self) -> None:
        ctypes.windll.user32.LockWorkStation()

    def shutdown(self, seconds: int = 60) -> None:
        os.system(
            f'shutdown /s /t {seconds} /c "Computer will shutdown in {seconds} seconds"'
        )

    def cancel_shutdown(self) -> None:
        os.system("shutdown /a")

    def show_message(self, message: str, title: str = "PC Time Control") -> None:
        def display() -> None:
            root = None
            try:
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                root.after(60000, root.destroy)
                messagebox.showwarning(title, message)
            except Exception as exc:
                logging.getLogger("PCTimeControl").error("Error showing message: %s", exc)
            finally:
                if root:
                    try:
                        root.quit()
                        root.destroy()
                    except Exception:
                        pass

        threading.Thread(target=display, daemon=True).start()

    def get_hostname(self) -> str:
        import platform

        return platform.node()

    def log_connectivity_diagnostics(
        self,
        logger: logging.Logger,
        *,
        agent_port: int,
        log_file: str,
        log_level_name: str,
        python_executable: str,
    ) -> None:
        primary_ip = get_primary_ipv4()

        logger.info(
            "Connectivity check: pid=%s user=%s primary_ip=%s python=%s log=%s level=%s",
            os.getpid(),
            getpass.getuser(),
            primary_ip or "none",
            python_executable,
            log_file,
            log_level_name,
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
                    entry.get("InterfaceAlias", "?"),
                    entry.get("IPv4Connectivity", "?"),
                    entry.get("NetworkCategory", "?"),
                )

            def _is_public(category) -> bool:
                if category in (0, "0"):
                    return True
                return str(category).lower() == "public"

            on_public = any(_is_public(p.get("NetworkCategory")) for p in profiles)
            if on_public:
                logger.warning(
                    "At least one interface is Public. The installer "
                    "firewall rule allows inbound TCP %s only on Private/Domain "
                    "unless you chose to include Public. Remote scans and pc_cli "
                    "will fail until the network is Private or the rule includes Public.",
                    agent_port,
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
        elif not rule.get("found"):
            logger.warning(
                "No firewall rule named %r — inbound TCP 9999 may be blocked. "
                "Re-run scripts/install.py as administrator.",
                _FIREWALL_RULE_DISPLAY_NAME,
            )
        else:
            profile_mask = int(rule.get("profile") or 0)
            profile_names = []
            if profile_mask & 1:
                profile_names.append("Domain")
            if profile_mask & 2:
                profile_names.append("Private")
            if profile_mask & 4:
                profile_names.append("Public")
            logger.info(
                "Firewall rule: enabled=%s profiles=%s (%s) program=%s localPort=%s",
                rule.get("enabled"),
                profile_mask,
                ",".join(profile_names) or "none",
                rule.get("program"),
                rule.get("localPort"),
            )
            if on_public and not (profile_mask & 4):
                logger.warning(
                    "Network is Public but the firewall rule does not include the "
                    "Public profile — LAN clients cannot reach TCP %s. Set the home "
                    "network to Private in Windows Settings, or re-run scripts/install.py "
                    "and allow Public networks.",
                    agent_port,
                )
            program = rule.get("program") or ""
            if program and os.path.normcase(python_executable) != os.path.normcase(program):
                logger.warning(
                    "Firewall rule program %r does not match this process %r — "
                    "inbound connections may be blocked.",
                    program,
                    python_executable,
                )
