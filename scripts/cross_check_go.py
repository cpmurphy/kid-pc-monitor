#!/usr/bin/env python3
"""Cross-check the Go protocol package against the Python implementation.

Builds ``go/cmd/xcheck`` and runs two real TCP conversations, one in each
direction, so each implementation has to understand frames the other wrote:

  A. Go agent  <->  Python panel   (remote_client.exchange_on_socket)
  B. Python agent (the real dispatcher, fake host)  <->  Go panel

and checks that each side can load the settings/state files the other saved:

  C. Python AgentStateStore  <->  Go state.Store

and, on Windows only, runs the real Go agent against the Python panel:

  D. go/cmd/kid-pc-agent  <->  PanelReverseServer + a discovery endpoint
     (secret store, discovery, reverse session, log format, reconnect; the
     agent gets throwaway data directories and is never asked to lock)

The golden vectors (``go test ./...`` plus ``tests/test_protocol_vectors.py``)
check each function in isolation; this checks the whole session, framing and
all.  Needs a Go toolchain.  Linux/macOS/Windows; no Windows session required.

    python scripts/cross_check_go.py [--go /path/to/go] [--keep DIR]
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime
from datetime import time as dtime
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from kid_pc_monitor import agent_protocol as proto  # noqa: E402
from kid_pc_monitor.agent_state import AgentStateStore, DailySettings, RuntimeState  # noqa: E402
from kid_pc_monitor.pc_time_control import PCTimeControl  # noqa: E402
from kid_pc_monitor.remote_client import exchange_on_socket  # noqa: E402
from kid_pc_monitor.remote_control_server import handle_request  # noqa: E402
from test_pc_time_control import FakeHostPlatform  # noqa: E402

SECRET = "cross-check-secret ✓"
GO_HOSTNAME = "go-kid-pc"
PY_HOSTNAME = "py-kid-pc"
IO_TIMEOUT = 15.0

# Keep in sync with messageText in go/cmd/xcheck/main.go.
MESSAGE_TEXT = 'Dinner 🍝 at "six"\n\tsee C:\\path\\ ünï\n'


class Checks:
    def __init__(self, label: str) -> None:
        self.label = label
        self.failures: list[str] = []
        self.count = 0

    def check(self, name: str, got: Any, want: Any) -> None:
        self.count += 1
        if got == want:
            print(f"  ok    {name}")
        else:
            print(f"  FAIL  {name}\n          got  {got!r}\n          want {want!r}")
            self.failures.append(f"{self.label}: {name}")


def build_xcheck(go: str, out_dir: Path) -> Path:
    exe = out_dir / ("xcheck.exe" if sys.platform == "win32" else "xcheck")
    subprocess.run(
        [go, "build", "-o", str(exe), "./cmd/xcheck"],
        cwd=ROOT / "go",
        check=True,
    )
    return exe


# ---------------------------------------------------------------------------
# A. Go agent <-> Python panel
# ---------------------------------------------------------------------------
def go_agent_session(exe: Path) -> Checks:
    print("A. Go agent <-> Python panel")
    checks = Checks("go-agent")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(IO_TIMEOUT)
    port = listener.getsockname()[1]
    agent = subprocess.Popen(
        [
            str(exe),
            "agent",
            "-connect",
            f"127.0.0.1:{port}",
            "-secret",
            SECRET,
            "-hostname",
            GO_HOSTNAME,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    try:
        sock, _ = listener.accept()
    except TimeoutError:
        agent.kill()
        checks.check("agent connected", False, True)
        return checks
    finally:
        listener.close()

    sock.settimeout(IO_TIMEOUT)

    def ask(action: str, **kwargs: Any) -> proto.Response:
        return exchange_on_socket(sock, action, secret=SECRET, **kwargs)

    def raw(body: str) -> proto.Response:
        sock.sendall(proto.encode_frame(body))
        return proto.parse_response(proto.read_frame(sock), secret=SECRET)

    def req(action: str, **kwargs: Any) -> str:
        return proto.build_request(action, secret=SECRET, **kwargs)

    with sock:
        r = ask("get", var="settings")  # unnamed read: discovery
        checks.check("discovery reports the agent's hostname", r.name, GO_HOSTNAME)
        settings = r.settings or {}
        checks.check("settings: daily_limit", settings.get("daily_limit"), 120)
        checks.check("settings: null survives", settings.get("time_remaining"), None)
        checks.check("settings: bool survives", settings.get("manual_lock"), False)
        checks.check("settings: quoted time", settings.get("bed_time"), "21:00")
        checks.check(
            "settings: same variables as Python's list",
            sorted(settings),
            sorted(proto.VARIABLES),
        )

        checks.check("get name", ask("get", var="name", name=GO_HOSTNAME).result, GO_HOSTNAME)

        sock.sendall(proto.encode_frame(req("list_capabilities")))
        caps = proto.parse(proto.read_frame(sock))
        by_name = {n.name: n for n in caps}
        checks.check(
            "capabilities: actions identical",
            {c.name: c.arg for c in by_name["actions"].children},
            proto.ACTIONS,
        )
        checks.check(
            "capabilities: variables identical",
            {c.name: c.arg for c in by_name["values"].children},
            proto.VARIABLES,
        )

        checks.check("lock", ask("lock").result, "locked")
        checks.check("manual_lock after lock", ask("get", var="manual_lock").result, True)
        checks.check("unlock", ask("unlock").result, "unlocked")
        checks.check("set daily_limit", ask("set", var="daily_limit", val=90).ok, True)
        checks.check("get daily_limit", ask("get", var="daily_limit").result, 90)
        r = ask("set", var="daily_limit", val=99999)
        checks.check("out-of-range limit rejected", (r.ok, r.error_code), (False, "invalid_value"))
        checks.check("set bed_time", ask("set", var="bed_time", val="21:30").ok, True)
        checks.check("get bed_time", ask("get", var="bed_time").result, "21:30")
        checks.check("extend", ask("extend", val=15).ok, True)
        checks.check("cumulative_extension (seconds)", ask("get", var="cumulative_extension").result, 900)
        checks.check("message accepted", ask("message", val=MESSAGE_TEXT).result, "message sent")
        checks.check("message with trailing newline", ask("message", val="hello\n").ok, True)
        r = raw(req("message", val="   ", name=GO_HOSTNAME))
        checks.check("blank message refused", r.error_code, "invalid_value")
        r = raw(req("extend", val=-30, name=GO_HOSTNAME))
        checks.check("negative extension refused", r.error_code, "invalid_value")
        r = raw(req("set", var="bed_time", val="7:5", name=GO_HOSTNAME))
        checks.check("sloppy time refused", r.error_code, "invalid_value")

        r = ask("get_logs", tail=3)
        logs = r.logs
        checks.check("get_logs: truncated", logs.truncated if logs else None, True)
        checks.check("get_logs: three lines", len(logs.lines) if logs else None, 3)
        checks.check(
            "get_logs: escaping survives",
            logs.lines[-1] if logs else None,
            '[2026-05-31 12:00:09] INFO kid_pc_monitor: line 9 "quoted" \\ ünï',
        )
        checks.check("get_logs: path", logs.path if logs else None, r"C:\ProgramData\KidPCMonitor\pc_control.log")
        checks.check("get_logs default is untruncated", ask("get_logs").logs.truncated, False)  # type: ignore[union-attr]

        r = ask("get", var="status", name=GO_HOSTNAME)
        checks.check("get status after unlock", r.result, "UNLOCKED")

        # Rejections must be signed failures the Python client can authenticate.
        now = int(time.time())
        r = raw(proto.build_request("get", secret="wrong", var="name"))
        checks.check("wrong secret", r.error_code, "authentication_failed")
        r = raw(req("get", var="name", timestamp=now - 3600))
        checks.check("stale timestamp", r.error_code, "stale_timestamp")
        r = raw(req("lock", name="some-other-pc"))
        checks.check("frame for another PC", r.error_code, "authentication_failed")
        r = raw(req("lock"))
        checks.check("unnamed write", r.error_code, "authentication_required")
        r = raw(req("get", var="nope", name=GO_HOSTNAME))
        checks.check("unknown variable", r.error_code, "unknown_variable")
        r = raw(req("shutdown", val=-1, name=GO_HOSTNAME))
        checks.check("negative shutdown", r.error_code, "invalid_value")
        r = raw(req("get_logs", tail=5001))
        checks.check("tail over the cap", r.error_code, "invalid_value")
        r = raw("v 2\nid x\naction get")
        checks.check("old protocol version", (r.error_code, r.version), ("unsupported_version", 3))
        r = raw("this is {{ not kdl")
        checks.check("unparseable frame", r.error_code, "invalid_request")
        r = raw("a {" * 5000)
        checks.check("hostile nesting", r.error_code, "invalid_request")
        checks.check("agent still answers afterwards", ask("get", var="name", name=GO_HOSTNAME).ok, True)

    try:
        agent.wait(timeout=IO_TIMEOUT)
    except subprocess.TimeoutExpired:
        agent.kill()
    output = agent.stdout.read() if agent.stdout else ""
    checks.check("agent exited cleanly", agent.returncode, 0)
    try:
        report = json.loads(output)
    except ValueError:
        report = {"unparseable": output}
    checks.check(
        "popup text reached the agent byte for byte",
        report.get("messages"),
        [MESSAGE_TEXT, "hello\n"],
    )
    return checks


# ---------------------------------------------------------------------------
# B. Python agent <-> Go panel
# ---------------------------------------------------------------------------
def python_agent_session(exe: Path) -> Checks:
    print("B. Python agent <-> Go panel")
    checks = Checks("py-agent")
    platform = FakeHostPlatform(hostname=PY_HOSTNAME)
    with tempfile.TemporaryDirectory() as tmp:
        control = PCTimeControl(
            platform=platform, data_directory=Path(tmp), start_background_threads=False
        )
        panel = subprocess.Popen(
            [str(exe), "panel", "-listen", "127.0.0.1:0", "-secret", SECRET],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert panel.stdout is not None
        ready = panel.stdout.readline().split()
        if len(ready) != 2 or ready[0] != "LISTENING":
            panel.kill()
            checks.check("panel listening", ready, "LISTENING <port>")
            return checks

        sock = socket.create_connection(("127.0.0.1", int(ready[1])), timeout=IO_TIMEOUT)
        sock.settimeout(IO_TIMEOUT)
        with sock:
            while True:
                try:
                    body = proto.read_frame(sock)
                except proto.ConnectionClosedBeforeFrame:
                    break  # the panel finished its script
                except (proto.ProtocolError, TimeoutError, OSError) as exc:
                    checks.check("agent read a frame", repr(exc), "a frame")
                    break
                sock.sendall(
                    proto.encode_frame(handle_request(control, body, secret=SECRET))
                )

        stdout_rest = panel.stdout.read()
        stderr = panel.stderr.read() if panel.stderr else ""
        try:
            panel.wait(timeout=IO_TIMEOUT)
        except subprocess.TimeoutExpired:
            panel.kill()

    steps: dict[str, dict[str, Any]] = {}
    for line in stdout_rest.splitlines():
        if line.strip():
            record = json.loads(line)
            steps[record["step"]] = record

    def step(name: str) -> dict[str, Any]:
        return steps.get(name, {"local_error": "step did not run"})

    checks.check("panel exit status", (panel.returncode, stderr.strip()), (0, ""))
    checks.check("script ran to completion", step("done").get("ok"), True)
    checks.check("no step failed locally", [s for s, r in steps.items() if "local_error" in r], [])

    checks.check("discovery learns the hostname", step("discover").get("name"), PY_HOSTNAME)
    checks.check(
        "settings has every variable",
        sorted(step("discover").get("settings") or {}),
        sorted(proto.VARIABLES),
    )
    checks.check("get name", step("get_name").get("result"), PY_HOSTNAME)
    checks.check("list_capabilities", step("list_capabilities").get("ok"), True)
    checks.check("lock", step("lock").get("result"), "locked")
    checks.check("manual_lock after lock", step("get_manual_lock_after_lock").get("result"), True)
    checks.check("unlock", step("unlock").get("result"), "unlocked")
    checks.check("set daily_limit", step("set_daily_limit").get("ok"), True)
    checks.check("get daily_limit", step("get_daily_limit").get("result"), 90)
    checks.check(
        "out-of-range limit", step("set_daily_limit_too_big").get("error_code"), "invalid_value"
    )
    checks.check("set bed_time", step("set_bed_time").get("ok"), True)
    checks.check("extend", step("extend").get("ok"), True)
    checks.check("message accepted", step("message").get("ok"), True)
    checks.check(
        "message text arrived exactly",
        [text for _title, text in platform.messages],
        [MESSAGE_TEXT],
    )
    logs = step("get_logs_tail_3")
    checks.check("get_logs ok", logs.get("ok"), True)
    checks.check("get_logs: at most 3 lines", len((logs.get("logs") or {"lines": []})["lines"]) <= 3, True)
    checks.check("unknown variable", step("get_unknown_variable").get("error_code"), "unknown_variable")
    checks.check("negative shutdown", step("shutdown_negative").get("error_code"), "invalid_value")
    checks.check("wrong secret", step("wrong_secret").get("error_code"), "authentication_failed")
    checks.check("stale timestamp", step("stale_timestamp").get("error_code"), "stale_timestamp")
    checks.check("frame for another PC", step("foreign_name").get("error_code"), "authentication_failed")
    checks.check("unnamed write", step("unnamed_write").get("error_code"), "authentication_required")
    checks.check(
        "old protocol version", step("old_protocol_version").get("error_code"), "unsupported_version"
    )
    checks.check("unparseable frame", step("not_kdl").get("error_code"), "invalid_request")
    checks.check("hostile nesting", step("hostile_nesting").get("error_code"), "invalid_request")
    return checks


# ---------------------------------------------------------------------------
# C. State files: each side loads what the other wrote
# ---------------------------------------------------------------------------
STATE_NOW = "2026-05-17T10:00:00"
STATE_SAMPLE = {
    "wake_time": "06:30",
    "bed_time": "21:15",
    "allowance": 100,
    "timestamp": STATE_NOW,
    "accumulated_seconds": 1234.568,  # rounded to 3 places on save
    "manual_lock_active": True,
    "cumulative_extension_seconds": 300,
}


def state_files_session(exe: Path) -> Checks:
    print("C. State files: Python <-> Go")
    checks = Checks("state-files")
    now = datetime.fromisoformat(STATE_NOW)

    def python_store(directory: Path) -> AgentStateStore:
        return AgentStateStore(
            directory, current_user="kid", clock=lambda: now, program_data_dir=None
        )

    def dump(directory: Path) -> dict[str, Any]:
        proc = subprocess.run(
            [str(exe), "state-dump", "-dir", str(directory), "-now", STATE_NOW],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        checks.check("go state-dump exits cleanly", (proc.returncode, proc.stderr.strip()), (0, ""))
        return json.loads(proc.stdout) if proc.stdout.strip() else {}

    with tempfile.TemporaryDirectory() as tmp:
        py_dir, go_dir = Path(tmp) / "py", Path(tmp) / "go"

        # Python writes, Go reads.
        python_store(py_dir).save(
            DailySettings(bed_time=dtime(21, 15), wake_time=dtime(6, 30), allowance=100),
            RuntimeState(
                timestamp=now,
                accumulated_seconds=1234.56789,
                manual_lock_active=True,
                cumulative_extension_seconds=300,
            ),
        )
        checks.check("Go loads what Python saved", dump(py_dir), STATE_SAMPLE)

        # Go writes, Python reads.
        subprocess.run(
            [str(exe), "state-write", "-dir", str(go_dir), "-now", STATE_NOW], check=True
        )
        daily, runtime = python_store(go_dir).load()
        checks.check(
            "Python loads what Go saved",
            {
                "wake_time": f"{daily.wake_time:%H:%M}",
                "bed_time": f"{daily.bed_time:%H:%M}" if daily.bed_time else None,
                "allowance": daily.allowance,
                "timestamp": runtime.timestamp.isoformat(),
                "accumulated_seconds": runtime.accumulated_seconds,
                "manual_lock_active": runtime.manual_lock_active,
                "cumulative_extension_seconds": runtime.cumulative_extension_seconds,
            },
            STATE_SAMPLE,
        )

        # A Go load of an empty directory writes the same defaults Python does.
        go_empty, py_empty = Path(tmp) / "go-empty", Path(tmp) / "py-empty"
        dump(go_empty)
        python_store(py_empty).load()
        checks.check(
            "default files match",
            {
                name: json.loads((go_empty / name).read_text())
                for name in ("daily_settings.json", "state.json")
            },
            {
                name: json.loads((py_empty / name).read_text())
                for name in ("daily_settings.json", "state.json")
            },
        )
    return checks


# ---------------------------------------------------------------------------
# D. The real Go agent (kid-pc-agent) <-> Python panel reverse server
# ---------------------------------------------------------------------------
def real_agent_session(_exe: Path, go: str, out_dir: Path) -> Checks:
    """Discovery, secret store, reverse session, logging and reconnect.

    Windows only. The agent runs against throwaway LOCALAPPDATA, ProgramData
    and secrets directories with no limits set, and is only sent reads and a
    daily_limit change, so it never locks, pops up or shuts down this PC.
    """
    import getpass
    import os
    import platform as pyplatform
    import re
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from kid_pc_monitor import secrets_store
    from kid_pc_monitor.panel_reverse_server import PanelReverseServer

    print("D. Real Go agent <-> Python panel reverse server")
    checks = Checks("real-agent")
    agent_exe = out_dir / "kid-pc-agent.exe"
    subprocess.run(
        [go, "build", "-o", str(agent_exe), "./cmd/kid-pc-agent"], cwd=ROOT / "go", check=True
    )

    work = Path(tempfile.mkdtemp(prefix="kpm-real-agent-"))
    local_appdata = work / "local"
    program_data = work / "programdata"
    secrets_dir = work / "secrets"
    for d in (local_appdata, program_data, secrets_dir):
        d.mkdir()
    saved_env = {k: os.environ.get(k) for k in ("KID_PC_MONITOR_SECRETS_DIR",)}
    os.environ["KID_PC_MONITOR_SECRETS_DIR"] = str(secrets_dir)
    secrets_store.save_secret("panel-agent-shared-secret", SECRET)

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    reverse_port = probe.getsockname()[1]
    probe.close()
    server = PanelReverseServer(host="127.0.0.1", port=reverse_port, status_refresh_sec=3600)
    server.start()

    class Discover(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            body = json.dumps(
                {"service": "kid-pc-monitor-panel", "version": 1, "reverse_port": reverse_port}
            ).encode()
            self.send_response(200 if self.path == "/agent/v1/discover" else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Discover)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    panel_url = f"http://127.0.0.1:{http.server_address[1]}"

    env = {
        **os.environ,
        "LOCALAPPDATA": str(local_appdata),
        "ProgramData": str(program_data),
        "KID_PC_MONITOR_PANEL_URL": panel_url,
        "KID_PC_MONITOR_LOG_LEVEL": "DEBUG",
    }
    agent = subprocess.Popen(
        [str(agent_exe)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def wait_session(previous: Any = None, timeout: float = 20.0) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s = server.session_for_ip("127.0.0.1")
            if s is not None and s is not previous:
                return s
            time.sleep(0.1)
        return None

    data_dir = local_appdata / "KidPCMonitor"
    try:
        session = wait_session()
        checks.check("agent discovered the panel and connected", session is not None, True)
        if session is None:
            return checks
        checks.check("hostname matches platform.node()", session.hostname, pyplatform.node())
        checks.check(
            "current_user matches getpass.getuser()",
            session.pc_info.get("current_user"),
            getpass.getuser(),
        )
        checks.check("fresh state: no daily limit", session.pc_info.get("daily_limit"), None)
        checks.check("fresh state: not manually locked", session.pc_info.get("manual_lock"), False)
        checks.check(
            "panel URL cached",
            (data_dir / "panel_url.txt").read_text(encoding="utf-8"),
            panel_url + "\n",
        )

        r = session.submit(action="set", var="daily_limit", val=600)
        checks.check("set daily_limit", r.ok, True)
        r = session.submit(action="get", var="daily_limit")
        checks.check("get daily_limit", r.result, 600)
        daily = json.loads((data_dir / "daily_settings.json").read_text(encoding="utf-8"))
        checks.check("daily_settings.json written", daily.get("allowance"), 600)

        logs = server.get_logs("127.0.0.1", tail=200)
        line_re = re.compile(
            r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] (DEBUG|INFO|WARNING|ERROR|CRITICAL) \S+: "
        )
        checks.check(
            "every log line is in Python's format",
            [line for line in logs.lines if not line_re.match(line)],
            [],
        )
        checks.check("log path", logs.path, str(data_dir / "pc_control.log"))
        for needle in (
            "INFO kid_pc_monitor: Agent process starting",
            "INFO kid_pc_monitor: Connectivity check: pid=",
            "INFO AgentReverseClient: Connected reverse session to panel 127.0.0.1:",
            "INFO kid_pc_monitor: Agent running (enforcement + reverse TCP)",
        ):
            checks.check(f"log has {needle!r}", any(needle in line for line in logs.lines), True)

        # The panel drops the session; the agent must come back on its own.
        session.close()
        again = wait_session(previous=session, timeout=20.0)
        checks.check("agent reconnected after the panel hung up", again is not None, True)
        if again is not None:
            r = again.submit(action="get", var="daily_limit")
            checks.check("state survives the reconnect", r.result, 600)
            tail = server.get_logs("127.0.0.1", tail=50).lines
            checks.check(
                "hang-up logged",
                any("AgentReverseClient: Panel closed reverse connection" in line for line in tail),
                True,
            )
    finally:
        agent.kill()
        agent.wait(timeout=10)
        server.stop()
        http.shutdown()
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(work, ignore_errors=True)
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"), help="path to the go tool")
    parser.add_argument("--keep", help="build xcheck into this directory and keep it")
    args = parser.parse_args()
    if not args.go:
        print("cross_check_go: the Go toolchain is not installed (or pass --go)", file=sys.stderr)
        return 2

    sessions: list[Callable[[Path], Checks]] = [
        go_agent_session,
        python_agent_session,
        state_files_session,
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(args.keep) if args.keep else Path(tmp)
        out_dir.mkdir(parents=True, exist_ok=True)
        exe = build_xcheck(args.go, out_dir)
        if sys.platform == "win32":

            def real_agent(exe: Path) -> Checks:
                return real_agent_session(exe, args.go, out_dir)

            real_agent.__name__ = "real_agent_session"
            sessions.append(real_agent)

        results: list[Checks] = []
        for session in sessions:
            try:
                results.append(session(exe))
            except Exception:  # a crash mid-session is a failed check, not a skipped one
                traceback.print_exc()
                crashed = Checks(session.__name__)
                crashed.count = 1
                crashed.failures.append(f"{session.__name__}: raised an exception")
                results.append(crashed)

    total = sum(r.count for r in results)
    failures = [f for r in results for f in r.failures]
    if failures:
        print(f"\n{len(failures)} of {total} checks FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\nall {total} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
