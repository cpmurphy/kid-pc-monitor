#!/usr/bin/env python3
"""Cross-check the Go protocol package against the Python implementation.

Builds ``go/cmd/xcheck`` and runs two real TCP conversations, one in each
direction, so each implementation has to understand frames the other wrote:

  A. Go agent  <->  Python panel   (remote_client.exchange_on_socket)
  B. Python agent (the real dispatcher, fake host)  <->  Go panel

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
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from kid_pc_monitor import agent_protocol as proto  # noqa: E402
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
        checks.check("message round-trips exactly", ask("message", val=MESSAGE_TEXT).result, MESSAGE_TEXT)
        checks.check("message with trailing newline", ask("message", val="hello\n").result, "hello\n")

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
    checks.check("agent exited cleanly", (agent.returncode, output.strip()), (0, ""))
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"), help="path to the go tool")
    parser.add_argument("--keep", help="build xcheck into this directory and keep it")
    args = parser.parse_args()
    if not args.go:
        print("cross_check_go: the Go toolchain is not installed (or pass --go)", file=sys.stderr)
        return 2

    sessions: list[Callable[[Path], Checks]] = [go_agent_session, python_agent_session]
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(args.keep) if args.keep else Path(tmp)
        out_dir.mkdir(parents=True, exist_ok=True)
        exe = build_xcheck(args.go, out_dir)

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
