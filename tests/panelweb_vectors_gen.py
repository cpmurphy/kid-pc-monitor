"""Generate the golden web-panel HTTP vectors shared by Python and Go.

Each scenario seeds a fresh ``panel.db`` through the real Python stores (at
fixed instants, as in ``panelstore_vectors_gen.py``), optionally writes an
auth file, plugs in a fake reverse server with canned agent sessions, and
then drives the Flask app with its test client (keeping cookies between
requests) at a fixed time in a fixed timezone. For every request it records
the status, the headers that matter, and the body: parsed JSON, a normalized
HTML string, or the SHA-256 of a static file. The result is written to
``testdata/panelweb/vectors.json``.

``go/panel/web`` replays every scenario against its own handler and must
produce the same responses. ``tests/test_panelweb_vectors.py`` fails when the
file is stale.

This script also keeps ``go/panel/web/static`` (the Go panel's embedded copy
of ``src/kid_pc_monitor/static``) in sync; ``--check`` fails if it differs.

    python tests/panelweb_vectors_gen.py          # rewrite vectors and static copy
    python tests/panelweb_vectors_gen.py --check  # exit 1 if either is stale

The Allow header is recorded as a sorted method list (werkzeug's order follows
Python's per-process hash seed).

HTML normalization (implemented identically in Go): the CSRF token is masked,
numeric character references are decoded, runs of ASCII whitespace become one
space, whitespace between tags is dropped, and the result is trimmed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from werkzeug.security import _hash_internal  # noqa: E402

from kid_pc_monitor import panel_clock, panel_db  # noqa: E402
from kid_pc_monitor import web_panel as wp  # noqa: E402
from kid_pc_monitor.remote_client import action_request_fields  # noqa: E402
from panelstore_vectors_gen import pc, run_op  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "panelweb" / "vectors.json"
STATIC_SRC = ROOT / "src" / "kid_pc_monitor" / "static"
STATIC_GO = ROOT / "go" / "panel" / "web" / "static"

TZ = timezone(timedelta(hours=-5))
NOW = "2026-06-05T15:00:00-05:00"
PASSWORD = "supersecret1"
AUTH_RECORD = {
    "secret_key": "s" * 32,
    # Cheap scrypt parameters keep the vectors fast; any werkzeug hash works.
    "password_hash": "scrypt:1024:1:1$abcdefghijklmnop$"
    + _hash_internal("scrypt:1024:1:1", "abcdefghijklmnop", PASSWORD)[0],
}

A, B, C, D, E, F = (
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.20",
    "192.168.1.30",
)
G = "192.168.1.21"

KID_SETTINGS: dict[str, Any] = {
    "name": "KID-PC",
    "status": "UNLOCKED",
    "current_user": "kid",
    "daily_limit": 120,
    "bed_time": "21:00",
    "wake_time": "07:00",
    "cumulative_extension": 900,
    "accumulated_seconds": 5400,
    "time_remaining": 45,
    "manual_lock": True,
    "enforcement_active": False,
    "enforcement_reason": None,
    "access_status": "Locked — manual lock",
}


def step(at: str, op: str, **args: Any) -> dict[str, Any]:
    return {"at": at, "op": op, "args": args}


SEED: list[dict[str, Any]] = [
    # KID-PC: live, usage over several days.
    step("2026-06-03T18:00:00-05:00", "save_snapshot", pc_info=pc(ip=A, accumulated_seconds=7200)),
    step(
        "2026-06-04T20:00:00-05:00",
        "save_snapshot",
        pc_info=pc(
            ip=A, accumulated_seconds=3000, cumulative_extension_seconds=600, daily_limit=None
        ),
    ),
    step("2026-06-05T14:50:00-05:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
    step(
        "2026-06-05T14:50:00-05:00",
        "save_poll_snapshot",
        pc_info=pc(ip=A, accumulated_seconds=5400, time_remaining="45 minutes"),
    ),
    step("2026-06-05T14:50:00-05:00", "save_snapshot", pc_info=pc(ip=A, accumulated_seconds=5400)),
    # LAPTOP: was online this morning, now gone.
    step(
        "2026-06-05T09:00:00-05:00",
        "record_poll_inspect",
        ip=B,
        pc_info=pc(ip=B, hostname="LAPTOP", current_user="sib", daily_limit=60.0),
    ),
    step(
        "2026-06-05T09:00:00-05:00",
        "save_snapshot",
        # Over its 60-minute limit: the capped "over" meter.
        pc_info=pc(
            ip=B,
            hostname="LAPTOP",
            current_user="sib",
            daily_limit=60.0,
            effective_limit_minutes=60.0,
            accumulated_seconds=3800,
        ),
    ),
    step(
        "2026-06-05T10:00:00-05:00",
        "record_poll_inspect",
        ip=B,
        pc_info={"hostname": "LAPTOP", "ip": B, "reachable": False},
    ),
    # DESK: answering, but the panel cannot control it.
    step(
        "2026-06-05T14:00:00-05:00",
        "record_poll_inspect",
        ip=C,
        pc_info={
            "hostname": "DESK",
            "ip": C,
            "reachable": False,
            "connection_error": "Authentication failed — the shared secret on this panel may not match the kid PC.",
        },
    ),
    # Reverse-session callbacks (web_panel._record_reverse_pc_info / _disconnect).
    step(
        "2026-06-05T13:00:00-05:00",
        "reverse_status",
        hostname="TABLET",
        ip=F,
        settings={
            "name": "TABLET",
            "status": "UNLOCKED",
            "current_user": None,
            "wake_time": "07:00",
        },
    ),
    step("2026-06-05T13:30:00-05:00", "reverse_disconnect", hostname="TABLET", ip=F),
    step(
        "2026-06-05T14:55:00-05:00",
        "reverse_status",
        hostname="KID-PC",
        ip=A,
        settings=KID_SETTINGS,
    ),
    # A PC known only by IP, locked, no snapshot.
    step(
        "2026-06-05T14:30:00-05:00",
        "record_poll_inspect",
        ip=D,
        pc_info={"hostname": f"PC at {D}", "status": "LOCKED", "locked": True, "reachable": True},
    ),
]

SESSIONS: dict[str, dict[str, Any]] = {
    G: {
        "hostname": "NEARPC",
        # ~86.7% of the allowance: the "near" meter.
        "settings": {**KID_SETTINGS, "name": "NEARPC", "accumulated_seconds": 7020},
        "logs": [],
        "truncated": False,
    },
    A: {
        "hostname": "KID-PC",
        "settings": KID_SETTINGS,
        "logs": ["2026-06-05 14:00:00 INFO Monitoring kid", "<b>not html</b> & more"],
        "truncated": True,
    },
    E: {
        "hostname": "OLDAGENT",
        # 82% of the 135-minute allowance: below the "near" mark.
        "settings": {
            **KID_SETTINGS,
            "name": "OLDAGENT",
            "manual_lock": False,
            "access_status": None,
            "accumulated_seconds": 6642,
        },
        "logs_error": "unknown_action: unknown action: 'get_logs'",
    },
}


def req(method: str, path: str, **kw: Any) -> dict[str, Any]:
    return {"method": method, "path": path, **kw}


OPEN_REQUESTS: list[dict[str, Any]] = [
    req("GET", "/"),
    req("GET", "/agent/v1/discover"),
    req("GET", "/control/KID-PC"),
    req("GET", "/control/kid-pc"),
    req("GET", f"/control/{A}"),
    req("GET", "/control/LAPTOP"),
    req("GET", f"/control/{C}"),
    req("GET", f"/control/{D}"),
    req("GET", f"/control/{E}"),
    req("GET", "/control/TABLET"),
    req("GET", f"/control/{G}/stats"),
    req("GET", f"/logs/{G}"),
    req("GET", "/control/NOPE"),
    req("GET", "/control/10.9.9.9"),
    req("GET", "/control/KID-PC/poll-meta"),
    req("GET", f"/control/{E}/poll-meta"),
    req("GET", "/control/NOPE/poll-meta"),
    req("GET", "/control/KID-PC/stats"),
    req("GET", "/control/KID-PC/stats?source=poll"),
    req("GET", "/control/LAPTOP/stats"),
    req("GET", "/control/LAPTOP/stats?source=poll"),
    req("GET", f"/control/{C}/stats?source=poll"),
    req("GET", "/control/NOPE/stats"),
    req("GET", f"/logs/{A}"),
    req("GET", f"/logs/{B}"),
    req("GET", f"/logs/{E}"),
    req("GET", "/logs/10.9.9.9"),
    req("GET", f"/daily_settings/{A}"),
    req("GET", f"/daily_settings/{B}"),
    req("GET", f"/daily_settings/{C}"),
    req("GET", "/"),
    req("GET", "/daily_settings/NOPE"),
    req("GET", "/"),
    req("GET", "/usage/kid"),
    req("GET", "/usage/sib"),
    req("GET", "/usage/nobody"),
    req("GET", "/usage/a/b c"),
    req("POST", "/action", json={"ip": A, "action": "lock"}),
    req("POST", "/action", json={"ip": A, "action": "lock"}, csrf="header"),
    req("POST", "/action", json={"ip": A, "action": "extend_time", "minutes": 30}, csrf="header"),
    req("POST", "/action", json={"ip": A, "action": "extend_time", "minutes": "x"}, csrf="header"),
    req(
        "POST", "/action", json={"ip": A, "action": "set_daily_limit", "minutes": ""}, csrf="header"
    ),
    req("POST", "/action", json={"ip": "10.9.9.9", "action": "lock"}, csrf="header"),
    req("POST", "/action", json={"action": "lock"}, csrf="header"),
    req("POST", "/action", json={"ip": A, "action": ""}, csrf="header"),
    req("POST", "/action", form={"ip": A, "action": "lock"}, csrf="form"),
    req("POST", "/action", json={"ip": A, "action": "lock"}, headers={"X-CSRF-Token": "wrong"}),
    req("GET", "/action"),
    req("GET", "/nonexistent"),
    req("POST", "/nonexistent"),
    req("POST", "/control/KID-PC", csrf="form"),
    req("GET", "/control/KID-PC/"),
    req("GET", "/static/css/panel.css"),
    req("GET", "/static/js/core.js"),
    req("GET", "/static/nope.css"),
    req("GET", "/login"),
    req("GET", "/logout"),
    req("GET", "/set-password"),
    req(
        "POST",
        "/set-password",
        form={"password": "short", "password_confirm": "short"},
        csrf="form",
    ),
    req(
        "POST",
        "/set-password",
        form={"password": "longenough1", "password_confirm": "different1"},
        csrf="form",
    ),
    req(
        "POST",
        "/set-password",
        form={"password": "longenough1", "password_confirm": "longenough1"},
        csrf="form",
    ),
    req("GET", "/"),
    req("GET", "/control/KID-PC"),
]

PROTECTED_REQUESTS: list[dict[str, Any]] = [
    req("GET", "/"),
    req("GET", "/control/KID-PC"),
    req("GET", "/usage/a b"),
    req("GET", "/agent/v1/discover"),
    req("GET", "/set-password"),
    req("GET", "/login?next=/control/KID-PC"),
    req("GET", "/login?next=//evil.example/"),
    req("POST", "/login", form={"password": "wrong", "next": "/control/KID-PC"}, csrf="form"),
    req("POST", "/login", form={"password": PASSWORD, "next": "/\\evil.example/"}, csrf="form"),
    req("GET", "/logout"),
    req("GET", "/login?next=/control/KID-PC"),
    req("POST", "/login", form={"password": PASSWORD, "next": "/control/KID-PC"}, csrf="form"),
    req("GET", "/"),
    req("GET", "/set-password"),
    req(
        "POST",
        "/set-password",
        form={
            "current_password": "wrong",
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        },
        csrf="form",
    ),
    req(
        "POST",
        "/set-password",
        form={
            "current_password": PASSWORD,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        },
        csrf="form",
    ),
    req("GET", "/"),
    req("GET", "/logout"),
    req("GET", "/"),
    req("GET", "/login"),
    req("POST", "/login", form={"password": PASSWORD}, csrf="form"),
    req("POST", "/login", form={"password": "newpassword1"}, csrf="form"),
    req("GET", "/"),
]

SCENARIOS: list[dict[str, Any]] = [
    {"name": "open_panel", "auth": None, "requests": OPEN_REQUESTS},
    {"name": "password_protected", "auth": AUTH_RECORD, "requests": PROTECTED_REQUESTS},
]


# ---------------------------------------------------------------------------
# HTML normalization (mirrored in go/panel/web/vectors_test.go)
# ---------------------------------------------------------------------------
_CSRF_RE = re.compile(r'(name="csrf-token" content="|name="csrf_token" value=")[^"]*(")')
_NUM_REF_RE = re.compile(r"&#(?:(\d+)|[xX]([0-9a-fA-F]+));")
_WS_RE = re.compile(r"[ \t\n\r\f\v]+")
CSRF_SCRAPE_RE = re.compile(r'name="csrf-token" content="([^"]+)"')


def normalize_html(text: str) -> str:
    text = _CSRF_RE.sub(r"\1CSRF\2", text)
    text = _NUM_REF_RE.sub(lambda m: chr(int(m[1]) if m[1] else int(m[2], 16)), text)
    text = _WS_RE.sub(" ", text)
    return text.replace("> <", "><").strip()


# ---------------------------------------------------------------------------
# Fake reverse server (mirrored in go/panel/web/vectors_test.go)
# ---------------------------------------------------------------------------
class FakeSession:
    def __init__(self, ip: str, spec: dict[str, Any]) -> None:
        self.peer_ip = ip
        self.hostname = spec["hostname"]
        self.pc_info = dict(spec["settings"])


class FakeLogs:
    def __init__(self, lines: list[str], truncated: bool) -> None:
        self.lines = lines
        self.truncated = truncated
        self.path = "C:\\ProgramData\\KidPCMonitor\\pc_control.log"


class FakeReverse:
    """Answers like PanelReverseServer, without a network.

    perform_action reports the request fields it would have sent, so the
    vectors pin how the panel maps each UI action.
    """

    def __init__(self, sessions: dict[str, dict[str, Any]]) -> None:
        self.specs = sessions
        self.sessions = {ip: FakeSession(ip, spec) for ip, spec in sessions.items()}

    def session_for_ip(self, ip: str) -> FakeSession | None:
        return self.sessions.get(ip)

    def perform_action(
        self, ip: str, action_name: str, payload: dict[str, Any] | None = None
    ) -> tuple[bool, str] | None:
        if ip not in self.sessions:
            return None
        try:
            action, var, val, tail = action_request_fields(action_name, payload)
        except (ValueError, KeyError, TypeError) as exc:
            return False, f"Invalid value for {action_name}: {exc}"
        return True, f"{action} var={var} val={val} tail={tail}"

    def get_logs(self, ip: str) -> FakeLogs:
        spec = self.specs[ip]
        if "logs_error" in spec:
            raise ConnectionError(spec["logs_error"])
        return FakeLogs(spec["logs"], spec["truncated"])


# ---------------------------------------------------------------------------
# Running a scenario
# ---------------------------------------------------------------------------
RECORDED_HEADERS = ["Location", "Content-Type", "Cache-Control", "Pragma", "Expires", "Allow"]


@contextmanager
def panel_env(scenario: dict[str, Any]) -> Iterator[tuple[Any, Path]]:
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        db_path = Path(tmp) / panel_db.DB_FILENAME
        auth_path = Path(tmp) / wp.AUTH_FILE
        if scenario["auth"] is not None:
            auth_path.write_text(json.dumps(scenario["auth"], indent=2), encoding="utf-8")
        stack.enter_context(mock.patch.object(panel_db, "_db_path_override", db_path))
        stack.enter_context(mock.patch.object(wp, "_auth_path", return_value=auth_path))
        stack.enter_context(mock.patch.object(wp, "_auth_save_path", return_value=auth_path))
        stack.enter_context(
            mock.patch.object(wp, "get_reverse_server", return_value=FakeReverse(SESSIONS))
        )
        stack.enter_context(mock.patch.dict("os.environ", {"KID_PC_MONITOR_REVERSE_PORT": ""}))
        for item in SEED:
            at = datetime.fromisoformat(item["at"])
            args = item["args"]
            with panel_clock.fixed(lambda at=at: at, tz=TZ):
                if item["op"] == "reverse_status":
                    wp._record_reverse_pc_info(args["hostname"], args["ip"], dict(args["settings"]))
                elif item["op"] == "reverse_disconnect":
                    wp._record_reverse_disconnect(args["hostname"], args["ip"])
                else:
                    run_op(item["op"], args, db_path)
        now = datetime.fromisoformat(NOW)
        stack.enter_context(panel_clock.fixed(lambda: now, tz=TZ))
        app = wp.create_app()
        app.config["TESTING"] = True
        try:
            yield app, auth_path
        finally:
            panel_db._initialized_paths.discard(db_path)


def allow_set(value: str) -> str:
    """werkzeug lists Allow in set order, which varies with PYTHONHASHSEED."""
    return ", ".join(sorted(m.strip() for m in value.split(",")))


def body_record(response: Any) -> dict[str, Any]:
    content_type = response.headers.get("Content-Type", "")
    data = response.get_data()
    if content_type.startswith("application/json"):
        return {"json": json.loads(data)}
    if content_type.startswith("text/html"):
        return {"html": normalize_html(data.decode("utf-8"))}
    return {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    out_requests = []
    with panel_env(scenario) as (app, auth_path):
        client = app.test_client()
        csrf = ""
        for spec in scenario["requests"]:
            headers = dict(spec.get("headers", {}))
            form = dict(spec.get("form", {})) if "form" in spec else None
            if spec.get("csrf") == "header":
                headers["X-CSRF-Token"] = csrf
            elif spec.get("csrf") == "form":
                form = {**(form or {}), "csrf_token": csrf}
            kwargs: dict[str, Any] = {"headers": headers}
            if "json" in spec:
                kwargs["json"] = spec["json"]
            elif form is not None:
                kwargs["data"] = form
            response = client.open(spec["path"], method=spec["method"], **kwargs)
            text = response.get_data(as_text=True)
            scraped = CSRF_SCRAPE_RE.search(text)
            if scraped:
                csrf = scraped.group(1)
            record: dict[str, Any] = {
                "status": response.status_code,
                "headers": {
                    h: allow_set(response.headers[h]) if h == "Allow" else response.headers[h]
                    for h in RECORDED_HEADERS
                    if h in response.headers
                },
                **body_record(response),
            }
            out_requests.append({**spec, "response": record})
        auth_after = json.loads(auth_path.read_text()) if auth_path.exists() else None
    return {
        "name": scenario["name"],
        "auth": scenario["auth"],
        "requests": out_requests,
        # A password set during the scenario: only whether one exists (salts are random).
        "password_set_after": bool(auth_after and auth_after.get("password_hash")),
    }


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden web-panel HTTP vectors generated from kid_pc_monitor.web_panel by "
            "tests/panelweb_vectors_gen.py. Do not edit by hand."
        ),
        "tz": "-05:00",
        "now": NOW,
        "seed": SEED,
        "sessions": SESSIONS,
        "panel_username": wp.PANEL_USERNAME,
        "dynamic_cache_control": wp.DYNAMIC_CACHE_CONTROL,
        "scenarios": [run_scenario(s) for s in SCENARIOS],
    }


def render(vectors: dict[str, Any]) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=False) + "\n"


def static_files(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != "README.md"
    }


STATIC_README = (
    "Generated copy of src/kid_pc_monitor/static for go:embed (Go cannot embed files\n"
    "outside its module). Do not edit: change the originals and run\n"
    "`python tests/panelweb_vectors_gen.py`.\n"
)


def static_copy_is_current() -> bool:
    readme = STATIC_GO / "README.md"
    return (
        static_files(STATIC_SRC) == static_files(STATIC_GO)
        and readme.exists()
        and readme.read_text(encoding="utf-8") == STATIC_README
    )


def sync_static_copy() -> None:
    if STATIC_GO.exists():
        shutil.rmtree(STATIC_GO)
    shutil.copytree(STATIC_SRC, STATIC_GO)
    (STATIC_GO / "README.md").write_text(STATIC_README, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if anything is out of date")
    args = parser.parse_args()
    text = render(build_vectors())
    if args.check:
        current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else ""
        stale = []
        if current != text:
            stale.append(str(VECTORS_PATH))
        if not static_copy_is_current():
            stale.append(str(STATIC_GO))
        if stale:
            print(
                f"out of date: {', '.join(stale)}; run tests/panelweb_vectors_gen.py",
                file=sys.stderr,
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    sync_static_copy()
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)} and {STATIC_GO.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
