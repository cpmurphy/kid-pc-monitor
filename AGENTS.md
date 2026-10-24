# Agent Guide — Kid PC Monitor

## Project Layout

- `src/kid_pc_monitor/` — Package source (setuptools, `where = ["src"]`).
- `scripts/` — Installers and dev launchers.
- `tests/` — pytest; `pythonpath = ["src"]` in `pyproject.toml`.
- `docs/` — Protocol spec (`agent-protocol.md`), FAQ, cross-user install notes.
- `go/` — Go ports of the protocol, lock policy, state files, request dispatcher, monitoring loop, Windows platform and the agent process (`cmd/kid-pc-agent`), plus the `xcheck` / `wincheck` test tools; see `go/README.md`.
- `testdata/` — golden vectors shared by Python and Go (generated, do not hand-edit).

## Two Components

1. **Agent** (`pc_control.py`) — Kid-side Windows service. Monitors session, enforces locks, and connects outbound to the panel reverse port (**TCP 9998**).
2. **Web Panel** (`web_panel.py`) — Parent admin UI (Flask on **TCP 5000**) plus native reverse listener (**TCP 9998**). Runs on Windows, Linux, or macOS. Optional TLS via `config_dir()/tls/cert.pem` + `key.pem` or `KID_PC_MONITOR_SSL_CERT` / `KID_PC_MONITOR_SSL_KEY`; iOS Safari password autofill requires trusted HTTPS (see `scripts/setup_web_panel_https.sh`).

Entry points (after `pip install -e .`):
- `kid-pc-agent`
- `kid-pc-web-panel`

## Dev Setup

Minimum Python is **3.11** (`requires-python`, ruff `target-version`, CI matrix). Don't use newer-only syntax such as unparenthesized `except A, B:` (3.14).

```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

On Linux/macOS the web panel works; the agent is Windows-only (`pywin32`).

## Code Quality

Run from an activated venv (`./venv` or `./.venv`):

```bash
ruff format src tests
ruff check --fix src tests
basedpyright
pytest
```

Install dev tools with `pip install -e ".[dev]"` or `pip install -r requirements-dev.txt` (after runtime deps).

Optional git hooks (run once after dev install):

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

- **pre-commit**: `ruff format` and `ruff check` on every commit (`src/` and `tests/` only).
- **pre-push**: `basedpyright` on the whole tree before `git push`.

Run hooks manually with `pre-commit run --all-files` and `pre-commit run --hook-stage pre-push basedpyright --all-files`.

## Running from Checkout (No Install)

```bash
# Web panel
python scripts/run_web_panel.py

# Agent (Windows only)
python scripts/run_agent.py
```

These auto-detect `./venv` or `./.venv` and re-exec with the venv interpreter. They also add `src/` to `sys.path`.

## Testing

```bash
pytest                    # all tests (venv: ./venv/bin/pytest)
pytest tests/test_lock_policy.py -v   # single file
```

Tests stub the Windows platform via `FakeHostPlatform` — no real Windows session needed. If `pytest` is not on `$PATH`, use `./venv/bin/pytest` or `python -m pytest` from the activated venv.

## Agent Protocol (Custom)

- KDL-subset over TCP with a **length-prefix** frame (see `docs/agent-protocol.md`).
- **v2** adds HMAC-SHA256 mutual auth; the signing key is the UTF-8 bytes of the shared secret (`agent_auth.derive_key`).
- **v3** is the only wire version. New capabilities (e.g. `get_logs`) are optional actions at v3; unsupported agents return `unknown_action`.
- Write actions (`set`, `lock`, `unlock`, `extend`, `shutdown`, `message`) require `name` matching the agent's hostname.
- Timestamp window: ±60 s.
- Agents dial out to the panel reverse port (**9998**) and speak native v3; HTTP `/agent/v1/discover` on **5000** is bootstrap only (env/cache, then agent `/24` scan).
- Web panel **Agent log** page (`/logs/<ip>`) uses `get_logs` over the reverse session; agents without that action show an upgrade message.

## Go Port

The Python code is the reference; Go packages under `go/` mirror it and are held to it by golden vectors in `testdata/` (generated, do not hand-edit):

| Python module | Go package | Vectors | Generator |
|---|---|---|---|
| `agent_protocol.py`, `agent_auth.py` | `go/protocol` | `testdata/protocol/vectors.json` | `tests/protocol_vectors_gen.py` |
| `lock_policy.py` | `go/policy` | `testdata/policy/vectors.json` | `tests/policy_vectors_gen.py` |
| `agent_state.py` | `go/state` | `testdata/state/vectors.json` | `tests/state_vectors_gen.py` |
| `request_dispatcher.py` | `go/dispatcher` | `testdata/dispatcher/vectors.json` | `tests/dispatcher_vectors_gen.py` |
| `pc_time_control.py` | `go/monitor` | `testdata/monitor/vectors.json` | `tests/monitor_vectors_gen.py` |

Any intentional behavior change in one of those Python modules must regenerate its vectors and keep Go in step:

```bash
python tests/<name>_vectors_gen.py       # rewrite the vectors
(cd go && go test ./...)                 # Go must agree on every vector
python scripts/cross_check_go.py         # live Go<->Python sessions and state-file interop
```

`tests/test_*_vectors.py` fail when a vectors file is stale (on every Python in the CI matrix). Only the Go parts need Go 1.22+; the Python tests do not.

### State file handling

`agent_state.py` never silently discards a file: an unusable `daily_settings.json` / `state.json` is renamed to `<name>.corrupt-<timestamp>` and the last good `<name>.bak` (refreshed on every save) is restored; `AgentStateStore.problems` lists what happened. Values are validated strictly (see `go/state/doc.go`). A load that fails with an I/O error makes `PCTimeControl` skip saving, so defaults never overwrite real files.

### Monitoring loop

`PCTimeControl.monitor_step()` is one iteration of `run_monitor()` (which only adds the sleep); its phases (usage tick, warnings, lock enforcement, periodic save) run independently, so an error in one is logged once and never stops the others. Platform query errors fail toward enforcement: an unknown lock state counts as unlocked (so the lock is re-issued), an unknown session state as active (so time is counted). `PCTimeControl` takes `clock`, `current_user` and `program_data_dir` so tests and the monitor vectors can drive it deterministically.

## Windows Install Quirks

- **Cross-user install**: admin runs installer, child runs agent. Requires **system-wide Python** (installer refuses per-user installs). Files go to `C:\ProgramData\KidPCMonitor`; child gets read+execute via `icacls`.
- Same-user install: task runs as current user, elevated (`Highest`).
- `scripts/install_agent.ps1` is the PowerShell installer for the **Go agent** (no Python on the kid's PC): builds `go/cmd/kid-pc-agent` (or takes `-AgentExe`), installs `kid-pc-agent.exe` to ProgramData, removes the Python agent's files there, and sets an explicit ACL (SYSTEM/Administrators full, child RX). Same task name, settings files and Fernet secret format as `install.py`, so either installer can replace the other. Keep it ASCII-only (Windows PowerShell 5.1 reads BOM-less scripts as ANSI) and write JSON as UTF-8 **without** a BOM (the agents treat a BOM as corrupt). Dot-sourcing it loads the functions without running.
- `scripts/install_web_panel.py` is the Windows web-panel installer (also creates a scheduled task). Parent host needs inbound **5000** and **9998**.
- `scripts/install_web_panel_linux.sh install` is self-contained on Linux: it creates/repairs `venv/` (system Python 3.11+, else uv-managed Python), runs `pip install -e .`, writes a systemd `--user` unit, then checks linger and firewall (`kid_pc_monitor.linux_firewall`) and only suggests changes that are needed.
- Uninstall removes any leftover legacy inbound TCP 9999 firewall rule from older installs.

## State & Logging Paths

- Agent: `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` and `pc_control_state.json` (Windows).
- Agent log rotation: size-based via `RotatingFileHandler` (200 KiB active file, 4 backups → `pc_control.log.1` …).
- Web panel auth: `%LOCALAPPDATA%\kid-pc-monitor\web_panel_auth.json` (Windows) or `~/.config/kid-pc-monitor/web_panel_auth.json` (Linux/macOS).
- Log level: `KID_PC_MONITOR_LOG_LEVEL` env var (default `INFO`).
- `get_logs` returns only the active `pc_control.log` tail; older lines may be in rotated `.N` siblings on disk.

## Daily Settings

- `daily_settings.json` (merged at install, lives in agent state dir) controls `wake_time`, `bed_time`, `allowance`.
- Daily usage resets at **wake_time**, not midnight.
- `extend` accumulates; it does not zero already-counted time.

## Common Gotchas

- **Parent firewall must allow 5000 and 9998**: reverse control is inbound on the panel host, not the kid PC. Allow TCP 5000 (UI/discovery) and 9998 (native reverse).
- Agent re-locks whenever it detects an unlock while any limit (bedtime, allowance, manual lock) is active.
- Custom PC names: edit `CUSTOM_PC_NAMES` in `src/kid_pc_monitor/remote_client.py`.
