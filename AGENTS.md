# Agent Guide — Kid PC Monitor

## Project Layout

- `src/kid_pc_monitor/` — Package source (setuptools, `where = ["src"]`).
- `scripts/` — Installers and dev launchers.
- `tests/` — pytest; `pythonpath = ["src"]` in `pyproject.toml`.
- `docs/` — Protocol spec (`agent-protocol.md`), FAQ, cross-user install notes.

## Three Components

1. **Agent** (`pc_control.py`) — Kid-side Windows service. Monitors session, enforces locks, listens on **TCP 9999**.
2. **Web Panel** (`web_panel.py`) — Parent admin UI (Flask on **TCP 5000**). Runs on Windows, Linux, or macOS. Optional TLS via `config_dir()/tls/cert.pem` + `key.pem` or `KID_PC_MONITOR_SSL_CERT` / `KID_PC_MONITOR_SSL_KEY`; iOS Safari password autofill requires trusted HTTPS (see `scripts/setup_web_panel_https.sh`).
3. **CLI** (`pc_cli.py`) — Command-line remote client (`scan`, `inspect`, `set-limit`, `lock`, …).

Entry points (after `pip install -e .`):
- `kid-pc-agent`
- `kid-pc-web-panel`
- `kid-pc-cli`

## Dev Setup

```bash
pip install -r requirements.txt
pip install -e .
pytest
```

On Linux/macOS the web panel and CLI work; the agent is Windows-only (`pywin32`).

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
- **v2** adds HMAC-SHA256 mutual auth; signing key is `HMAC-SHA256(shared_secret)`.
- **v3** is the deployed baseline; **v4** is a strict superset (adds `get_logs`). Clients send v3 for existing actions and v4 only for v4-only features; agents accept both.
- Write actions (`set`, `lock`, `unlock`, `extend`, `shutdown`, `message`) require `name` matching the agent's hostname.
- Timestamp window: ±60 s.
- Web panel **Agent log** page (`/logs/<ip>`) uses v4 `get_logs`; v3-only agents show an upgrade message.

## Windows Install Quirks

- `scripts/install.py` creates a scheduled task and a **Windows Firewall** inbound rule scoped to the exact `pythonw.exe` path, TCP 9999, Private+Domain by default.
- **Cross-user install**: admin runs installer, child runs agent. Requires **system-wide Python** (installer refuses per-user installs). Files go to `C:\ProgramData\KidPCMonitor`; child gets read+execute via `icacls`.
- Same-user install: task runs as current user, elevated (`Highest`).
- `scripts/install_web_panel.py` is the Windows web-panel installer (also creates a scheduled task).
- `scripts/install_web_panel_linux.sh` writes a systemd `--user` unit on Linux.

## State & Logging Paths

- Agent: `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` and `pc_control_state.json` (Windows).
- Web panel auth: `%LOCALAPPDATA%\kid-pc-monitor\web_panel_auth.json` (Windows) or `~/.config/kid-pc-monitor/web_panel_auth.json` (Linux/macOS).
- Log level: `KID_PC_MONITOR_LOG_LEVEL` env var (default `INFO`).

## Daily Settings

- `daily_settings.json` (merged at install, lives in agent state dir) controls `wake_time`, `bed_time`, `allowance`.
- Daily usage resets at **wake_time**, not midnight.
- `extend` accumulates; it does not zero already-counted time.

## Common Gotchas

- **Public network profile blocks remote control**: Windows Firewall rule defaults to Private+Domain only. If the kid PC reconnects Wi-Fi and Windows marks it Public, scans time out. Fix: set network to Private, or re-run `install.py` and allow Public.
- **Firewall rule is tied to a specific `pythonw.exe` path**. If Python is upgraded or moved, the rule may still reference the old path and block traffic. Re-run the installer.
- Agent re-locks whenever it detects an unlock while any limit (bedtime, allowance, manual lock) is active.
- Custom PC names: edit `CUSTOM_PC_NAMES` in `src/kid_pc_monitor/remote_client.py`.
