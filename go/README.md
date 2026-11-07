# Go module

This directory is the Kid PC Monitor module (`kidpcmonitor`): the Windows
agent `kid-pc-agent` and the parent web panel `kid-pc-web-panel`. Both were
ported from the original Python programs. The agent uses only the standard
library. The panel adds `modernc.org/sqlite` (pure Go) and `golang.org/x/crypto`,
which the agent never imports (CI checks this). `golang.org/x/term` reads the
shared-secret prompt.

The agent reads and writes the same `daily_settings.json`, `state.json`,
`pc_control.log` and encrypted shared secret as an older Python agent, speaks
the same v3 protocol, and runs from the same `KidPCMonitor` scheduled task.
The panel reads the same `panel.db`, password file and secret.

## Install

From an administrator PowerShell on the kid's PC:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_agent.ps1
```

The installer builds the agent from this directory if Go is installed, and
otherwise downloads it from the latest GitHub release (checked against
`SHA256SUMS`). It replaces a Python agent in place, keeping its schedule and
secret. See the [README](../README.md) for the options.

## Build

```bash
cd go
go build -ldflags -H=windowsgui -o kid-pc-agent.exe ./cmd/kid-pc-agent
```

`-H=windowsgui` makes it a GUI-subsystem program so the scheduled task opens no
console window (the Python agent uses `pythonw.exe` for the same reason).
Release builds add `-trimpath -s -w` and `-X main.version=<tag>`; pushing a `v*`
tag publishes amd64 and arm64 builds (`.github/workflows/release.yml`).

Go 1.26 or later. Everything except `winplatform`, `cmd/kid-pc-agent` and
`cmd/wincheck` also builds and tests on Linux and macOS.

## Web panel

`cmd/kid-pc-web-panel` is the parent web panel. It reads the same `panel.db`,
`web_panel_auth.json`, TLS files and shared secret as the original Python panel:

```bash
cd go
go build -o kid-pc-web-panel ./cmd/kid-pc-web-panel
./kid-pc-web-panel set-secret   # once, unless an installer already stored it
./kid-pc-web-panel              # serves http(s)://0.0.0.0:5000 and TCP 9998
```

Release builds are published for Windows, Linux and macOS (amd64 and arm64).
`scripts/install_web_panel.ps1` (Windows) and
`scripts/install_web_panel_linux.sh install` set it up as a background
task or service (`install --go` is the same command). `serve -background`
hides the console Windows creates for a scheduled task and logs to
`config_dir/web_panel.log`. A session cookie from the original Python panel
does not carry over, so log in once after replacing that install.

## Packages

| Path | Python original | What |
|---|---|---|
| `cmd/kid-pc-web-panel/` | `web_panel.main` | The parent web panel executable (Windows, macOS, Linux): UI on 5000, reverse listener on 9998, same env vars and files as the Python panel; `set-secret` stores the shared secret. |
| `cmd/kid-pc-agent/` | `pc_control.py` | The executable: logging, monitor, reverse client; diagnostics in the background. |
| `agent/` | `agent_sync_client.py`, `pc_control.py` | Reverse client (env / cache / LAN discovery, TLS with self-signed fallback, reconnect), Python-format size-rotated `pc_control.log`, data dir and user name. |
| `monitor/` | `pc_time_control.py` | The enforcement loop: usage accounting, low-time warnings, lock enforcement, periodic saves, parent actions. Implements `dispatcher.Control` over a `Platform` interface; safe for concurrent use. |
| `winplatform/` | `platforms/windows.py` | Windows `monitor.Platform`: WTS lock state with LogonUI fallback, active-console check, `LockWorkStation`, self-closing popups, `shutdown.exe`, connectivity diagnostics. |
| `dispatcher/` | `request_dispatcher.py` | Executes validated panel requests (get / set / clear / extend / message / shutdown / lock / get_logs) and builds the response. |
| `protocol/` | `agent_protocol.py`, `agent_auth.py` | v3 wire protocol: KDL-subset parser and serializer, framing, HMAC auth, `HandleRequest` (authenticate, dispatch, sign). |
| `policy/` | `lock_policy.py` | Bedtime curfew, allowance, minutes until lock, access status. Pure functions. |
| `state/` | `agent_state.py` | Settings and runtime state files: strict validation, corrupt-file quarantine and `.bak` restore, wake-time rollover, legacy migration, ProgramData bootstrap. |
| `secrets/` | `secrets_store.py` | Reads the installer's Fernet-encrypted secrets, including the shared secret. |
| `netinfo/` | `network.py` | Primary IPv4 without contacting external hosts. |
| `panel/format/` | `panel_format.py`, `remote_client.py`, `scan_store.py` | Display formatting, agent settings → PC info, panel action → request fields, connection-error text, dashboard status. |
| `panel/store/` | `panel_db.py`, `scan_store.py`, `snapshot_store.py`, `agent_sync_store.py` | `panel.db` (tracked PCs, usage snapshots, reverse heartbeats), same schema and rows as the original Python panel. |
| `panel/auth/` | `web_panel.py` (auth), `werkzeug.security` | `web_panel_auth.json`, werkzeug scrypt/pbkdf2 hashes, signed session cookie with CSRF token and flashes, login redirect check. |
| `panel/reverse/` | `panel_reverse_server.py` | The reverse listener on 9998 — identify, per-agent session with queued actions and idle status refresh, session replacement, logs. |
| `panel/web/` | `web_panel.py`, `agent_poller.py`, `templates/` | Every route, templates for `html/template`, embedded static files, reverse-status recording, the registry pruner. |
| `panel/pyval/` | | Value semantics for JSON and `panel.db` written by the original Python panel: truthiness, `int()`, `repr`, float `repr`, `datetime.fromisoformat`. |
| `cmd/wincheck/` | | Manual check of `winplatform` on a real host (status, lock, message, shutdown / cancel). |
| `firewall/` | `linux_firewall.py` | Whether a Linux host firewall blocks the panel ports. `kid-pc-web-panel check-firewall` prints the installer's advice. |

How a request flows: `agent.ReverseClient` reads a frame from the panel,
`protocol.HandleRequest` authenticates it and calls `dispatcher.Handler`, which
drives `monitor.Control`; the monitor talks to Windows through
`winplatform.Platform` and persists through `state.Store`.

## Golden vectors

Each ported package is held to frozen vectors in `../testdata/*/vectors.json`.
They were generated from the original Python implementation and are now the
checked-in contract: change a file in the same commit as the Go behavior.
There is no generator.

```bash
cd go && go test ./...    # every vector must pass
```

The secret store is tested against tokens produced by the original Python
code. `tests/install_agent_test.ps1` checks the PowerShell installer, including
that it still removes leftover Python agent files.

## Differences from the Python agent

Deliberate, and documented in each package's `doc.go`:

- Enforcement starts immediately at logon; the connectivity diagnostics (which
  can take 15 s in a standard user's session) run in the background.
- No inbound TCP 9999 listener: the agent only connects out to the panel.
- Platform failures are returned and logged rather than swallowed, so a failed
  `LockWorkStation` is not mistaken for a locked PC.
- Go is stricter about a few inputs neither implementation writes (integer
  range, Unicode digits, non-finite floats, exotic ISO formats).
- Popups are native message boxes instead of tkinter; discovery ignores proxy
  settings; log rotation counts bytes; a few log lines are worded slightly
  differently.

## Using the protocol package

The packages can be used on their own, for example to talk to an agent:

```go
body, _ := protocol.BuildRequest(protocol.RequestParams{
    Action: "lock", Secret: secret, Name: hostname,
})
protocol.WriteFrame(conn, body)

// Agent side:
reply := protocol.HandleRequest(body, secret, hostname, time.Now().Unix(), dispatch)
```

Timestamps are passed in explicitly (`now`) so tests are deterministic.
