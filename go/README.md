# Go agent

A complete Go port of the Kid PC Monitor kid-side agent: one Windows
executable, `kid-pc-agent.exe`, that does everything the Python agent does
(enforcement, the reverse connection to the parent panel, logging) and needs no
Python on the kid's PC. Standard library only.

It is a drop-in replacement: it reads and writes the same `daily_settings.json`,
`state.json`, `pc_control.log` and encrypted shared secret, speaks the same v3
protocol to the same web panel, and runs from the same `KidPCMonitor` scheduled
task. The web panel itself stays in Python.

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

Go 1.22 or later. Everything except `winplatform`, `cmd/kid-pc-agent` and
`cmd/wincheck` also builds and tests on Linux and macOS.

## Packages

| Path | Python original | What |
|---|---|---|
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
| `cmd/wincheck/` | | Manual check of `winplatform` on a real host (status, lock, message, shutdown / cancel). |
| `cmd/xcheck/` | | Test fixture for `scripts/cross_check_go.py`: a toy agent, a toy panel and state-file helpers. |

How a request flows: `agent.ReverseClient` reads a frame from the panel,
`protocol.HandleRequest` authenticates it and calls `dispatcher.Handler`, which
drives `monitor.Control`; the monitor talks to Windows through
`winplatform.Platform` and persists through `state.Store`.

## The Python code is the reference

Each ported module is held to the Python implementation by golden vectors that
Python generates (`../testdata/*/vectors.json`, do not hand-edit) and Go must
reproduce exactly:

```bash
python tests/<name>_vectors_gen.py   # protocol, policy, state, dispatcher, monitor: regenerate after an intentional Python change
cd go && go test ./...               # every vector must pass in Go
python scripts/cross_check_go.py     # live Go<->Python sessions, state-file interop, and (on Windows) the real agent against the Python panel
```

`tests/test_*_vectors.py` fail when a vectors file is stale, so a Python change
cannot silently leave Go behind. The secret store is tested against tokens made
by the Python code, and `tests/install_agent_test.ps1` checks that Python reads
what the PowerShell installer writes.

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
