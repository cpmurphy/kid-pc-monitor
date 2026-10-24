# Go protocol port

A Go implementation of the Kid PC Monitor wire protocol (v3), the first step
toward a compiled Windows agent. Standard library only.

| Path | What |
|---|---|
| `protocol/` | Wire protocol: KDL-subset parser/serializer, framing, HMAC auth, request/response build and parse, and `HandleRequest` (the agent's authenticate → dispatch → sign entry point). |
| `policy/` | Lock policy: bedtime curfew, allowance, minutes until lock, access status. Pure functions. |
| `state/` | `daily_settings.json` / `state.json` persistence, wake-time rollover, legacy migration, ProgramData bootstrap. |
| `dispatcher/` | Executes validated requests against a `Control` interface (get/set/clear/extend/message/shutdown/lock/get_logs) and builds the response content; `dispatcher.Handler(control)` plugs into `protocol.HandleRequest`. |
| `monitor/` | The monitoring loop (`pc_time_control.py`): usage accounting, low-time warnings, lock enforcement, periodic saves, and the parent actions. `monitor.Control` implements `dispatcher.Control` over a `Platform` interface. Safe for concurrent use. |
| `winplatform/` | Windows `monitor.Platform` (`platforms/windows.py`): WTS session lock state with LogonUI fallback, active-console check, `LockWorkStation`, timed popups, `shutdown.exe`. |
| `cmd/wincheck/` | Manual check of `winplatform` on a real Windows host (status, lock, message, shutdown/cancel). |
| `cmd/xcheck/` | Test fixture used by `scripts/cross_check_go.py`: a toy agent, a toy panel, and state-file helpers. Not a product. |
| `../testdata/*/vectors.json` | Golden vectors generated from the Python implementation. |

Not ported yet: the agent's `main` (including the connectivity diagnostics
from `platforms/windows.py`), logging setup, the reverse-connection client,
and the installers.

## The Python code is the reference

`src/kid_pc_monitor/agent_protocol.py` and `agent_auth.py` define the
protocol. The vectors are a snapshot of what they do:

```bash
python tests/protocol_vectors_gen.py   # (or policy_ / state_ / dispatcher_ / monitor_) regenerate after an intentional Python change
cd go && go test ./...                 # every vector must pass in Go
python scripts/cross_check_go.py       # live TCP sessions and state-file interop
```

Each package's `doc.go` lists the few places where Go is deliberately stricter
than Python (integer range, Unicode digits, non-finite floats, exotic ISO
formats). None can occur in data either implementation writes.

## Using the package

```go
body, _ := protocol.BuildRequest(protocol.RequestParams{
    Action: "lock", Secret: secret, Name: hostname,
})
protocol.WriteFrame(conn, body)

// Agent side:
reply := protocol.HandleRequest(body, secret, hostname, time.Now().Unix(), dispatch)
```

Timestamps are passed in explicitly (`now`) so tests are deterministic.
