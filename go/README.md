# Go protocol port

A Go implementation of the Kid PC Monitor wire protocol (v3), the first step
toward a compiled Windows agent. Standard library only.

| Path | What |
|---|---|
| `protocol/` | The package: KDL-subset parser/serializer, framing, HMAC auth, request/response build and parse, and `HandleRequest` (the agent's authenticate → dispatch → sign entry point). |
| `cmd/xcheck/` | Test fixture used by `scripts/cross_check_go.py`: a toy agent and a toy panel. Not a product. |
| `../testdata/protocol/vectors.json` | Golden vectors generated from the Python implementation. |

## The Python code is the reference

`src/kid_pc_monitor/agent_protocol.py` and `agent_auth.py` define the
protocol. The vectors are a snapshot of what they do:

```bash
python tests/protocol_vectors_gen.py   # regenerate after an intentional Python change
cd go && go test ./...                 # every vector must pass in Go
python scripts/cross_check_go.py       # live TCP sessions in both directions
```

`go/protocol/doc.go` lists the few places where Go is deliberately stricter
than Python (integer range, Unicode digits, invalid UTF-8). None can occur in
frames either side produces.

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
