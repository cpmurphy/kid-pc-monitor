// Package agent is the kid agent's process plumbing: the reverse connection to
// the parent panel (src/kid_pc_monitor/agent_sync_client.py), Python-format
// size-rotated logging (pc_control.py), and the data directory and user name
// the Python agent uses. cmd/kid-pc-agent wires it to monitor and winplatform.
//
// # Reverse connection
//
// ReverseClient finds the panel ($KID_PC_MONITOR_PANEL_URL, then the
// panel_url.txt cache, then port 5000 across the local /24), asks
// /agent/v1/discover for its reverse port, dials it (TLS when the panel URL is
// https, falling back to an unverified handshake for self-signed panels) and
// answers framed v3 requests through protocol.HandleRequest and the
// dispatcher until the panel hangs up. It then waits 2-5 s and reconnects; a
// failed connection forgets the panel URL so it is rediscovered. The log lines
// match the Python client's.
//
// # Differences from the Python agent
//
//   - Discovery ignores proxy settings (urllib honours the Windows proxy);
//     the panel is always on the LAN.
//   - A discovery reply that is JSON but not an object, or an out-of-range
//     reverse_port, counts as "no panel" / a connect failure instead of
//     escaping as an unexpected exception (which Python retried after 15 s).
//   - The secret's key derivation is cached, so reconnecting does not repeat
//     600 000 PBKDF2 rounds.
//   - Stopping (cancelling the context) also interrupts discovery.
//   - Rotation counts bytes; Python counts characters. Log records carry no
//     tracebacks.
package agent
