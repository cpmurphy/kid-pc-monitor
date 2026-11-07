package web

import (
	"kidpcmonitor/panel/reverse"
	"kidpcmonitor/protocol"
)

// ReverseServer adapts a reverse.Server to Reverse.
type ReverseServer struct{ *reverse.Server }

// Session returns ip's live session.
func (r ReverseServer) Session(ip string) (string, map[string]any, bool) {
	s := r.SessionForIP(ip)
	if s == nil {
		return "", nil, false
	}
	return s.Hostname, s.Settings(), true
}

// GetLogs fetches the default tail (DEFAULT_LOG_TAIL_LINES).
func (r ReverseServer) GetLogs(ip string) (*protocol.LogsResult, error) {
	return r.Server.GetLogs(ip, protocol.DefaultLogTailLines)
}
