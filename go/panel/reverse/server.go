// Package reverse is the web panel's reverse listener (TCP 9998): agents dial
// out to it and the panel then drives each connection as a protocol client
// (panel_reverse_server.py).
//
// On connect the panel identifies the agent with an unnamed "get settings",
// registers the session by hostname and peer IP (replacing an older session
// for the same hostname), reports its status, and from then on sends queued
// parent actions or, after StatusRefresh without one, another "get settings".
// Any failure ends the session; the agent reconnects.
//
// Behavior that has to match the original Python listener is covered by
// server_test.go and by the panelweb golden vectors.
//
// # Known differences from the Python implementation
//
//   - A request still queued when its caller times out is dropped instead of
//     being sent later, and requests left queued when a session ends fail at
//     once instead of each waiting out its timeout.
//   - A value the protocol cannot carry fails that one action
//     ("Invalid value for ...") instead of ending the session.
//   - Transport error text comes from Go ("i/o timeout", "connection reset
//     by peer", ...), and a timed-out action reports "timed out" where
//     Python reports an empty message.
//   - get_logs with tail 0 sends no tail (the agent's default) where Python
//     sends "tail 0".
//   - The TLS handshake runs on the session's goroutine, so a slow client
//     cannot hold up other agents' connections.
package reverse

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/protocol"
)

// Defaults (panel_reverse_server.py).
const (
	DefaultPort     = 9998
	PortEnv         = "KID_PC_MONITOR_REVERSE_PORT"
	StatusRefresh   = 5 * time.Second
	ExchangeTimeout = 30 * time.Second
	retryDelay      = 5 * time.Second
)

// ListenPort is the reverse port from KID_PC_MONITOR_REVERSE_PORT, else
// DefaultPort (reverse_listen_port).
func ListenPort() int {
	raw := strings.TrimSpace(os.Getenv(PortEnv))
	if raw == "" {
		return DefaultPort
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultPort
	}
	return n
}

// ErrSessionClosed is returned for actions on a session that has ended.
var ErrSessionClosed = errors.New("Reverse agent session is closed")

// errTimedOut is a caller giving up on an action.
var errTimedOut = errors.New("timed out")

// Server accepts agent connections and runs their sessions.
type Server struct {
	// Addr is the TCP address to listen on, e.g. "0.0.0.0:9998" (IPv4 only,
	// as the Python panel binds AF_INET).
	Addr string
	// TLS, when set, wraps every connection (the panel's own certificate).
	TLS *tls.Config
	// Secret returns the shared secret; it is read for every connection, so
	// a secret set while the panel runs takes effect without a restart.
	Secret func() (string, error)
	// OnStatus receives each agent settings payload (hostname, peer IP,
	// settings); OnDisconnect fires when an agent's last session ends.
	OnStatus     func(hostname, ip string, settings map[string]any)
	OnDisconnect func(hostname, ip string)

	StatusRefresh   time.Duration // default StatusRefresh
	ExchangeTimeout time.Duration // default ExchangeTimeout
	Logger          *slog.Logger  // default slog.Default()
	// Now is the clock for protocol timestamps (default time.Now).
	Now func() time.Time

	mu     sync.Mutex
	byHost map[string]*Session
	byIP   map[string]*Session
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) refreshEvery() time.Duration {
	if s.StatusRefresh > 0 {
		return s.StatusRefresh
	}
	return StatusRefresh
}

func (s *Server) exchangeTimeout() time.Duration {
	if s.ExchangeTimeout > 0 {
		return s.ExchangeTimeout
	}
	return ExchangeTimeout
}

// ListenAndServe listens on Addr and serves until ctx ends, retrying every
// 5 s when the port cannot be bound (_serve).
func (s *Server) ListenAndServe(ctx context.Context) {
	for ctx.Err() == nil {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp4", s.Addr)
		if err != nil {
			s.log().Error("Reverse listener failed; retrying in 5s", "addr", s.Addr, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
			}
			continue
		}
		s.log().Info(fmt.Sprintf("Panel reverse TCP listening on %s%s", s.Addr, tlsSuffix(s.TLS)))
		s.Serve(ctx, ln)
	}
}

func tlsSuffix(cfg *tls.Config) string {
	if cfg != nil {
		return " (TLS)"
	}
	return ""
}

// Serve accepts connections on ln until ctx ends or ln fails, then closes
// ln and every session.
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer s.closeAll()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.log().Error("Reverse accept failed", "err", err)
			}
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.byHost))
	for _, sess := range s.byHost {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.close()
	}
}

// SessionForIP is the live session from ip, or nil.
func (s *Server) SessionForIP(ip string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byIP[ip]
}

// SessionForHostname is hostname's live session, or nil.
func (s *Server) SessionForHostname(hostname string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byHost[hostname]
}

// PerformAction runs a panel action (format.ActionRequestFields names) on
// ip's live session and returns the agent's verdict and text; found is false
// when ip has no session (PanelReverseServer.perform_action).
func (s *Server) PerformAction(ip, actionName string, payload map[string]any) (ok bool, text string, found bool) {
	sess := s.SessionForIP(ip)
	if sess == nil {
		return false, "", false
	}
	fields, err := format.ActionRequestFields(actionName, payload)
	if err != nil {
		return false, format.InvalidActionMessage(actionName, err), true
	}
	val, err := protocolValue(fields.Val)
	if err != nil {
		return false, format.InvalidActionMessage(actionName, err), true
	}
	req := protocol.RequestParams{Action: fields.Action, Val: val}
	if fields.Var != nil {
		req.Var = *fields.Var
	}
	if fields.Tail != nil {
		req.Tail = *fields.Tail
	}
	resp, err := sess.Submit(req, s.exchangeTimeout())
	if err != nil {
		return false, ErrorText(err), true
	}
	return resp.OK(), resp.Text(), true
}

// GetLogs fetches the tail of ip's agent log (PanelReverseServer.get_logs).
// An agent without get_logs answers unknown_action, which comes back as an
// error carrying the agent's text.
func (s *Server) GetLogs(ip string, tail int64) (*protocol.LogsResult, error) {
	sess := s.SessionForIP(ip)
	if sess == nil {
		return nil, fmt.Errorf("No reverse session for %s", ip)
	}
	resp, err := sess.Submit(protocol.RequestParams{Action: "get_logs", Tail: tail}, s.exchangeTimeout())
	if err != nil {
		return nil, err
	}
	if resp.Logs == nil {
		text := resp.Text()
		if text == "" {
			text = "Agent did not return logs"
		}
		return nil, errors.New(text)
	}
	return resp.Logs, nil
}

// ErrorText is the message the panel shows for an action error: a protocol
// error's message alone (as Python's str(ProtocolError)), else err's text.
func ErrorText(err error) string {
	var pe *protocol.ProtocolError
	if errors.As(err, &pe) {
		return pe.Message
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	return err.Error()
}

// protocolValue converts a JSON action value into a KDL scalar, as Python's
// format_value would render it.
func protocolValue(v any) (protocol.Value, error) {
	switch x := v.(type) {
	case nil, bool, int64, string:
		return x, nil
	case int:
		return int64(x), nil
	case float64:
		return pyval.FloatRepr(x), nil // str(float)
	}
	return nil, fmt.Errorf("unsupported value of type %T", v)
}

func reqID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	peerIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(peerIP); err == nil {
		peerIP = host
	}
	if s.TLS != nil {
		tc := tls.Server(conn, s.TLS)
		tc.SetDeadline(time.Now().Add(s.exchangeTimeout()))
		if err := tc.HandshakeContext(ctx); err != nil {
			s.log().Info("Reverse session ended", "peer", peerIP, "err", err)
			conn.Close()
			return
		}
		conn = tc
	}
	secret, err := s.Secret()
	if err != nil || secret == "" {
		s.log().Info("Reverse session ended: no shared secret is configured", "peer", peerIP)
		conn.Close()
		return
	}
	sess := &Session{
		server: s,
		conn:   conn,
		reader: bufio.NewReader(conn),
		secret: secret,
		PeerIP: peerIP,
		reqs:   make(chan *request),
		done:   make(chan struct{}),
	}
	resp, err := sess.exchange(protocol.RequestParams{Action: "get", Var: "settings"}, "")
	if err != nil {
		s.log().Info("Reverse session ended", "peer", peerIP, "err", err)
		conn.Close()
		return
	}
	if !resp.OK() || resp.Settings == nil || resp.Name == nil || *resp.Name == "" {
		s.log().Warn("Reverse identify failed", "peer", peerIP, "text", resp.Text())
		conn.Close()
		return
	}
	sess.Hostname = *resp.Name
	sess.setSettings(resp.Settings)
	s.register(sess)
	s.emitStatus(sess, resp.Settings)
	s.log().Info(fmt.Sprintf("Reverse agent connected: %s from %s", sess.Hostname, peerIP))

	err = sess.loop(ctx)
	if err != nil {
		s.log().Info(fmt.Sprintf("Reverse session from %s ended: %v", peerIP, err))
	}
	s.unregister(sess)
	sess.close()
	s.emitDisconnectIfGone(sess)
}

func (s *Server) register(sess *Session) {
	s.mu.Lock()
	if s.byHost == nil {
		s.byHost = map[string]*Session{}
		s.byIP = map[string]*Session{}
	}
	previous := s.byHost[sess.Hostname]
	for ip, existing := range s.byIP {
		if existing == previous || (existing.Hostname == sess.Hostname && existing != sess) {
			delete(s.byIP, ip)
		}
	}
	s.byHost[sess.Hostname] = sess
	s.byIP[sess.PeerIP] = sess
	s.mu.Unlock()
	if previous != nil && previous != sess {
		previous.close()
	}
}

func (s *Server) unregister(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byHost[sess.Hostname] == sess {
		delete(s.byHost, sess.Hostname)
	}
	if s.byIP[sess.PeerIP] == sess {
		delete(s.byIP, sess.PeerIP)
	}
}

func (s *Server) emitStatus(sess *Session, settings map[string]any) {
	if s.OnStatus == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("Failed to record reverse status", "host", sess.Hostname, "panic", r)
		}
	}()
	s.OnStatus(sess.Hostname, sess.PeerIP, copySettings(settings))
}

func (s *Server) emitDisconnectIfGone(sess *Session) {
	if s.OnDisconnect == nil {
		return
	}
	s.mu.Lock()
	_, replaced := s.byHost[sess.Hostname]
	s.mu.Unlock()
	if replaced {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("Failed to record reverse disconnect", "host", sess.Hostname, "panic", r)
		}
	}()
	s.OnDisconnect(sess.Hostname, sess.PeerIP)
}

func copySettings(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
