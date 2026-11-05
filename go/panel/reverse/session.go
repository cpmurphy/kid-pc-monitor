package reverse

import (
	"bufio"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"kidpcmonitor/protocol"
)

// Session is one connected agent (ReverseSession).
type Session struct {
	Hostname string
	PeerIP   string

	server *Server
	conn   net.Conn
	reader *bufio.Reader
	secret string

	mu       sync.Mutex
	settings map[string]any
	lastSeen time.Time

	reqs      chan *request
	done      chan struct{}
	closeOnce sync.Once
}

type request struct {
	params    protocol.RequestParams
	result    chan result
	abandoned atomic.Bool
}

type result struct {
	resp *protocol.Response
	err  error
}

// Settings is a copy of the agent's latest settings payload.
func (s *Session) Settings() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copySettings(s.settings)
}

// LastSeen is when the agent last answered.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

func (s *Session) setSettings(settings map[string]any) {
	s.mu.Lock()
	s.settings = copySettings(settings)
	s.mu.Unlock()
}

func (s *Session) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

// Submit queues a request for the agent and waits up to timeout for its
// response. A request still queued at the timeout is dropped.
func (s *Session) Submit(p protocol.RequestParams, timeout time.Duration) (*protocol.Response, error) {
	r := &request{params: p, result: make(chan result, 1)}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case s.reqs <- r:
	case <-s.done:
		return nil, ErrSessionClosed
	case <-timer.C:
		return nil, errTimedOut
	}
	select {
	case res := <-r.result:
		return res.resp, res.err
	case <-timer.C:
		r.abandoned.Store(true)
		return nil, errTimedOut
	case <-s.done:
		select {
		case res := <-r.result: // answered just before the session ended
			return res.resp, res.err
		default:
			return nil, ErrSessionClosed
		}
	}
}

// loop serves queued requests and refreshes status when idle, until the
// session fails, is replaced or ctx ends (_session_loop).
func (s *Session) loop(ctx context.Context) error {
	idle := time.NewTimer(s.server.refreshEvery())
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return nil
		case r := <-s.reqs:
			if r.abandoned.Load() {
				continue
			}
			resp, err := s.exchange(r.params, s.Hostname)
			r.result <- result{resp, err}
			if err != nil {
				return err
			}
		case <-idle.C:
			if err := s.refresh(); err != nil {
				return err
			}
		}
		idle.Reset(s.server.refreshEvery())
	}
}

// refresh re-reads the agent's settings and reports them (_refresh_status).
func (s *Session) refresh() error {
	resp, err := s.exchange(protocol.RequestParams{Action: "get", Var: "settings"}, s.Hostname)
	if err != nil {
		return err
	}
	if !resp.OK() || resp.Settings == nil {
		text := resp.Text()
		if text == "" {
			text = "status refresh failed"
		}
		return &protocol.ProtocolError{Code: protocol.InternalError, Message: text}
	}
	s.setSettings(resp.Settings)
	s.server.emitStatus(s, resp.Settings)
	return nil
}

// exchange sends one signed request and reads the response
// (remote_client.exchange_on_socket). name "" is the unnamed identify.
func (s *Session) exchange(p protocol.RequestParams, name string) (*protocol.Response, error) {
	p.Secret = s.secret
	p.ReqID = reqID()
	p.Name = name
	p.Timestamp = s.server.now().Unix()
	body, err := protocol.BuildRequest(p)
	if err != nil {
		return nil, err
	}
	s.conn.SetDeadline(time.Now().Add(s.server.exchangeTimeout()))
	if err := protocol.WriteFrame(s.conn, body); err != nil {
		return nil, err
	}
	reply, err := protocol.ReadFrame(s.reader)
	if err != nil {
		return nil, err
	}
	resp, err := protocol.ParseResponse(reply, s.secret, protocol.ResponseOptions{
		ExpectedName:    name,
		ExpectedVersion: protocol.ClientDefaultVersion,
	}, s.server.now().Unix())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.lastSeen = s.server.now()
	s.mu.Unlock()
	return resp, nil
}
