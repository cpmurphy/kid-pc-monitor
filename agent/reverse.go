package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kidpcmonitor/dispatcher"
	"kidpcmonitor/netinfo"
	"kidpcmonitor/protocol"
	"kidpcmonitor/secrets"
)

// Reverse-connection settings, as agent_sync_client.py.
const (
	DefaultPanelPort   = 5000
	DefaultReversePort = 9998
	PanelURLEnv        = "KID_PC_MONITOR_PANEL_URL"
	CacheFile          = "panel_url.txt"
	DiscoveryMarker    = "kid-pc-monitor-panel"

	discoveryTimeout  = 500 * time.Millisecond
	connectTimeout    = 10 * time.Second
	frameTimeout      = 120 * time.Second
	reconnectMin      = 2 * time.Second
	reconnectMax      = 60 * time.Second
	idleRetry         = 30 * time.Second
	cycleFailureRetry = 15 * time.Second
	maxDiscoveryHosts = 254
)

// ReverseClient keeps an outbound native-protocol session open to the parent
// panel and answers its requests with Control. Only Control and DataDir are
// required.
type ReverseClient struct {
	Control dispatcher.Control
	// DataDir holds the panel URL cache (panel_url.txt).
	DataDir string
	Logger  *slog.Logger
	// LoadSecret returns the shared secret. Defaults to
	// secrets.LoadSharedSecret; it is called on every connection attempt, so
	// a secret set after start-up is picked up.
	LoadSecret func() (string, error)
	// LocalIP is the address whose /24 is scanned. Defaults to netinfo.LocalIP.
	LocalIP func() string
	// Now supplies protocol timestamps. Defaults to time.Now.
	Now func() time.Time

	panelURL             string
	loggedConnectFailure bool
}

func (c *ReverseClient) log() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *ReverseClient) infof(format string, args ...any) { c.log().Info(fmt.Sprintf(format, args...)) }
func (c *ReverseClient) warnf(format string, args ...any) { c.log().Warn(fmt.Sprintf(format, args...)) }
func (c *ReverseClient) debugf(format string, args ...any) {
	c.log().Debug(fmt.Sprintf(format, args...))
}

// Run connects, serves and reconnects until ctx is done. Cancelling ctx
// closes any open session.
func (c *ReverseClient) Run(ctx context.Context) {
	for ctx.Err() == nil {
		delay := c.cycle(ctx)
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}

// cycle is one ConnectOnce; a panic is logged and retried later rather than
// ending the client (Python's "Reverse TCP cycle failed").
func (c *ReverseClient) cycle(ctx context.Context) (delay time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			c.log().Error(fmt.Sprintf("Reverse TCP cycle failed: %v", r))
			delay = cycleFailureRetry
		}
	}()
	return c.ConnectOnce(ctx)
}

// ConnectOnce discovers the panel if needed, connects and serves until the
// session ends. It returns how long to wait before the next attempt.
func (c *ReverseClient) ConnectOnce(ctx context.Context) time.Duration {
	load := c.LoadSecret
	if load == nil {
		load = secrets.LoadSharedSecret
	}
	secret, err := load()
	if err != nil || secret == "" {
		c.log().Error("No shared secret configured; reverse TCP disabled")
		return idleRetry
	}

	if c.panelURL == "" {
		c.panelURL = c.discoverPanelURL(ctx)
		if c.panelURL == "" {
			c.debugf("No Kid PC Monitor panel discovered on this LAN")
			return idleRetry
		}
	}

	host, port, useTLS, err := c.reverseEndpoint(ctx, c.panelURL)
	var conn net.Conn
	if err == nil {
		conn, err = openReverse(ctx, host, port, useTLS)
	}
	if err != nil {
		c.logConnectFailure(err)
		c.panelURL = ""
		return reconnectDelay()
	}

	c.loggedConnectFailure = false
	tlsNote := ""
	if useTLS {
		tlsNote = " (TLS)"
	}
	c.infof("Connected reverse session to panel %s:%d%s", host, port, tlsNote)
	c.serve(ctx, conn, secret)
	return reconnectDelay()
}

func reconnectDelay() time.Duration {
	d := reconnectMin + time.Duration(rand.Float64()*float64(3*time.Second))
	return min(d, reconnectMax)
}

func (c *ReverseClient) logConnectFailure(err error) {
	if c.loggedConnectFailure {
		c.debugf("Reverse connect failed (%v); rediscovering", err)
		return
	}
	c.warnf("Reverse connect failed (%v); rediscovering", err)
	c.loggedConnectFailure = true
}

// serve answers frames until the panel hangs up, the connection fails or ctx
// is done. It closes conn.
func (c *ReverseClient) serve(ctx context.Context, conn net.Conn, secret string) {
	var once sync.Once
	closeConn := func() { once.Do(func() { conn.Close() }) }
	defer closeConn()
	stop := context.AfterFunc(ctx, closeConn)
	defer stop()

	now := c.Now
	if now == nil {
		now = time.Now
	}
	handler := dispatcher.Handler(c.Control)
	br := bufio.NewReader(conn)
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(frameTimeout))
		body, err := protocol.ReadFrame(br)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var pe *protocol.ProtocolError
			switch {
			case protocol.IsClosedBeforeFrame(err):
				c.infof("Panel closed reverse connection")
			case errors.As(err, &pe):
				c.warnf("Reverse framing error: %s", pe.Message)
			default:
				c.infof("Reverse connection idle/error: %v", err)
			}
			return
		}
		reply := protocol.HandleRequest(body, secret, c.Control.Hostname(), now().Unix(), handler)
		_ = conn.SetWriteDeadline(time.Now().Add(frameTimeout))
		if err := protocol.WriteFrame(conn, reply); err != nil {
			if ctx.Err() == nil {
				c.warnf("Reverse send failed: %v", err)
			}
			return
		}
	}
}

// --- discovery ----------------------------------------------------------------

// discoveryClient talks to LAN panels only, so it ignores proxy settings.
var discoveryClient = &http.Client{
	Timeout:   discoveryTimeout,
	Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: discoveryTimeout},
}

// NormalizePanelURL trims a configured panel URL and adds http:// when it has
// no scheme.
func NormalizePanelURL(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	return u
}

// discoverPayload fetches <base>/agent/v1/discover and returns it when it
// identifies a Kid PC Monitor panel.
func discoverPayload(ctx context.Context, base string) map[string]any {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/agent/v1/discover", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := discoveryClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	if payload["service"] != DiscoveryMarker {
		return nil
	}
	return payload
}

func (c *ReverseClient) cachePath() string { return filepath.Join(c.DataDir, CacheFile) }

func (c *ReverseClient) readCachedPanelURL() string {
	b, err := os.ReadFile(c.cachePath())
	if err != nil {
		return ""
	}
	return NormalizePanelURL(string(b))
}

func (c *ReverseClient) writeCachedPanelURL(u string) {
	if err := os.WriteFile(c.cachePath(), []byte(strings.TrimRight(u, "/")+"\n"), 0o644); err != nil {
		c.debugf("Could not write panel URL cache: %v", err)
	}
}

// discoverPanelURL tries $KID_PC_MONITOR_PANEL_URL, then the cached URL, then
// port 5000 on every host of the local /24 in random order. It returns "" when
// nothing answers.
func (c *ReverseClient) discoverPanelURL(ctx context.Context) string {
	for _, candidate := range []string{NormalizePanelURL(os.Getenv(PanelURLEnv)), c.readCachedPanelURL()} {
		if candidate != "" && discoverPayload(ctx, candidate) != nil {
			c.writeCachedPanelURL(candidate)
			return candidate
		}
	}

	localIP := c.LocalIP
	if localIP == nil {
		localIP = netinfo.LocalIP
	}
	hosts := subnetHosts(localIP())
	rand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
	for _, ip := range hosts {
		if ctx.Err() != nil {
			return ""
		}
		candidate := fmt.Sprintf("http://%s:%d", ip, DefaultPanelPort)
		if discoverPayload(ctx, candidate) != nil {
			c.infof("Discovered Kid PC Monitor panel at %s", candidate)
			c.writeCachedPanelURL(candidate)
			return candidate
		}
	}
	return ""
}

// subnetHosts lists the usable addresses of ip's /24 (.1 to .254), or nil
// when ip is not IPv4.
func subnetHosts(ip string) []string {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return nil
	}
	hosts := make([]string, 0, maxDiscoveryHosts)
	for i := 1; i <= maxDiscoveryHosts; i++ {
		hosts = append(hosts, net.IPv4(v4[0], v4[1], v4[2], byte(i)).String())
	}
	return hosts
}

// reverseEndpoint is where the panel listens for agents: the panel URL's
// host, the reverse_port it advertises (9998 by default), and TLS when the
// panel URL is https.
func (c *ReverseClient) reverseEndpoint(ctx context.Context, panelURL string) (host string, port int, useTLS bool, err error) {
	u, err := url.Parse(panelURL)
	if err != nil || u.Hostname() == "" {
		return "", 0, false, fmt.Errorf("Invalid panel URL: %s", panelURL)
	}
	host = strings.ToLower(u.Hostname())
	port = advertisedPort(discoverPayload(ctx, panelURL))
	if port < 1 || port > 65535 {
		return "", 0, false, fmt.Errorf("panel advertised invalid reverse port %d", port)
	}
	return host, port, u.Scheme == "https", nil
}

// advertisedPort reads reverse_port as Python's int() would: an integer,
// a float (truncated), a numeric string or a bool; 9998 otherwise.
func advertisedPort(payload map[string]any) int {
	raw, ok := payload["reverse_port"]
	if !ok {
		return DefaultReversePort
	}
	switch v := raw.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return DefaultReversePort
		}
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	case bool:
		if v {
			return 1
		}
		return 0
	}
	return DefaultReversePort
}

// openReverse dials the panel. With TLS it verifies the certificate first and,
// when the handshake itself fails (LAN panels often use a locally generated
// certificate), reconnects without verification, as the Python agent does.
func openReverse(ctx context.Context, host string, port int, useTLS bool) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: connectTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil || !useTLS {
		return raw, err
	}
	conn, err := handshake(ctx, raw, &tls.Config{ServerName: host})
	if err == nil {
		return conn, nil
	}
	raw.Close()
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return nil, err // a network failure, not a certificate problem
	}
	raw, err = dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn, err = handshake(ctx, raw, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // see doc
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func handshake(ctx context.Context, raw net.Conn, cfg *tls.Config) (net.Conn, error) {
	conn := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, frameTimeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	return conn, nil
}
