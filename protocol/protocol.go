package protocol

import (
	"fmt"
	"time"
)

const (
	// ProtocolVersion is the only wire version.
	ProtocolVersion = 3
	// ClientDefaultVersion is what clients send.
	ClientDefaultVersion = 3

	DefaultLogTailLines = 500
	MaxLogTailLines     = 5000

	DefaultShutdownSeconds = 60
	MinDailyLimit          = 1
	MaxDailyLimit          = 1440
)

// SupportedVersion reports whether v is a wire version this package speaks.
func SupportedVersion(v int64) bool { return v == ProtocolVersion }

// Entry is an ordered name/description pair.
type Entry struct{ Name, Description string }

// Actions lists every action in display order.
var Actions = []Entry{
	{"get", `get a single variable or "settings" to get all variables`},
	{"set", "set a single variable to a new value"},
	{"clear", "clear a single variable"},
	{"lock", "immediately lock"},
	{"unlock", "release a manual lock"},
	{"extend", "add minutes of extra allowance for today (val=minutes)"},
	{"message", "show a popup message on the PC (val=text)"},
	{"shutdown", "shut down the PC after a warning (val=seconds, default 60)"},
	{"list_capabilities", "describe supported actions and variables"},
	{"get_logs", "read the agent log file (tail=N lines, default 500, max 5000)"},
}

// Variables lists every readable variable in display order.
var Variables = []Entry{
	{"name", "read-only, name of computer"},
	{"status", "read-only, the lock status (LOCKED/UNLOCKED)"},
	{"current_user", "read-only, the username of the currently logged-in user"},
	{"daily_limit", "current daily limit in minutes"},
	{"bed_time", "bed time, at which the computer will be locked"},
	{"manual_lock", "boolean, whether a manual lock is in effect"},
	{"wake_time", "time, at which the computer can be used the following morning"},
	{"cumulative_extension", "read-only, a running total of extension seconds today"},
	{"accumulated_seconds", "read-only, a running total of active seconds used today"},
	{"time_remaining", "read-only, minutes remaining today (or null)"},
	{"enforcement_active", "read-only, whether schedule/limit enforcement is active"},
	{"enforcement_reason", "read-only, brief reason when enforcement is active (or null)"},
	{"access_status", "read-only, brief overall access status for the parent panel"},
}

// WriteActions must carry a "name" matching the agent's hostname.
var WriteActions = map[string]bool{
	"set": true, "clear": true, "lock": true, "unlock": true,
	"extend": true, "shutdown": true, "message": true,
}

func hasAction(name string) bool {
	for _, a := range Actions {
		if a.Name == name {
			return true
		}
	}
	return false
}

func hasVariable(name string) bool {
	for _, v := range Variables {
		if v.Name == name {
			return true
		}
	}
	return false
}

// WritableVariables are the variables the "set" action may change.
var WritableVariables = map[string]bool{
	"daily_limit": true, "bed_time": true, "manual_lock": true, "wake_time": true,
}

// ClearableVariables are the variables the "clear" action may reset.
var ClearableVariables = map[string]bool{
	"daily_limit": true, "bed_time": true, "manual_lock": true, "cumulative_extension": true,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func splitAuth(nodes []Node) (auth *Node, rest []Node) {
	for i := range nodes {
		if nodes[i].Name == "auth" && auth == nil {
			n := nodes[i]
			auth = &n
		} else {
			rest = append(rest, nodes[i])
		}
	}
	return auth, rest
}

func authNode(signed []Node, secret string) Node {
	signature := ComputeSignature(DeriveKey(secret), Serialize(signed))
	return Block("auth",
		N("algorithm", Algorithm),
		N("key_id", DefaultKeyID),
		N("signature", signature),
	)
}

// lastFields maps node names to their first argument; the last duplicate wins.
func lastFields(nodes []Node) map[string]Value {
	m := make(map[string]Value, len(nodes))
	for _, n := range nodes {
		m[n.Name] = n.Arg()
	}
	return m
}

// VerifyFrame validates the auth, timestamp and nonce of a parsed frame.
//
// It returns the frame's name (nil for an unnamed read-only frame). The caller
// must still match the name against the expected hostname.
func VerifyFrame(nodes []Node, secret string, reqID *string, now int64) (*string, error) {
	auth, rest := splitAuth(nodes)
	fields := lastFields(rest)

	var name *string
	if v := fields["name"]; v != nil {
		name = Ptr(pyStr(v))
	}

	if auth == nil {
		return nil, perr(AuthenticationRequired, "missing auth block", reqID)
	}
	timestamp, nonce := fields["timestamp"], fields["nonce"]
	if timestamp == nil {
		return nil, perr(AuthenticationRequired, "missing timestamp", reqID)
	}
	if nonce == nil {
		return nil, perr(AuthenticationRequired, "missing nonce", reqID)
	}
	ts, ok := timestamp.(int64)
	if !ok {
		return nil, perr(InvalidRequest, "timestamp must be an integer", reqID)
	}
	if !IsValidNonce(nonce) {
		return nil, perr(InvalidRequest, "nonce must be hex randomness", reqID)
	}
	signature := auth.ChildMap()["signature"]
	if signature == nil {
		return nil, perr(AuthenticationRequired, "missing signature", reqID)
	}
	if !VerifySignature(DeriveKey(secret), Serialize(rest), pyStr(signature)) {
		return nil, perr(AuthenticationFailed, "signature did not verify.\n", reqID)
	}
	if !TimestampInWindow(ts, now) {
		return nil, perr(StaleTimestamp, "timestamp outside allowed window", reqID)
	}
	return name, nil
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

// RequestParams describes a request to build. Zero values mean "absent" for
// ReqID, Name, Var, Val and Tail, and "now"/"random"/"default" for Timestamp,
// Nonce and Version.
type RequestParams struct {
	Action    string
	Secret    string
	Var       string
	Val       Value
	ReqID     string
	Name      string // target agent hostname; required for write actions
	Timestamp int64
	Nonce     string
	Version   int64
	Tail      int64
}

// BuildRequest builds and signs a request body for a client to send.
func BuildRequest(p RequestParams) (string, error) {
	version := p.Version
	if version == 0 {
		version = ClientDefaultVersion
	}
	if !SupportedVersion(version) {
		return "", fmt.Errorf("unsupported protocol version: %d", version)
	}
	ts := p.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}
	nonce := p.Nonce
	if nonce == "" {
		nonce = MakeNonce()
	}
	nodes := []Node{N("v", version)}
	if p.ReqID != "" {
		nodes = append(nodes, N("id", p.ReqID))
	}
	if p.Name != "" {
		nodes = append(nodes, N("name", p.Name))
	}
	nodes = append(nodes, N("timestamp", ts), N("nonce", nonce), N("action", p.Action))
	if p.Var != "" {
		nodes = append(nodes, N("var", p.Var))
	}
	if p.Val != nil {
		nodes = append(nodes, N("val", p.Val))
	}
	if p.Tail != 0 {
		nodes = append(nodes, N("tail", p.Tail))
	}
	nodes = append(nodes, authNode(nodes, p.Secret))
	return Serialize(nodes), nil
}

// Request is a parsed, authenticated request.
type Request struct {
	Version   int64
	ID        *string
	Action    string
	Var       *string
	Val       Value
	Name      *string
	Timestamp int64
	Nonce     string
	Tail      *int64
}

// ParseRequest parses, authenticates and structurally validates a request.
// hostname is the agent's own name, used to reject frames addressed to a
// different PC. Value-level checks belong to the dispatcher.
func ParseRequest(body, secret, hostname string, now int64) (*Request, error) {
	nodes, err := Parse(body)
	if err != nil {
		return nil, perr(InvalidRequest, "could not parse request", nil)
	}

	var nonAuth []Node
	for _, n := range nodes {
		if n.Name != "auth" {
			nonAuth = append(nonAuth, n)
		}
	}
	fields := lastFields(nonAuth)

	var reqID *string
	if v := fields["id"]; v != nil {
		reqID = Ptr(pyStr(v))
	}

	rawVersion := fields["v"]
	if rawVersion == nil {
		return nil, perr(InvalidRequest, "missing protocol version", reqID)
	}
	version, ok := rawVersion.(int64)
	if !ok {
		return nil, perr(InvalidRequest, "protocol version must be an integer", reqID)
	}
	if !SupportedVersion(version) {
		return nil, perr(UnsupportedVersion,
			fmt.Sprintf("protocol version %s is not supported", pyRepr(version)), reqID)
	}

	// Authenticate before acting on anything in the frame.
	name, err := VerifyFrame(nodes, secret, reqID, now)
	if err != nil {
		return nil, err
	}

	rawAction := fields["action"]
	action, isString := rawAction.(string)
	if !isString || !hasAction(action) {
		return nil, perr(UnknownAction, fmt.Sprintf("unknown action: %s", pyRepr(rawAction)), reqID)
	}

	// Destination binding: a named frame must target this agent; write
	// actions must always be named.
	if name != nil && *name != hostname {
		return nil, perr(AuthenticationFailed, "frame addressed to a different agent", reqID)
	}
	if WriteActions[action] && name == nil {
		return nil, perr(AuthenticationRequired,
			fmt.Sprintf("%s requires a name identifying the target agent", action), reqID)
	}

	var variable *string
	if v := fields["var"]; v != nil {
		variable = Ptr(pyStr(v))
	}
	val := fields["val"]

	switch {
	case action == "get":
		if variable == nil {
			return nil, perr(InvalidRequest, "get requires a variable", reqID)
		}
		if *variable != "settings" && !hasVariable(*variable) {
			return nil, perr(UnknownVariable, "unknown variable: "+*variable, reqID)
		}
	case action == "set" || action == "clear":
		if variable == nil {
			return nil, perr(InvalidRequest, action+" requires a variable", reqID)
		}
		if !hasVariable(*variable) {
			return nil, perr(UnknownVariable, "unknown variable: "+*variable, reqID)
		}
		if action == "set" && val == nil {
			return nil, perr(InvalidRequest, "set requires a value", reqID)
		}
	case action == "extend" && val == nil:
		return nil, perr(InvalidRequest, "extend requires minutes", reqID)
	case action == "message" && val == nil:
		return nil, perr(InvalidRequest, "message requires text", reqID)
	}

	var tail *int64
	if raw := fields["tail"]; raw != nil {
		n, err := ParseInt(raw, reqID)
		if err != nil {
			return nil, err
		}
		if n < 1 {
			return nil, perr(InvalidValue, "tail must be at least 1", reqID)
		}
		if n > MaxLogTailLines {
			return nil, perr(InvalidValue,
				fmt.Sprintf("tail must be at most %d", MaxLogTailLines), reqID)
		}
		tail = &n
	}

	nonce, _ := fields["nonce"].(string)
	return &Request{
		Version:   version,
		ID:        reqID,
		Action:    action,
		Var:       variable,
		Val:       val,
		Name:      name,
		Timestamp: fields["timestamp"].(int64),
		Nonce:     nonce,
		Tail:      tail,
	}, nil
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

// OKContent is a successful response carrying a scalar result.
func OKContent(result Value) []Node { return []Node{N("status", "ok"), N("result", result)} }

// BlockContent is a successful response carrying a block (settings, logs, ...).
func BlockContent(block Node) []Node { return []Node{N("status", "ok"), block} }

// ErrorContent is a failure response.
func ErrorContent(code, message string) []Node {
	return []Node{
		N("status", "failure"),
		Block("error", N("code", code), N("message", message)),
	}
}

// CapabilitiesContent describes the supported actions and variables.
func CapabilitiesContent() []Node {
	actions := Node{Name: "actions"}
	for _, a := range Actions {
		actions.Children = append(actions.Children, N(a.Name, a.Description))
	}
	values := Node{Name: "values"}
	for _, v := range Variables {
		values.Children = append(values.Children, N(v.Name, v.Description))
	}
	return []Node{N("status", "ok"), actions, values}
}

// ResponseParams carries the envelope fields for SignResponse. Zero values
// mean absent (ReqID), now (Timestamp), random (Nonce) or default (Version).
type ResponseParams struct {
	Secret    string
	Hostname  string
	ReqID     string
	Timestamp int64
	Nonce     string
	Version   int64
}

// SignResponse wraps response content in a signed envelope. Every response
// carries the agent's own name and is signed with the shared key.
func SignResponse(content []Node, p ResponseParams) (string, error) {
	version := p.Version
	if version == 0 {
		version = ClientDefaultVersion
	}
	if !SupportedVersion(version) {
		return "", fmt.Errorf("unsupported protocol version: %d", version)
	}
	ts := p.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}
	nonce := p.Nonce
	if nonce == "" {
		nonce = MakeNonce()
	}
	nodes := []Node{N("v", version)}
	if p.ReqID != "" {
		nodes = append(nodes, N("id", p.ReqID))
	}
	nodes = append(nodes, N("name", p.Hostname), N("timestamp", ts), N("nonce", nonce))
	nodes = append(nodes, content...)
	nodes = append(nodes, authNode(nodes, p.Secret))
	return Serialize(nodes), nil
}

// LogsResult is the parsed "logs" block of a get_logs response.
type LogsResult struct {
	Path      string
	Truncated bool
	Lines     []string
}

// Response is a parsed, authenticated response, for clients.
type Response struct {
	Version      int64
	ID           *string
	Status       string
	Result       Value
	ErrorCode    Value
	ErrorMessage Value
	Settings     map[string]Value // nil when there was no settings block
	Logs         *LogsResult
	Name         *string
	Timestamp    int64
	Nonce        string
}

// OK reports whether the response status is "ok".
func (r *Response) OK() bool { return r.Status == "ok" }

// Text is a human-readable one-liner for CLI/panel display.
func (r *Response) Text() string {
	switch {
	case !r.OK():
		return pyStr(r.ErrorCode) + ": " + pyStr(r.ErrorMessage)
	case r.Settings != nil:
		return "ok"
	case r.Result == nil:
		return ""
	}
	return pyStr(r.Result)
}

// ResponseOptions are the optional expectations for ParseResponse.
type ResponseOptions struct {
	ExpectedName    string // "" means no expectation
	ExpectedVersion int64  // 0 means no expectation
}

// ParseResponse parses and authenticates a response body received by a
// client. When ExpectedName is set (every request after discovery) the
// reported name must match it, defeating attempts to pass off one PC's signed
// response as another's.
func ParseResponse(body, secret string, opts ResponseOptions, now int64) (*Response, error) {
	nodes, err := Parse(body)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		if n.Name != "auth" {
			byName[n.Name] = n
		}
	}

	var reqID *string
	if n, ok := byName["id"]; ok && n.Arg() != nil {
		reqID = Ptr(pyStr(n.Arg()))
	}

	var rawVersion Value
	if n, ok := byName["v"]; ok {
		rawVersion = n.Arg()
	}
	version, isInt := rawVersion.(int64)
	if !isInt || !SupportedVersion(version) {
		return nil, perr(UnsupportedVersion,
			fmt.Sprintf("protocol version %s is not supported", pyRepr(rawVersion)), reqID)
	}
	if opts.ExpectedVersion != 0 && version != opts.ExpectedVersion {
		return nil, perr(UnsupportedVersion,
			fmt.Sprintf("expected protocol version %d, got %d", opts.ExpectedVersion, version), reqID)
	}

	name, err := VerifyFrame(nodes, secret, reqID, now)
	if err != nil {
		return nil, err
	}
	if opts.ExpectedName != "" && (name == nil || *name != opts.ExpectedName) {
		return nil, perr(AuthenticationFailed, "response came from an unexpected agent", reqID)
	}

	resp := &Response{Version: version, ID: reqID, Status: "failure", Name: name}
	if n, ok := byName["status"]; ok {
		resp.Status = pyStr(n.Arg())
	}
	if n, ok := byName["error"]; ok {
		m := n.ChildMap()
		resp.ErrorCode, resp.ErrorMessage = m["code"], m["message"]
	}
	if n, ok := byName["settings"]; ok {
		resp.Settings = n.ChildMap()
	}
	if n, ok := byName["logs"]; ok {
		fields := n.ChildMap()
		logs := &LogsResult{Lines: []string{}, Truncated: pyTruthy(fields["truncated"])}
		if p, present := fields["path"]; present {
			logs.Path = pyStr(p)
		}
		for _, c := range n.Children {
			if c.Name == "lines" {
				for _, a := range c.Args {
					logs.Lines = append(logs.Lines, pyStr(a))
				}
				break
			}
		}
		resp.Logs = logs
	}
	if n, ok := byName["result"]; ok {
		resp.Result = n.Arg()
	}
	if n, ok := byName["timestamp"]; ok {
		resp.Timestamp, _ = n.Arg().(int64)
	}
	if n, ok := byName["nonce"]; ok {
		resp.Nonce, _ = n.Arg().(string)
	}
	return resp, nil
}
