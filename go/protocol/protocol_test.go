package protocol

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "test-shared-secret"
	testHost   = "kid-pc"
	testNow    = int64(1_710_000_000)
)

func reader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func TestReadFrame(t *testing.T) {
	r := reader("5\nhello3\nabc")
	for _, want := range []string{"hello", "abc"} {
		got, err := ReadFrame(r)
		if err != nil || got != want {
			t.Fatalf("ReadFrame = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := ReadFrame(r); !IsClosedBeforeFrame(err) {
		t.Errorf("EOF before any bytes: err = %v, want closed-before-frame", err)
	}
}

func TestReadFrameErrors(t *testing.T) {
	for name, in := range map[string]string{
		"not a frame":       "hello\nworld",
		"closed mid prefix": "12",
		"closed mid body":   "10\nabc",
		"too large":         "65537\nabc",
		"invalid utf-8":     "2\n\xff\xfe",
		"negative":          "-1\nab",
	} {
		_, err := ReadFrame(reader(in))
		if CodeOf(err) != InvalidRequest {
			t.Errorf("%s: err = %v, want invalid_request", name, err)
		}
	}
}

func TestWriteFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, "v 3"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(bufio.NewReader(&buf))
	if err != nil || got != "v 3" {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	if _, err := ReadFrame(bufio.NewReader(&buf)); err != io.EOF && !IsClosedBeforeFrame(err) {
		t.Errorf("drained buffer: %v", err)
	}
}

func okDispatcher(req *Request) ([]Node, error) {
	switch req.Action {
	case "lock":
		return OKContent("locked"), nil
	case "get":
		return OKContent(testHost), nil
	case "shutdown":
		return nil, perr(InvalidValue, "seconds must not be negative", req.ID)
	}
	return nil, io.ErrUnexpectedEOF
}

func handle(t *testing.T, body string) *Response {
	t.Helper()
	out := HandleRequest(body, testSecret, testHost, testNow, okDispatcher)
	resp, err := ParseResponse(out, testSecret, ResponseOptions{}, time.Now().Unix())
	if err != nil {
		t.Fatalf("response did not verify: %v\n%s", err, out)
	}
	if resp.Name == nil || *resp.Name != testHost {
		t.Errorf("response name = %v, want %s", resp.Name, testHost)
	}
	return resp
}

func request(t *testing.T, p RequestParams) string {
	t.Helper()
	p.Secret, p.Timestamp, p.Nonce = testSecret, testNow, strings.Repeat("ab", 16)
	body, err := BuildRequest(p)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHandleRequest(t *testing.T) {
	resp := handle(t, request(t, RequestParams{Action: "lock", Name: testHost, ReqID: "r1"}))
	if !resp.OK() || resp.Result != "locked" || resp.ID == nil || *resp.ID != "r1" {
		t.Errorf("lock: %+v", resp)
	}

	resp = handle(t, request(t, RequestParams{Action: "get", Var: "name"}))
	if resp.Text() != testHost {
		t.Errorf("discovery get: %+v", resp)
	}

	// Dispatcher-supplied protocol errors keep their code and request id.
	resp = handle(t, request(t, RequestParams{Action: "shutdown", Name: testHost, ReqID: "s1"}))
	if resp.OK() || resp.ErrorCode != InvalidValue || resp.ID == nil || *resp.ID != "s1" {
		t.Errorf("shutdown: %+v", resp)
	}

	// Anything else becomes internal_error.
	resp = handle(t, request(t, RequestParams{Action: "unlock", Name: testHost}))
	if resp.ErrorCode != InternalError {
		t.Errorf("unlock: %+v", resp)
	}
}

func TestHandleRequestRejectsBadFrames(t *testing.T) {
	good := request(t, RequestParams{Action: "lock", Name: testHost})
	for name, tc := range map[string]struct {
		body string
		code string
	}{
		"tampered":        {strings.Replace(good, "action lock", "action unlock", 1), AuthenticationFailed},
		"other host":      {request(t, RequestParams{Action: "lock", Name: "other-pc"}), AuthenticationFailed},
		"unnamed write":   {request(t, RequestParams{Action: "lock"}), AuthenticationRequired},
		"old version":     {"v 2\nid x\naction get", UnsupportedVersion},
		"bool version":    {"v true\naction get", InvalidRequest},
		"hostile nesting": {strings.Repeat("a {", 5000), InvalidRequest},
		"trailing slash":  {"v 3\nfoo \"a\\", InvalidRequest},
		"garbage":         {"\x00\x01 not kdl {{", InvalidRequest},
		"empty":           {"", InvalidRequest},
	} {
		resp := handle(t, tc.body)
		if resp.OK() || resp.ErrorCode != tc.code {
			t.Errorf("%s: error code = %v, want %s", name, resp.ErrorCode, tc.code)
		}
		if resp.Version != ProtocolVersion {
			t.Errorf("%s: response version = %d", name, resp.Version)
		}
	}
}

func TestMessageWithTrailingNewlineSurvives(t *testing.T) {
	body := request(t, RequestParams{Action: "message", Name: testHost, Val: "hello\n"})
	req, err := ParseRequest(body, testSecret, testHost, testNow)
	if err != nil || req.Val != "hello\n" {
		t.Fatalf("ParseRequest = %+v, %v", req, err)
	}
}

func TestPyInt(t *testing.T) {
	for in, want := range map[string]int64{
		"0": 0, "-7": -7, "+5": 5, "007": 7, "1_000": 1000, " 12 ": 12,
		"9223372036854775807": 1<<63 - 1, "-9223372036854775808": -1 << 63,
	} {
		if got, st := pyInt(in); st != intOK || got != want {
			t.Errorf("pyInt(%q) = %d, %v; want %d", in, got, st, want)
		}
	}
	for _, in := range []string{"", "-", "+", "1.5", "0x10", "1e5", "_1", "1_", "1__0", "12abc", "٣"} {
		if _, st := pyInt(in); st != intNotInt {
			t.Errorf("pyInt(%q) status = %v, want not-int", in, st)
		}
	}
	for _, in := range []string{"9223372036854775808", "-9223372036854775809", "99999999999999999999999"} {
		if _, st := pyInt(in); st != intOverflow {
			t.Errorf("pyInt(%q) status = %v, want overflow", in, st)
		}
	}
}

func TestIntegerOverflowIsParseError(t *testing.T) {
	if _, err := Parse("a 99999999999999999999999"); CodeOf(err) != InvalidRequest {
		t.Errorf("err = %v, want invalid_request", err)
	}
}
