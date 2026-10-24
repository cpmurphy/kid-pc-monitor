package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The golden vectors are generated from the Python implementation by
// tests/protocol_vectors_gen.py. Every case here must agree with it.

type obj = map[string]any

func vectorsPath() string {
	return filepath.Join("..", "..", "testdata", "protocol", "vectors.json")
}

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decoding vectors: %v", err)
	}
	return norm(v).(obj)
}

// norm turns json.Number into int64 so decoded values match Value.
func norm(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			panic(err)
		}
		return n
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = norm(x[i])
		}
		return out
	case map[string]any:
		out := make(obj, len(x))
		for k, e := range x {
			out[k] = norm(e)
		}
		return out
	}
	return v
}

// canon round-trips v through JSON so Go values compare equal to decoded vectors.
func canon(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return norm(out)
}

func cases(t *testing.T, v obj, section string) []obj {
	t.Helper()
	list, ok := v[section].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("section %q missing or empty", section)
	}
	out := make([]obj, len(list))
	for i, c := range list {
		out[i] = c.(obj)
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func i64(v any) int64 {
	n, _ := v.(int64)
	return n
}

func nodesFromJSON(v any) []Node {
	list, _ := v.([]any)
	nodes := make([]Node, 0, len(list))
	for _, e := range list {
		m := e.(obj)
		n := Node{Name: str(m["name"])}
		n.Args = append(n.Args, m["args"].([]any)...)
		n.Children = nodesFromJSON(m["children"])
		if len(n.Children) == 0 {
			n.Children = nil
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func nodesToJSON(nodes []Node) []any {
	out := make([]any, 0, len(nodes))
	for _, n := range nodes {
		m := obj{"name": n.Name, "args": append([]any{}, n.Args...)}
		if len(n.Children) > 0 {
			m["children"] = nodesToJSON(n.Children)
		}
		out = append(out, m)
	}
	return out
}

func ptrJSON(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func optString(v any) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

func TestVectorConstants(t *testing.T) {
	c := loadVectors(t)["constants"].(obj)
	if i64(c["protocol_version"]) != ProtocolVersion {
		t.Errorf("protocol_version")
	}
	if i64(c["max_frame_bytes"]) != MaxFrameBytes {
		t.Errorf("max_frame_bytes")
	}
	if i64(c["max_log_tail_lines"]) != MaxLogTailLines {
		t.Errorf("max_log_tail_lines")
	}
	if i64(c["timestamp_window_seconds"]) != TimestampWindowSeconds {
		t.Errorf("timestamp_window_seconds")
	}
	if str(c["key_id"]) != DefaultKeyID || str(c["algorithm"]) != Algorithm {
		t.Errorf("key_id/algorithm")
	}
	var actions, variables []any
	actionDesc, varDesc := obj{}, obj{}
	for _, a := range Actions {
		actions = append(actions, a.Name)
		actionDesc[a.Name] = a.Description
	}
	for _, v := range Variables {
		variables = append(variables, v.Name)
		varDesc[v.Name] = v.Description
	}
	for key, got := range map[string]any{
		"actions": actions, "action_descriptions": actionDesc,
		"variables": variables, "variable_descriptions": varDesc,
	} {
		if !reflect.DeepEqual(got, c[key]) {
			t.Errorf("%s differ:\n go:     %v\n python: %v", key, got, c[key])
		}
	}
	var writes []any
	for _, a := range Actions {
		if WriteActions[a.Name] {
			writes = append(writes, a.Name)
		}
	}
	if len(writes) != len(WriteActions) {
		t.Errorf("WriteActions has entries that are not actions")
	}
	want := map[string]bool{}
	for _, w := range c["write_actions"].([]any) {
		want[w.(string)] = true
	}
	if !reflect.DeepEqual(want, WriteActions) {
		t.Errorf("write_actions: go %v, python %v", WriteActions, want)
	}
}

func TestVectorFormatValue(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_value") {
		if got := FormatValue(c["value"]); got != c["text"] {
			t.Errorf("FormatValue(%#v) = %q, want %q", c["value"], got, c["text"])
		}
	}
}

func TestVectorSerialize(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "serialize") {
		t.Run(str(c["name"]), func(t *testing.T) {
			if got := Serialize(nodesFromJSON(c["nodes"])); got != c["text"] {
				t.Errorf("got %q, want %q", got, c["text"])
			}
		})
	}
}

func TestVectorParse(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "parse") {
		t.Run(str(c["name"]), func(t *testing.T) {
			nodes, err := Parse(str(c["text"]))
			if want, isErr := c["error"]; isErr {
				if CodeOf(err) != want {
					t.Fatalf("error = %v, want code %v", err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := canon(t, nodesToJSON(nodes)); !reflect.DeepEqual(got, c["nodes"]) {
				t.Errorf("got %v\nwant %v", got, c["nodes"])
			}
			if !namesAreBare(nodes) {
				return // node names are emitted verbatim, so only bare names round-trip
			}
			again, err := Parse(Serialize(nodes))
			if err != nil || !reflect.DeepEqual(canon(t, nodesToJSON(again)), c["nodes"]) {
				t.Errorf("round trip changed the document: %v", err)
			}
		})
	}
}

func TestVectorFrameEncode(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "frame_encode") {
		if got := hex.EncodeToString(EncodeFrame(str(c["body"]))); got != c["frame_hex"] {
			t.Errorf("EncodeFrame(%q) = %s, want %s", c["body"], got, c["frame_hex"])
		}
	}
}

func TestVectorFrameInspect(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "frame_inspect") {
		t.Run(str(c["name"]), func(t *testing.T) {
			in, _ := hex.DecodeString(str(c["input_hex"]))
			status, body, rest, err := InspectFrame(in)
			if want, isErr := c["error"]; isErr {
				if CodeOf(err) != want {
					t.Fatalf("error = %v, want code %v", err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(status) != c["status"] || body != optString(c["body"]) ||
				hex.EncodeToString(rest) != c["rest_hex"] {
				t.Errorf("got (%s, %q, %x), want (%v, %v, %v)",
					status, body, rest, c["status"], c["body"], c["rest_hex"])
			}
		})
	}
}

func TestVectorSignature(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "signature") {
		t.Run(str(c["name"]), func(t *testing.T) {
			key := DeriveKey(str(c["secret"]))
			if got := ComputeSignature(key, str(c["canonical"])); got != c["signature"] {
				t.Errorf("got %s, want %s", got, c["signature"])
			}
			if !VerifySignature(key, str(c["canonical"]), str(c["signature"])) {
				t.Errorf("valid signature rejected")
			}
			if VerifySignature(key, str(c["canonical"])+" ", str(c["signature"])) {
				t.Errorf("altered canonical accepted")
			}
		})
	}
}

func TestVectorNonce(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "nonce") {
		if got := IsValidNonce(c["nonce"]); got != c["valid"] {
			t.Errorf("IsValidNonce(%q) = %v, want %v", c["nonce"], got, c["valid"])
		}
	}
	if n := MakeNonce(); !IsValidNonce(n) || n == MakeNonce() {
		t.Errorf("MakeNonce returned an invalid or repeated nonce")
	}
}

func TestVectorTimestampWindow(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "timestamp_window") {
		if got := TimestampInWindow(i64(c["timestamp"]), i64(c["now"])); got != c["in_window"] {
			t.Errorf("TimestampInWindow(%v, %v) = %v, want %v", c["timestamp"], c["now"], got, c["in_window"])
		}
	}
}

func TestVectorPeekVersion(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "peek_version") {
		if got := PeekVersion(str(c["body"])); got != i64(c["version"]) {
			t.Errorf("PeekVersion(%.30q) = %d, want %v", c["body"], got, c["version"])
		}
	}
}

func TestVectorBuildRequest(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "build_request") {
		t.Run(str(c["name"]), func(t *testing.T) {
			a := c["args"].(obj)
			got, err := BuildRequest(RequestParams{
				Action:    str(a["action"]),
				Secret:    str(a["secret"]),
				Var:       str(a["var"]),
				Val:       a["val"],
				ReqID:     str(a["req_id"]),
				Name:      str(a["name"]),
				Timestamp: i64(a["timestamp"]),
				Nonce:     str(a["nonce"]),
				Tail:      i64(a["tail"]),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != c["body"] {
				t.Errorf("got:\n%s\nwant:\n%s", got, c["body"])
			}
		})
	}
}

func requestJSON(r *Request) obj {
	var tail any
	if r.Tail != nil {
		tail = *r.Tail
	}
	return obj{
		"version": r.Version, "id": ptrJSON(r.ID), "action": r.Action, "var": ptrJSON(r.Var),
		"val": r.Val, "name": ptrJSON(r.Name), "timestamp": r.Timestamp, "nonce": r.Nonce,
		"tail": tail,
	}
}

func TestVectorParseRequest(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "parse_request") {
		t.Run(str(c["name"]), func(t *testing.T) {
			req, err := ParseRequest(str(c["body"]), str(c["secret"]), str(c["hostname"]), i64(c["now"]))
			if want, isErr := c["error"]; isErr {
				w := want.(obj)
				var pe *ProtocolError
				if err == nil || !errors.As(err, &pe) {
					t.Fatalf("got err=%v, want code %v", err, w["code"])
				}
				if pe.Code != w["code"] || ptrJSON(pe.ReqID) != w["req_id"] {
					t.Errorf("got code=%s req_id=%v, want code=%v req_id=%v",
						pe.Code, ptrJSON(pe.ReqID), w["code"], w["req_id"])
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := canon(t, requestJSON(req)); !reflect.DeepEqual(got, c["request"]) {
				t.Errorf("got %v\nwant %v", got, c["request"])
			}
		})
	}
}

func TestVectorBuildResponse(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "build_response") {
		t.Run(str(c["name"]), func(t *testing.T) {
			a := c["args"].(obj)
			got, err := SignResponse(nodesFromJSON(c["content"]), ResponseParams{
				Secret:    str(a["secret"]),
				Hostname:  str(a["hostname"]),
				ReqID:     optString(a["req_id"]),
				Timestamp: i64(a["timestamp"]),
				Nonce:     str(a["nonce"]),
				Version:   i64(a["version"]),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != c["body"] {
				t.Errorf("got:\n%s\nwant:\n%s", got, c["body"])
			}
		})
	}
}

func responseJSON(r *Response) obj {
	var logs any
	if r.Logs != nil {
		lines := make([]any, len(r.Logs.Lines))
		for i, l := range r.Logs.Lines {
			lines[i] = l
		}
		logs = obj{"path": r.Logs.Path, "truncated": r.Logs.Truncated, "lines": lines}
	}
	var settings any
	if r.Settings != nil {
		settings = r.Settings
	}
	return obj{
		"version": r.Version, "id": ptrJSON(r.ID), "status": r.Status, "result": r.Result,
		"error_code": r.ErrorCode, "error_message": r.ErrorMessage, "settings": settings,
		"logs": logs, "name": ptrJSON(r.Name), "timestamp": r.Timestamp, "nonce": r.Nonce,
	}
}

func TestVectorParseResponse(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "parse_response") {
		t.Run(str(c["name"]), func(t *testing.T) {
			resp, err := ParseResponse(str(c["body"]), str(c["secret"]), ResponseOptions{
				ExpectedName:    optString(c["expected_name"]),
				ExpectedVersion: i64(c["expected_version"]),
			}, i64(c["now"]))
			if want, isErr := c["error"]; isErr {
				w := want.(obj)
				var pe *ProtocolError
				if err == nil || !errors.As(err, &pe) {
					t.Fatalf("got err=%v, want code %v", err, w["code"])
				}
				if pe.Code != w["code"] || ptrJSON(pe.ReqID) != w["req_id"] {
					t.Errorf("got code=%s req_id=%v, want code=%v req_id=%v",
						pe.Code, ptrJSON(pe.ReqID), w["code"], w["req_id"])
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := canon(t, responseJSON(resp)); !reflect.DeepEqual(got, c["response"]) {
				t.Errorf("got %v\nwant %v", got, c["response"])
			}
		})
	}
}

func namesAreBare(nodes []Node) bool {
	for _, n := range nodes {
		if !isBare(n.Name) || !namesAreBare(n.Children) {
			return false
		}
	}
	return true
}
