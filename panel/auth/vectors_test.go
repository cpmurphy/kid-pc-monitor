package auth

import (
	"os"
	"path/filepath"
	"testing"

	"kidpcmonitor/panel/pyval"
)

// The golden vectors are the checked-in contract, originally generated from
// werkzeug and the Python web panel. Every case here must agree with them.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "panelauth", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyval.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(obj)
}

func cases(t *testing.T, section string) []obj {
	t.Helper()
	list, ok := loadVectors(t)[section].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("section %q missing or empty", section)
	}
	out := make([]obj, len(list))
	for i, c := range list {
		out[i] = c.(obj)
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

func TestConstants(t *testing.T) {
	c := loadVectors(t)["constants"].(obj)
	if c["auth_file"] != AuthFile || c["min_secret_key_length"] != int64(MinSecretKeyLength) {
		t.Errorf("constants = %v", c)
	}
}

func TestHashWithSalt(t *testing.T) {
	for _, c := range cases(t, "generate_password_hash") {
		got, err := HashWithSalt(str(c["method"]), str(c["salt"]), str(c["password"]))
		if err != nil || got != c["hash"] {
			t.Errorf("HashWithSalt(%q, %q, %q) = %q, %v; want %q",
				c["method"], c["salt"], c["password"], got, err, c["hash"])
		}
		if !CheckPasswordHash(str(c["hash"]), str(c["password"])) {
			t.Errorf("CheckPasswordHash rejects its own %q", c["hash"])
		}
	}
}

func TestCheckPasswordHash(t *testing.T) {
	for _, c := range cases(t, "check_password_hash") {
		want := c["result"] == true // "error" is a wrong password
		if got := CheckPasswordHash(str(c["hash"]), str(c["password"])); got != want {
			t.Errorf("CheckPasswordHash(%q, %q) = %v, want %v (python: %v)",
				c["hash"], c["password"], got, want, c["result"])
		}
	}
}

func TestAuthRecord(t *testing.T) {
	for _, c := range cases(t, "auth_record") {
		text := str(c["text"])
		files := Files{Dir: t.TempDir()}
		if err := os.WriteFile(files.SavePath(), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		rec, err := files.Read()
		if locked := err != nil; locked != c["locked"] {
			t.Errorf("Read(%q) locked = %v (%v), want %v", text, locked, err, c["locked"])
		}
		wantHash, wantKey := str(c["password_hash"]), str(c["secret_key"])
		if got := rec.PasswordHash(); got != wantHash {
			t.Errorf("PasswordHash(%q) = %q, want %q", text, got, wantHash)
		}
		if got := rec.SecretKey(); got != wantKey {
			t.Errorf("SecretKey(%q) = %q, want %q", text, got, wantKey)
		}
	}
}

func TestFormatRecordJSON(t *testing.T) {
	for _, c := range cases(t, "save_record") {
		if got := FormatRecordJSON(str(c["secret_key"]), str(c["password_hash"])); got != c["text"] {
			t.Errorf("FormatRecordJSON(%q, %q) =\n%s\nwant\n%s", c["secret_key"], c["password_hash"], got, c["text"])
		}
	}
}

func TestIsLocalPath(t *testing.T) {
	for _, c := range cases(t, "is_local_path") {
		in := str(c["in"])
		if got := IsLocalPath(in); got != c["out"] {
			t.Errorf("IsLocalPath(%q) = %v, want %v", in, got, c["out"])
		}
		want := "/"
		if c["out"] == true && in != "" {
			want = in
		}
		if got := SafeNextURL(in); got != want {
			t.Errorf("SafeNextURL(%q) = %q, want %q", in, got, want)
		}
	}
}
