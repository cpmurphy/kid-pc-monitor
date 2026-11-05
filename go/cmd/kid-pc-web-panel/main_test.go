package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kidpcmonitor/secrets"
)

func TestSetSecretPipedRetriesThenSaves(t *testing.T) {
	t.Setenv("KID_PC_MONITOR_SECRETS_DIR", t.TempDir())
	var out bytes.Buffer
	in := strings.NewReader("short\nlong enough one\nmismatch!!\nlong enough one\n  long enough one \n")
	if err := setSecret(in, &out, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := secrets.LoadSharedSecret(); got != "long enough one" {
		t.Fatalf("stored %q", got)
	}
	for _, want := range []string{"Too short", "did not match", "Shared secret saved"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := setSecret(strings.NewReader(""), &out, false); err != nil || !strings.Contains(out.String(), "Reusing existing") {
		t.Fatalf("reuse: %v %q", err, out.String())
	}
	if err := setSecret(strings.NewReader("brand new secret\n"), &out, true); err == nil {
		t.Fatal("replace accepted an unconfirmed secret")
	}
	if got, _ := secrets.LoadSharedSecret(); got != "long enough one" {
		t.Fatalf("cancelled replace changed the secret to %q", got)
	}
}

func TestListenNetwork(t *testing.T) {
	for host, want := range map[string]string{"0.0.0.0": "tcp4", "127.0.0.1": "tcp4", "::": "tcp", "localhost": "tcp"} {
		if got := listenNetwork(host); got != want {
			t.Errorf("listenNetwork(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestOpenLogRollsOverLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "web_panel.log")
	f, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bytes.Repeat([]byte("x"), maxLogBytes+1))
	f.Close()
	f, err = openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("fresh\n")
	f.Close()
	if st, err := os.Stat(path + ".1"); err != nil || st.Size() != maxLogBytes+1 {
		t.Fatalf("rolled file: %v %v", st, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "fresh\n" {
		t.Fatalf("new log = %q", b)
	}
}
