// Package auth is the web panel's parent login: the password file
// (web_panel_auth.json), werkzeug-compatible password hashes, the signed
// session cookie with its CSRF token, and the login "next" redirect check.
//
// The auth file, hashes and redirect check follow the Python panel
// (web_panel.py, werkzeug.security), so a password set in either panel
// logs in to the other. The Python implementation is the reference:
// testdata/panelauth/vectors.json is generated from it
// (tests/panelauth_vectors_gen.py) and vectors_test.go checks every case.
//
// # Known differences from the Python implementation
//
//   - The session cookie is this package's own format (Flask's is
//     itsdangerous-signed), so switching panels means logging in again.
//   - A hash werkzeug rejects by raising (unknown method, malformed
//     parameters) is a wrong password instead of a server error, and an
//     auth file holding a JSON value that is not an object counts as no file
//     instead of crashing.
//   - The auth file is written atomically with mode 0600 (it holds the
//     session signing key); Python writes it in place with the umask.
//   - Python also reads the file from its package directory (where installs
//     before the May 2026 package layout kept it); Go has no package
//     directory, so callers list such legacy paths in Files.Legacy.
package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/secrets"
)

// AuthFile is web_panel.AUTH_FILE.
const AuthFile = "web_panel_auth.json"

// MinSecretKeyLength is the shortest stored secret_key the panel uses.
const MinSecretKeyLength = 16

// Record is the parsed auth file.
type Record map[string]any

// PasswordHash is the stored password hash, or "" when none is set
// (web_panel._stored_password_hash).
func (r Record) PasswordHash() string {
	h, _ := r["password_hash"].(string)
	return h
}

// SecretKey is the stored session secret key, or "" when it is missing or
// shorter than MinSecretKeyLength characters (web_panel._panel_secret_key).
func (r Record) SecretKey() string {
	k, _ := r["secret_key"].(string)
	if utf8.RuneCountInString(k) < MinSecretKeyLength {
		return ""
	}
	return k
}

// VerifyPassword reports whether password matches the stored hash.
func (r Record) VerifyPassword(password string) bool {
	h := r.PasswordHash()
	return h != "" && CheckPasswordHash(h, password)
}

// ParseRecord parses auth-file text; it returns nil for text that is not a
// JSON object (web_panel.load_auth_record).
func ParseRecord(data []byte) Record {
	v, err := pyval.DecodeJSON(data)
	if err != nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

// Files locates the auth file: Dir/web_panel_auth.json (the config
// directory), falling back to the first existing Legacy path for reading.
type Files struct {
	Dir    string
	Legacy []string
}

// DefaultFiles uses the panel's config directory (paths.config_dir).
func DefaultFiles() Files { return Files{Dir: secrets.ConfigDir()} }

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// ReadPath is the file to read (web_panel._auth_path).
func (f Files) ReadPath() string {
	canonical := filepath.Join(f.Dir, AuthFile)
	if isFile(canonical) {
		return canonical
	}
	for _, legacy := range f.Legacy {
		if isFile(legacy) {
			return legacy
		}
	}
	return canonical
}

// SavePath is where passwords are written (web_panel._auth_save_path).
func (f Files) SavePath() string { return filepath.Join(f.Dir, AuthFile) }

// Load reads the auth record, or nil when there is none or it is unreadable.
func (f Files) Load() Record {
	data, err := os.ReadFile(f.ReadPath())
	if err != nil {
		return nil
	}
	return ParseRecord(data)
}

// PasswordConfigured reports whether a password is set.
func (f Files) PasswordConfigured() bool { return f.Load().PasswordHash() != "" }

// FormatRecordJSON is the text save_password writes:
// json.dumps({"secret_key": ..., "password_hash": ...}, indent=2).
func FormatRecordJSON(secretKey, passwordHash string) string {
	key, _ := pyval.EncodeJSON(secretKey)
	hash, _ := pyval.EncodeJSON(passwordHash)
	return "{\n  \"secret_key\": " + key + ",\n  \"password_hash\": " + hash + "\n}"
}

// SavePassword stores a new password hash, keeping the existing secret key
// (or making one), and returns the secret key now stored
// (web_panel.save_password).
func (f Files) SavePassword(password string) (string, error) {
	secretKey := f.Load().SecretKey()
	if secretKey == "" {
		var err error
		if secretKey, err = RandomHex(32); err != nil {
			return "", err
		}
	}
	pwhash, err := GeneratePasswordHash(password)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(f.SavePath(), []byte(FormatRecordJSON(secretKey, pwhash))); err != nil {
		return "", err
	}
	return secretKey, nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// IsLocalPath reports whether target is a path on this panel that is safe
// to redirect to (web_panel.is_local_path): a leading "/" not followed by
// another, no backslashes (browsers read them as "/") and no control
// characters.
func IsLocalPath(target string) bool {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return false
	}
	for _, r := range target {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// SafeNextURL is target when it is a local path, else "/" (the dashboard)
// (web_panel._safe_next_url).
func SafeNextURL(target string) string {
	if target != "" && IsLocalPath(target) {
		return target
	}
	return "/"
}
