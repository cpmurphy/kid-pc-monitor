// Package auth is the web panel's parent login: the password file
// (web_panel_auth.json), werkzeug-compatible password hashes, the signed
// session cookie with its CSRF token, and the login "next" redirect check.
//
// The auth file, hashes and redirect check follow the original Python panel
// (web_panel.py, werkzeug.security), so a password set there still logs in
// here. testdata/panelauth/vectors.json is the checked-in contract from that
// port and vectors_test.go checks every case.
//
// # Known differences from the Python implementation
//
//   - The session cookie is this package's own format (Flask's is
//     itsdangerous-signed), so switching panels means logging in again.
//   - A hash werkzeug rejects by raising (unknown method, malformed
//     parameters) is a wrong password instead of a server error.
//   - The auth file is written atomically with mode 0600 (it holds the
//     session signing key); Python writes it in place with the umask.
//   - Python also reads the file from its package directory (where installs
//     before the May 2026 package layout kept it); Go has no package
//     directory, so callers list such legacy paths in Files.Legacy.
package auth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// notThere reports whether err says the path does not exist.
func notThere(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// mayExist is false only when path certainly does not exist; any other stat
// error counts as existing, so reading the file reports the problem
// (web_panel._may_exist).
func mayExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !notThere(err)
}

// ReadPath is the file to read (web_panel._auth_path).
func (f Files) ReadPath() string {
	canonical := filepath.Join(f.Dir, AuthFile)
	if mayExist(canonical) {
		return canonical
	}
	for _, legacy := range f.Legacy {
		if mayExist(legacy) {
			return legacy
		}
	}
	return canonical
}

// SavePath is where passwords are written (web_panel._auth_save_path).
func (f Files) SavePath() string { return filepath.Join(f.Dir, AuthFile) }

// Read reads the auth record (web_panel.read_auth_file). It returns nil, nil
// when there is no file (no password set), and an error when the file exists
// but cannot be used: unreadable, not UTF-8, not a JSON object, a
// password_hash that is neither a string nor null, or the old hash/salt
// format. The panel must then stay
// locked rather than act as if no password were set.
func (f Files) Read() (Record, error) {
	path := f.ReadPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if notThere(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("cannot read %s: not UTF-8 text", path)
	}
	v, err := pyval.DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	rec, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s does not hold a JSON object", path)
	}
	if h, present := rec["password_hash"]; present && h != nil {
		if _, ok := h.(string); !ok {
			return nil, fmt.Errorf("%s has a password_hash that is not a string", path)
		}
	}
	if _, old := rec["hash"]; old && Record(rec).PasswordHash() == "" {
		// The panel's short-lived salt/hash format (May 2026).
		return nil, fmt.Errorf("%s uses an old password format; delete it and set the password again", path)
	}
	return rec, nil
}

// Problem is why the auth file exists but cannot be used, or nil
// (web_panel.auth_file_problem).
func (f Files) Problem() error {
	_, err := f.Read()
	return err
}

// Load reads the auth record, or nil when there is none or it cannot be used
// (web_panel.load_auth_record).
func (f Files) Load() Record {
	rec, _ := f.Read()
	return rec
}

// LockedText is the body the panel serves while the auth file at path cannot
// be used (web_panel.auth_file_locked_text).
func LockedText(path string) string {
	return "Kid PC Monitor is locked: its password file " + path + " is damaged or cannot be read.\n" +
		"\n" +
		"Nothing is shown until the file is fixed, so the panel is not left open to\n" +
		"anyone on the network. Restore the file (the panel's log says what is wrong\n" +
		"with it), or delete it and set a new password: deleting it removes the\n" +
		"password, and the next person to open the panel can set one.\n"
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
//
// It refuses to replace an auth file that cannot be used (see Read).
func (f Files) SavePassword(password string) (string, error) {
	rec, err := f.Read()
	if err != nil {
		return "", err
	}
	secretKey := rec.SecretKey()
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
