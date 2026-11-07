// Package secrets reads and writes the secrets the installers store, a port
// of src/kid_pc_monitor/secrets_store.py and shared_secret.load_shared_secret.
// Standard library only.
//
// Each secret is a Fernet token (AES-128-CBC + HMAC-SHA256) in <name>.enc. The
// Fernet key is PBKDF2-HMAC-SHA256 (600 000 rounds, salt "kpm-fernet-salt") of
// $KID_PC_MONITOR_SECRET_KEY, or of a built-in bootstrap key when that is
// unset. Directories are searched in this order and the first file that
// decrypts wins:
//
//  1. $KID_PC_MONITOR_SECRETS_DIR, when set, and nothing else;
//  2. the machine-wide directory the installer writes (%ProgramData%\KidPCMonitor\secrets
//     on Windows, /etc/kid-pc-monitor/secrets elsewhere);
//  3. the per-user config directory (%LOCALAPPDATA%\kid-pc-monitor\secrets on
//     Windows, $XDG_CONFIG_HOME or ~/.config elsewhere).
//
// Save writes to the first of those directories that accepts the file.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// SharedSecretName is the panel <-> agent shared secret (protocol v2+).
const SharedSecretName = "panel-agent-shared-secret"

const (
	bootstrapKey = "kid-pc-monitor-v3-shared-secret-kdf-2026"
	kdfSalt      = "kpm-fernet-salt"
	kdfRounds    = 600_000
	keyEnv       = "KID_PC_MONITOR_SECRET_KEY"
	dirEnv       = "KID_PC_MONITOR_SECRETS_DIR"
	dirName      = "secrets"
)

// ErrNotFound means no directory holds a decryptable copy of the secret.
var ErrNotFound = errors.New("secret not found")

// errInvalidToken is any malformed, forged or wrong-key Fernet token.
var errInvalidToken = errors.New("invalid Fernet token")

// LoadSharedSecret returns the panel <-> agent shared secret.
func LoadSharedSecret() (string, error) {
	return Load(SharedSecretName)
}

// Load decrypts the named secret from the first directory whose copy
// decrypts. It returns ErrNotFound when there is none.
func Load(name string) (string, error) {
	key, err := fernetKey()
	if err != nil {
		return "", err
	}
	for _, dir := range Dirs() {
		token, err := os.ReadFile(filepath.Join(dir, name+".enc"))
		if err != nil {
			continue
		}
		plain, err := fernetDecrypt(key, token)
		if err != nil {
			continue
		}
		return string(plain), nil
	}
	return "", ErrNotFound
}

// Dirs lists the secrets directories, highest priority first.
func Dirs() []string {
	if override := strings.TrimSpace(os.Getenv(dirEnv)); override != "" {
		return []string{override}
	}
	machine := filepath.Join("/etc", "kid-pc-monitor", dirName)
	if runtime.GOOS == "windows" {
		machine = filepath.Join(envOr("ProgramData", `C:\ProgramData`), "KidPCMonitor", dirName)
	}
	user := filepath.Join(ConfigDir(), dirName)
	if user == machine {
		return []string{machine}
	}
	return []string{machine, user}
}

// ConfigDir is the per-user config directory (paths.config_dir).
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(envOr("LOCALAPPDATA", home), "kid-pc-monitor")
	}
	return filepath.Join(envOr("XDG_CONFIG_HOME", filepath.Join(home, ".config")), "kid-pc-monitor")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

var (
	keyMu    sync.Mutex
	keyCache = map[string][]byte{}
)

// fernetKey derives the 32-byte Fernet key (signing half, then encryption
// half). The derivation is slow by design, so results are cached.
func fernetKey() ([]byte, error) {
	material := strings.TrimSpace(os.Getenv(keyEnv))
	if material == "" {
		material = bootstrapKey
	}
	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok := keyCache[material]; ok {
		return k, nil
	}
	// pbkdf2.Key fails only in FIPS 140-only mode (GODEBUG=fips140=only),
	// which requires a 16-byte salt; kdfSalt is 15 bytes and cannot change
	// without breaking every secret the installers have already written.
	k, err := pbkdf2.Key(sha256.New, material, []byte(kdfSalt), kdfRounds, 32)
	if err != nil {
		return nil, fmt.Errorf("derive secrets key: %w", err)
	}
	keyCache[material] = k
	return k, nil
}

// fernetDecrypt verifies and decrypts a Fernet token (no TTL, as Python's
// Fernet.decrypt without ttl).
func fernetDecrypt(key, token []byte) ([]byte, error) {
	raw, err := base64.URLEncoding.DecodeString(strings.TrimSpace(string(token)))
	if err != nil {
		return nil, errInvalidToken
	}
	// version(1) | timestamp(8) | iv(16) | ciphertext(16n) | hmac(32)
	if len(raw) < 1+8+16+16+32 || raw[0] != 0x80 || (len(raw)-1-8-16-32)%aes.BlockSize != 0 {
		return nil, errInvalidToken
	}
	body, tag := raw[:len(raw)-32], raw[len(raw)-32:]
	mac := hmac.New(sha256.New, key[:16])
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, errInvalidToken
	}
	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, err
	}
	iv, ct := body[9:25], body[25:]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errInvalidToken
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errInvalidToken
		}
	}
	return plain[:len(plain)-pad], nil
}
