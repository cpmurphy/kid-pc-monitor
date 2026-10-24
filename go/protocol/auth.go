package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const (
	// Algorithm is the only signature algorithm the protocol defines.
	Algorithm = "hmac-sha256"
	// DefaultKeyID identifies the (single) shared secret.
	DefaultKeyID = "kid-pc-monitor-shared-secret"
	// TimestampWindowSeconds is the allowed clock skew either way.
	TimestampWindowSeconds = 60
	// NonceBytes of randomness, hex-encoded, make a nonce.
	NonceBytes       = 16
	nonceMinHexChars = NonceBytes * 2
)

// DeriveKey returns the HMAC signing key: the UTF-8 bytes of the shared secret.
func DeriveKey(sharedSecret string) []byte { return []byte(sharedSecret) }

// ComputeSignature returns base64url(HMAC-SHA256(key, canonical)).
func ComputeSignature(key []byte, canonical string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySignature is a constant-time check that signature matches canonical.
func VerifySignature(key []byte, canonical, signature string) bool {
	expected := ComputeSignature(key, canonical)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// MakeNonce returns a fresh hex nonce with NonceBytes of randomness.
func MakeNonce() string {
	buf := make([]byte, NonceBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("protocol: no system randomness: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// IsValidNonce reports whether nonce is plain hex of at least the minimum length.
func IsValidNonce(nonce Value) bool {
	s, ok := nonce.(string)
	if !ok || len(s) < nonceMinHexChars {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// TimestampInWindow reports whether ts is within TimestampWindowSeconds of now.
func TimestampInWindow(ts, now int64) bool {
	return ts >= now-TimestampWindowSeconds && ts <= now+TimestampWindowSeconds
}
