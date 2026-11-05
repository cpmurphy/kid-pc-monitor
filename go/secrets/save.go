package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Save encrypts value as a Fernet token and writes it atomically to the
// first secrets directory that accepts it (secrets_store.save_secret),
// returning the path written. The installers write the machine-wide
// directory when they can, so the agent and panel find the same secret.
func Save(name, value string) (string, error) {
	token, err := fernetEncrypt(fernetKey(), []byte(value), time.Now())
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, dir := range Dirs() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			lastErr = err
			continue
		}
		path := filepath.Join(dir, name+".enc")
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, token, 0o644); err != nil {
			lastErr = err
			continue
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			lastErr = err
			continue
		}
		return path, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no writable secrets directory")
	}
	return "", lastErr
}

// SaveSharedSecret stores the panel <-> agent shared secret.
func SaveSharedSecret(value string) (string, error) { return Save(SharedSecretName, value) }

// FindPath is the first directory's file holding a decryptable copy of the
// secret, or "" (secrets_store.find_secret_path).
func FindPath(name string) string {
	key := fernetKey()
	for _, dir := range Dirs() {
		path := filepath.Join(dir, name+".enc")
		token, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, err := fernetDecrypt(key, token); err == nil {
			return path
		}
	}
	return ""
}

// fernetEncrypt builds a Fernet token: version 0x80, big-endian timestamp,
// random IV, AES-128-CBC with PKCS7 padding, HMAC-SHA256 over all of that,
// URL-safe base64 with padding (cryptography.fernet.Fernet.encrypt).
func fernetEncrypt(key, plain []byte, now time.Time) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return fernetEncryptIV(key, plain, now, iv)
}

func fernetEncryptIV(key, plain []byte, now time.Time, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte(nil), plain...), make([]byte, pad)...)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	body := make([]byte, 0, 1+8+16+len(padded)+32)
	body = append(body, 0x80)
	body = binary.BigEndian.AppendUint64(body, uint64(now.Unix()))
	body = append(body, iv...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	body = append(body, ct...)
	mac := hmac.New(sha256.New, key[:16])
	mac.Write(body)
	body = mac.Sum(body)
	out := make([]byte, base64.URLEncoding.EncodedLen(len(body)))
	base64.URLEncoding.Encode(out, body)
	return out, nil
}
