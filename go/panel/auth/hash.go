package auth

import (
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"math/big"
	"strings"

	"golang.org/x/crypto/scrypt"

	"kidpcmonitor/panel/pyval"
)

// Werkzeug password hashes are "method$salt$hexdigest", where method is
// "scrypt:N:r:p" or "pbkdf2:hashname:iterations" (werkzeug.security).

const (
	saltChars        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	saltLength       = 16
	defaultMethod    = "scrypt"
	defaultPBKDF2Its = 1_000_000 // werkzeug.security.DEFAULT_PBKDF2_ITERATIONS
)

var errBadMethod = errors.New("invalid password hash method")

var pbkdf2Hashes = map[string]func() hash.Hash{
	"md5":        md5.New,
	"sha1":       sha1.New,
	"sha224":     sha256.New224,
	"sha256":     sha256.New,
	"sha384":     sha512.New384,
	"sha512":     sha512.New,
	"sha512_224": sha512.New512_224,
	"sha512_256": sha512.New512_256,
	"sha3_224":   func() hash.Hash { return sha3.New224() },
	"sha3_256":   func() hash.Hash { return sha3.New256() },
	"sha3_384":   func() hash.Hash { return sha3.New384() },
	"sha3_512":   func() hash.Hash { return sha3.New512() },
}

func parseIntArg(s string) (int, error) {
	n, err := pyval.Int(s)
	if err != nil || n > 1<<31 || n < -(1<<31) {
		return 0, errBadMethod
	}
	return int(n), nil
}

// hashInternal is werkzeug.security._hash_internal: the hex digest of
// password and the normalized method string. It fails where werkzeug raises.
func hashInternal(method, salt, password string) (hexDigest, methodOut string, err error) {
	name, rest, hasArgs := strings.Cut(method, ":")
	var args []string
	if hasArgs {
		args = strings.Split(rest, ":")
	}
	switch name {
	case "scrypt":
		n, r, p := 1<<15, 8, 1
		if hasArgs {
			if len(args) != 3 {
				return "", "", errBadMethod
			}
			vals := [3]int{}
			for i, a := range args {
				if vals[i], err = parseIntArg(a); err != nil {
					return "", "", err
				}
			}
			n, r, p = vals[0], vals[1], vals[2]
		}
		// hashlib.scrypt: n a power of two above 1, positive r and p, and
		// OpenSSL's memory need (128*r*p + 128*r*(n+2) bytes) within
		// werkzeug's maxmem of 132*n*r*p.
		if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 ||
			int64(128)*int64(r)*int64(p)+int64(128)*int64(r)*int64(n+2) > int64(132)*int64(n)*int64(r)*int64(p) {
			return "", "", errBadMethod
		}
		key, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, 64)
		if err != nil {
			return "", "", errBadMethod
		}
		return hex.EncodeToString(key), "scrypt:" + itoa(n) + ":" + itoa(r) + ":" + itoa(p), nil
	case "pbkdf2":
		hashName, iterations := "sha256", defaultPBKDF2Its
		switch len(args) {
		case 0:
		case 1:
			hashName = args[0]
		case 2:
			hashName = args[0]
			if iterations, err = parseIntArg(args[1]); err != nil {
				return "", "", err
			}
		default:
			return "", "", errBadMethod
		}
		newHash, ok := pbkdf2Hashes[hashName]
		if !ok || iterations < 1 {
			return "", "", errBadMethod
		}
		key, err := pbkdf2.Key(newHash, password, []byte(salt), iterations, newHash().Size())
		if err != nil {
			return "", "", errBadMethod
		}
		return hex.EncodeToString(key), "pbkdf2:" + hashName + ":" + itoa(iterations), nil
	}
	return "", "", errBadMethod
}

func itoa(n int) string { return pyval.Str(n) }

// CheckPasswordHash is werkzeug.security.check_password_hash. Hashes werkzeug
// rejects by raising (an unknown method, malformed parameters) are a wrong
// password here.
func CheckPasswordHash(pwhash, password string) bool {
	parts := strings.SplitN(pwhash, "$", 3)
	if len(parts) != 3 {
		return false
	}
	digest, _, err := hashInternal(parts[0], parts[1], password)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(digest), []byte(parts[2])) == 1
}

// HashWithSalt builds the full stored hash for method and salt, as
// generate_password_hash does with a given salt.
func HashWithSalt(method, salt, password string) (string, error) {
	digest, methodOut, err := hashInternal(method, salt, password)
	if err != nil {
		return "", err
	}
	return methodOut + "$" + salt + "$" + digest, nil
}

// GeneratePasswordHash is generate_password_hash(password, method="scrypt"):
// scrypt N=32768, r=8, p=1 with a random 16-character salt.
func GeneratePasswordHash(password string) (string, error) {
	salt, err := genSalt(saltLength)
	if err != nil {
		return "", err
	}
	return HashWithSalt(defaultMethod, salt, password)
}

// genSalt is werkzeug.security.gen_salt.
func genSalt(length int) (string, error) {
	var b strings.Builder
	limit := big.NewInt(int64(len(saltChars)))
	for range length {
		i, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		b.WriteByte(saltChars[i.Int64()])
	}
	return b.String(), nil
}
