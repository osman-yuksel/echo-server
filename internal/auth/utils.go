package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

var AUTH_SECRET = os.Getenv("AUTH_SECRET")

// `size` is the base key size, not includes hash
func GenerateVerificationToken(size int) string {
	s := randomString(size)
	h := hashVerificationKey(s)
	return s + "|" + h
}

func VerifyVerificationToken(token string) bool {
	parts := strings.Split(token, "|")
	if len(parts) != 2 {
		return false
	}

	h := hashVerificationKey(parts[0])
	return h == parts[1]
}

// hashVerificationKey creates an HMAC hash of the input string using the secret key
func hashVerificationKey(s string) string {
	secretKey := []byte(AUTH_SECRET)
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func randomString(size int) string {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)[:size]
}
