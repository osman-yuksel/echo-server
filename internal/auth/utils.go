package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"strings"
)

var AUTH_SECRET = os.Getenv("AUTH_SECRET")

func GenerateVerificationKey() string {
	s := randomString(16)

	h := sha256.New()
	h.Write([]byte(s + AUTH_SECRET))
	sha1_hash := hex.EncodeToString(h.Sum(nil))[:32]

	return s + "|" + sha1_hash
}

func ValidateVerificationKey(state string) bool {
	parts := strings.Split(state, "|")
	if len(parts) != 2 {
		return false
	}

	h := sha256.New()
	h.Write([]byte(parts[0] + AUTH_SECRET))
	sha1_hash := hex.EncodeToString(h.Sum(nil))[:32]
	return parts[1] == sha1_hash
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
