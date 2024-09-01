package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

var AUTH_SECRET = os.Getenv("AUTH_SECRET")

func GenerateHMACToken(size int) string {
	randomStr := generateRandomString(size)
	hash := createHMACHash(randomStr)
	return fmt.Sprintf("%s|%s", randomStr, hash)
}

func VerifyHMACToken(token string) bool {
	parts := strings.Split(token, "|")
	if len(parts) != 2 {
		return false
	}
	return createHMACHash(parts[0]) == parts[1]
}

func createHMACHash(input string) string {
	secretKey := []byte(AUTH_SECRET)
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

func generateRandomString(size int) string {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)[:size]
}
