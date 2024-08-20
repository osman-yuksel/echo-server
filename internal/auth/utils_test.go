package auth

import "testing"

func TestOAuthVerificationKey(t *testing.T) {
	key := GenerateVerificationToken(16)
	if !VerifyVerificationToken(key) {
		t.Errorf("key is not valid")
	}

	if VerifyVerificationToken("invalid") {
		t.Errorf("key is valid")
	}
}
