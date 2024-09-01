package auth

import "testing"

func TestOAuthVerificationKey(t *testing.T) {
	// Test with a valid generated token
	validToken := GenerateHMACToken(16)
	if !VerifyHMACToken(validToken) {
		t.Errorf("Expected valid token to pass verification")
	}

	// Test with an invalid token
	invalidToken := "invalid"
	if VerifyHMACToken(invalidToken) {
		t.Errorf("Expected invalid token to fail verification")
	}

	// Test with a malformed token
	malformedToken := "malformed|token|extra"
	if VerifyHMACToken(malformedToken) {
		t.Errorf("Expected malformed token to fail verification")
	}
}
