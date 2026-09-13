package server

import "testing"

func TestGitHubSignatureVector(t *testing.T) {
	secret := "It's a Secret to Everybody"
	payload := []byte("Hello, World!")
	header := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if !verifyGitHubSignature(secret, header, payload) {
		t.Fatal("GitHub documented test vector failed")
	}
	if verifyGitHubSignature(secret, header, []byte("tampered")) {
		t.Fatal("tampered payload accepted")
	}
}
