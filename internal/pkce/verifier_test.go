package pkce_test

import (
	"strings"
	"testing"

	"github.com/alexandrmotologa/authlens/internal/pkce"
)

func TestRFC7636OfficialTestVector(t *testing.T) {
	// RFC 7636 Appendix B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	computed, err := pkce.ComputeChallenge(verifier, "S256")
	if err != nil {
		t.Fatalf("unexpected error computing challenge: %v", err)
	}

	if computed != expectedChallenge {
		t.Fatalf("RFC 7636 test vector mismatch: got %q, expected %q", computed, expectedChallenge)
	}

	err = pkce.VerifyChallenge(verifier, expectedChallenge, "S256")
	if err != nil {
		t.Fatalf("expected verification to succeed: %v", err)
	}
}

func TestPlainChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	computed, err := pkce.ComputeChallenge(verifier, "plain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if computed != verifier {
		t.Errorf("expected plain challenge to equal verifier")
	}

	err = pkce.VerifyChallenge(verifier, verifier, "plain")
	if err != nil {
		t.Errorf("expected plain verification to pass: %v", err)
	}
}

func TestInvalidVerifierLengths(t *testing.T) {
	// Length < 43
	tooShort := strings.Repeat("a", 42)
	_, err := pkce.ComputeChallenge(tooShort, "S256")
	if err == nil {
		t.Error("expected error for verifier length < 43")
	}

	// Length > 128
	tooLong := strings.Repeat("a", 129)
	_, err = pkce.ComputeChallenge(tooLong, "S256")
	if err == nil {
		t.Error("expected error for verifier length > 128")
	}

	// Valid length (43)
	valid43 := strings.Repeat("a", 43)
	_, err = pkce.ComputeChallenge(valid43, "S256")
	if err != nil {
		t.Errorf("expected length 43 to be valid, got: %v", err)
	}

	// Valid length (128)
	valid128 := strings.Repeat("a", 128)
	_, err = pkce.ComputeChallenge(valid128, "S256")
	if err != nil {
		t.Errorf("expected length 128 to be valid, got: %v", err)
	}
}

func TestInvalidVerifierCharacters(t *testing.T) {
	// Invalid characters (spaces, symbols like $, %, +)
	invalidChar := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX+@"
	_, err := pkce.ComputeChallenge(invalidChar, "S256")
	if err == nil {
		t.Error("expected error for verifier with invalid characters (+, @)")
	}
}

func TestVerificationMismatch(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrongChallenge := "E9Mel-2Vz6wdhA4n99bGa5vDZBgOmGMTnvOMNa3ElXX"

	err := pkce.VerifyChallenge(verifier, wrongChallenge, "S256")
	if err == nil {
		t.Error("expected verification to fail on mismatch")
	}
}
