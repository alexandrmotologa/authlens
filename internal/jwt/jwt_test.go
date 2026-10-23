package jwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/alexandrmotologa/authlens/internal/jwt"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
)

func TestSignAndDecodeOffline(t *testing.T) {
	km, err := keys.NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	p := &persona.Persona{
		ID:            "admin",
		Sub:           "usr_alice",
		Name:          "Alice",
		Email:         "alice@local.test",
		EmailVerified: true,
		Roles:         []string{"admin"},
	}

	tokenStr, err := jwt.SignPersonaToken(p, km, "http://127.0.0.1:9099", "http://127.0.0.1:9099/api", "RS256", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	decoded, err := jwt.DecodeOffline(tokenStr)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}

	if decoded.Algorithm != "RS256" {
		t.Errorf("expected algorithm RS256, got %s", decoded.Algorithm)
	}
	if decoded.Subject != "usr_alice" {
		t.Errorf("expected subject usr_alice, got %s", decoded.Subject)
	}
	if decoded.IsExpired {
		t.Error("expected fresh token not to be expired")
	}
	if !decoded.HasSignature || decoded.SignatureSize == 0 {
		t.Error("expected valid signature bytes")
	}

	// Validate cryptographically against local keys
	valRes, err := jwt.ValidateOffline(tokenStr, km, "")
	if err != nil {
		t.Fatalf("validation error: %v", err)
	}
	if !valRes.Valid {
		t.Errorf("expected token to be cryptographically valid, got error: %s", valRes.Error)
	}
	if valRes.KeySource != "local_rsa" {
		t.Errorf("expected key source local_rsa, got %s", valRes.KeySource)
	}
}

func TestECDSAandHMAC(t *testing.T) {
	km, _ := keys.NewKeyManager()
	claims := map[string]any{"sub": "test_user", "role": "dev"}

	// ES256
	esToken, err := jwt.SignCustom(claims, km, "ES256")
	if err != nil {
		t.Fatalf("failed to sign ES256: %v", err)
	}
	valES, err := jwt.ValidateOffline(esToken, km, "")
	if err != nil || !valES.Valid {
		t.Errorf("expected ES256 to validate: %v, %s", err, valES.Error)
	}

	// EdDSA (Ed25519)
	edToken, err := jwt.SignCustom(claims, km, "EdDSA")
	if err != nil {
		t.Fatalf("failed to sign EdDSA: %v", err)
	}
	valEd, err := jwt.ValidateOffline(edToken, km, "")
	if err != nil || !valEd.Valid {
		t.Errorf("expected EdDSA to validate: %v, %s", err, valEd.Error)
	}
	if valEd.KeySource != "local_eddsa" {
		t.Errorf("expected key source local_eddsa, got %s", valEd.KeySource)
	}

	// HS256
	hsToken, err := jwt.SignCustom(claims, km, "HS256")
	if err != nil {
		t.Fatalf("failed to sign HS256: %v", err)
	}
	valHS, err := jwt.ValidateOffline(hsToken, km, "")
	if err != nil || !valHS.Valid {
		t.Errorf("expected HS256 to validate: %v, %s", err, valHS.Error)
	}
}

func TestTamperDetection(t *testing.T) {
	km, _ := keys.NewKeyManager()
	claims := map[string]any{"sub": "user_1", "role": "guest"}
	tokenStr, _ := jwt.SignCustom(claims, km, "RS256")

	// Tamper payload segment by altering characters
	parts := strings.Split(tokenStr, ".")
	tampered := parts[0] + ".eyJyZXZlcnNlZCI6ImFkbWluIn0." + parts[2]

	valRes, _ := jwt.ValidateOffline(tampered, km, "")
	if valRes.Valid {
		t.Error("expected tampered token to fail cryptographic verification")
	}
}

func TestAlgNoneRejection(t *testing.T) {
	km, _ := keys.NewKeyManager()
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."

	valRes, _ := jwt.ValidateOffline(token, km, "")
	if valRes.Valid {
		t.Error("expected alg: none to be rejected")
	}
	if !strings.Contains(valRes.Error, "VULNERABILITY") {
		t.Errorf("expected vulnerability warning, got: %s", valRes.Error)
	}
}
