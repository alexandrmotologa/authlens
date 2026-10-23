package keys_test

import (
	"strings"
	"testing"

	"github.com/alexandrmotologa/authlens/internal/keys"
)

func TestKeyManagerGeneration(t *testing.T) {
	km, err := keys.NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	if km.ActiveRSA == nil || km.ActiveRSA.RSAPriv == nil {
		t.Fatal("expected active RSA key to be generated")
	}
	if km.ActiveECDSA == nil || km.ActiveECDSA.ECPriv == nil {
		t.Fatal("expected active ECDSA key to be generated")
	}

	if !strings.HasPrefix(km.ActiveRSA.ID, "authlens-rsa-key-") {
		t.Errorf("unexpected RSA key id: %s", km.ActiveRSA.ID)
	}
	if !strings.HasPrefix(km.ActiveECDSA.ID, "authlens-ec-key-") {
		t.Errorf("unexpected ECDSA key id: %s", km.ActiveECDSA.ID)
	}

	jwks, err := km.GetJWKS()
	if err != nil {
		t.Fatalf("failed to build JWKS: %v", err)
	}
	if jwks.Len() < 2 {
		t.Errorf("expected at least 2 keys in JWKS, got %d", jwks.Len())
	}
}

func TestKeyRotation(t *testing.T) {
	km, err := keys.NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	oldRSAID := km.ActiveRSA.ID
	oldECID := km.ActiveECDSA.ID

	err = km.RotateKeys()
	if err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	if km.ActiveRSA.ID == oldRSAID {
		t.Error("expected new RSA key ID after rotation")
	}
	if km.ActiveECDSA.ID == oldECID {
		t.Error("expected new ECDSA key ID after rotation")
	}

	// Rotated keys should still be findable
	found := km.FindKeyByID(oldRSAID)
	if found == nil {
		t.Errorf("expected to find rotated key %s", oldRSAID)
	}

	jwks, _ := km.GetJWKS()
	if jwks.Len() < 4 {
		t.Errorf("expected at least 4 keys in JWKS after rotation, got %d", jwks.Len())
	}
}

func TestExportPEM(t *testing.T) {
	km, err := keys.NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	rsaPEM, err := km.ExportRSAPublicPEM()
	if err != nil || !strings.Contains(rsaPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("failed to export valid RSA PEM: %v", err)
	}

	ecPEM, err := km.ExportECPublicPEM()
	if err != nil || !strings.Contains(ecPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("failed to export valid ECDSA PEM: %v", err)
	}
}
