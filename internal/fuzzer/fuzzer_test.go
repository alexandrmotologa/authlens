package fuzzer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexandrmotologa/authlens/internal/fuzzer"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
)

func TestGenerateAllVectors(t *testing.T) {
	km, err := keys.NewKeyManager()
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	gen := fuzzer.NewAttackGenerator(km, "http://127.0.0.1:9099")
	p := &persona.Persona{
		Sub:   "usr_probe_1",
		Name:  "Probe",
		Email: "probe@local.test",
		Roles: []string{"user"},
	}

	vectors, err := gen.GenerateAll(p)
	if err != nil {
		t.Fatalf("failed to generate vectors: %v", err)
	}

	if len(vectors) < 9 {
		t.Fatalf("expected at least 9 attack vectors, got %d", len(vectors))
	}

	// Verify specific attack vectors exist
	vectorMap := make(map[string]fuzzer.AttackVector)
	for _, v := range vectors {
		vectorMap[v.ID] = v
		if v.Token == "" {
			t.Errorf("vector %s has empty token", v.ID)
		}
	}

	expectedIDs := []string{
		"alg_none",
		"sig_tampering",
		"key_confusion",
		"token_expired",
		"future_nbf",
		"wrong_issuer",
		"wrong_audience",
		"unknown_kid",
		"stripped_signature",
	}

	for _, id := range expectedIDs {
		if _, ok := vectorMap[id]; !ok {
			t.Errorf("missing expected attack vector %s", id)
		}
	}
}

func TestSecuritySuiteRunner(t *testing.T) {
	km, _ := keys.NewKeyManager()
	gen := fuzzer.NewAttackGenerator(km, "http://127.0.0.1:9099")
	vectors, _ := gen.GenerateAll(nil)

	// Mock server that acts as a secure middleware (rejects with 401 Unauthorized)
	secureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, "alg_none") || strings.Contains(auth, "eyJ") {
			// Properly reject invalid / compromised tokens
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer secureServer.Close()

	report := fuzzer.RunSuite(context.Background(), secureServer.URL, "GET", "Authorization: Bearer {{token}}", vectors)

	if report.Passed != len(vectors) {
		t.Errorf("expected 100%% pass rate for secure backend, got %d passed out of %d", report.Passed, report.TotalTests)
	}
	if report.ScorePct < 99.9 {
		t.Errorf("expected security score 100%%, got %.1f%%", report.ScorePct)
	}
}
