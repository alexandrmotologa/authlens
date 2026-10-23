package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alexandrmotologa/authlens/internal/pkce"
	"github.com/alexandrmotologa/authlens/internal/server"
)

func setupTestServer() *server.Server {
	srv, _ := server.NewServer(server.Config{
		Host:    "127.0.0.1",
		Port:    9099,
		BaseURL: "http://127.0.0.1:9099",
	})
	return srv
}

func TestOIDCDiscovery(t *testing.T) {
	srv := setupTestServer()

	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("failed to parse discovery JSON: %v", err)
	}

	if meta["issuer"] != "http://127.0.0.1:9099" {
		t.Errorf("unexpected issuer: %v", meta["issuer"])
	}
	if meta["authorization_endpoint"] != "http://127.0.0.1:9099/oauth/authorize" {
		t.Errorf("unexpected auth endpoint: %v", meta["authorization_endpoint"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := setupTestServer()

	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	srv.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var jwks map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &jwks)
	keysList, ok := jwks["keys"].([]any)
	if !ok || len(keysList) < 2 {
		t.Errorf("expected at least 2 keys in JWKS, got: %v", jwks)
	}
}

func TestEndToEndPKCEFlow(t *testing.T) {
	srv := setupTestServer()

	// 1. Client generates PKCE challenge
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge, err := pkce.ComputeChallenge(verifier, "S256")
	if err != nil {
		t.Fatalf("failed to compute challenge: %v", err)
	}

	// 2. Client initiates GET /oauth/authorize
	authURL := "/oauth/authorize?client_id=test-app&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=" +
		challenge + "&code_challenge_method=S256&persona=admin&state=xyz123"

	reqAuth, _ := http.NewRequest("GET", authURL, nil)
	wAuth := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wAuth, reqAuth)

	if wAuth.Code != http.StatusFound {
		t.Fatalf("expected redirect (302 Found), got %d", wAuth.Code)
	}

	loc := wAuth.Header().Get("Location")
	parsedLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}

	authCode := parsedLoc.Query().Get("code")
	if authCode == "" {
		t.Fatal("expected authorization code in redirect query params")
	}

	// 3. Client attempts token exchange with WRONG verifier (must fail!)
	formFail := url.Values{}
	formFail.Set("grant_type", "authorization_code")
	formFail.Set("code", authCode)
	formFail.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX_WRONG")
	formFail.Set("client_id", "test-app")

	reqFail, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(formFail.Encode()))
	reqFail.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wFail := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wFail, reqFail)

	if wFail.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on invalid verifier, got %d", wFail.Code)
	}

	// 4. Client generates fresh authorization code for successful exchange
	reqAuth2, _ := http.NewRequest("GET", authURL, nil)
	wAuth2 := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wAuth2, reqAuth2)
	parsedLoc2, _ := url.Parse(wAuth2.Header().Get("Location"))
	validCode := parsedLoc2.Query().Get("code")

	// 5. Client attempts token exchange with VALID verifier (must succeed!)
	formSuccess := url.Values{}
	formSuccess.Set("grant_type", "authorization_code")
	formSuccess.Set("code", validCode)
	formSuccess.Set("code_verifier", verifier)
	formSuccess.Set("client_id", "test-app")

	reqSucc, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(formSuccess.Encode()))
	reqSucc.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wSucc := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wSucc, reqSucc)

	if wSucc.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid verifier, got %d (body: %s)", wSucc.Code, wSucc.Body.String())
	}

	var tokenResp map[string]any
	_ = json.Unmarshal(wSucc.Body.Bytes(), &tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("expected access_token in response")
	}
	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("expected id_token in response")
	}

	// 6. Test /userinfo endpoint using the newly acquired Access Token
	reqUser, _ := http.NewRequest("GET", "/userinfo", nil)
	reqUser.Header.Set("Authorization", "Bearer "+accessToken)
	wUser := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wUser, reqUser)

	if wUser.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on userinfo, got %d (body: %s)", wUser.Code, wUser.Body.String())
	}

	var userInfo map[string]any
	_ = json.Unmarshal(wUser.Body.Bytes(), &userInfo)
	if userInfo["email"] != "admin@local.test" {
		t.Errorf("expected admin email, got %v", userInfo["email"])
	}

	// 7. Test /oauth/introspect endpoint
	formIntro := url.Values{}
	formIntro.Set("token", accessToken)
	reqIntro, _ := http.NewRequest("POST", "/oauth/introspect", strings.NewReader(formIntro.Encode()))
	reqIntro.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wIntro := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wIntro, reqIntro)

	if wIntro.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on introspect, got %d", wIntro.Code)
	}
	var introResp map[string]any
	_ = json.Unmarshal(wIntro.Body.Bytes(), &introResp)
	if introResp["active"] != true {
		t.Errorf("expected active: true in token introspection")
	}
}
