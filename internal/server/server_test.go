package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexandrmotologa/authlens/internal/jwt"
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

func TestMockProtectedSandbox(t *testing.T) {
	srv := setupTestServer()

	// 1. Missing Authorization header (must return 401)
	reqNoAuth, _ := http.NewRequest("GET", "/api/mock/protected", nil)
	wNoAuth := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", wNoAuth.Code)
	}

	// 2. Valid Admin token (must return 200 OK)
	pAdmin, _ := srv.Personas.Get("admin")
	adminTok, err := jwt.SignPersonaToken(pAdmin, srv.KM, srv.BaseURL, srv.BaseURL+"/api", "RS256", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to sign admin token: %v", err)
	}

	reqAdmin, _ := http.NewRequest("GET", "/api/mock/protected", nil)
	reqAdmin.Header.Set("Authorization", "Bearer "+adminTok)
	wAdmin := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid admin token, got %d (body: %s)", wAdmin.Code, wAdmin.Body.String())
	}

	// 3. Suspended user token (must return 403 Forbidden)
	pSusp, _ := srv.Personas.Get("suspended")
	suspTok, _ := jwt.SignPersonaToken(pSusp, srv.KM, srv.BaseURL, srv.BaseURL+"/api", "RS256", 1*time.Hour)

	reqSusp, _ := http.NewRequest("GET", "/api/mock/protected", nil)
	reqSusp.Header.Set("Authorization", "Bearer "+suspTok)
	wSusp := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wSusp, reqSusp)
	if wSusp.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for suspended user, got %d", wSusp.Code)
	}

	// 4. Role mismatch (Developer requesting required_role=admin -> 403)
	pDev, _ := srv.Personas.Get("developer")
	devTok, _ := jwt.SignPersonaToken(pDev, srv.KM, srv.BaseURL, srv.BaseURL+"/api", "RS256", 1*time.Hour)

	reqDev, _ := http.NewRequest("GET", "/api/mock/protected?required_role=admin", nil)
	reqDev.Header.Set("Authorization", "Bearer "+devTok)
	wDev := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wDev, reqDev)
	if wDev.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for dev missing admin role, got %d", wDev.Code)
	}
}

func TestAuditLogsAndExports(t *testing.T) {
	srv := setupTestServer()

	// Trigger a request to populate audit log
	reqStatus, _ := http.NewRequest("GET", "/api/status", nil)
	wStatus := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wStatus, reqStatus)

	// Fetch audit logs
	reqLogs, _ := http.NewRequest("GET", "/api/audit/logs", nil)
	wLogs := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wLogs, reqLogs)
	if wLogs.Code != http.StatusOK {
		t.Errorf("expected 200 OK for audit logs, got %d", wLogs.Code)
	}

	var logs []server.AuditLogEntry
	_ = json.Unmarshal(wLogs.Body.Bytes(), &logs)
	if len(logs) == 0 {
		t.Error("expected at least 1 audit log entry")
	}

	// Test Postman Export
	reqPostman, _ := http.NewRequest("GET", "/api/export/postman", nil)
	wPostman := httptest.NewRecorder()
	srv.Engine.ServeHTTP(wPostman, reqPostman)
	if wPostman.Code != http.StatusOK {
		t.Errorf("expected 200 OK for postman export, got %d", wPostman.Code)
	}

	var postmanCol map[string]any
	_ = json.Unmarshal(wPostman.Body.Bytes(), &postmanCol)
	if postmanCol["info"] == nil {
		t.Error("expected valid postman collection info object")
	}
}
