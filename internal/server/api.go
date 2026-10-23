package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrmotologa/authlens/internal/fuzzer"
	"github.com/alexandrmotologa/authlens/internal/jwt"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/oidc"
	"github.com/alexandrmotologa/authlens/internal/persona"
	"github.com/alexandrmotologa/authlens/internal/pkce"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Server encapsulates the HTTP router, state managers, and background services.
type Server struct {
	Engine     *gin.Engine
	KM         *keys.KeyManager
	Personas   *persona.Registry
	Codes      *oidc.AuthCodeStore
	Traces     *pkce.TraceStore
	Fuzzer     *fuzzer.AttackGenerator
	BaseURL    string
	Port       int
	StartTime  time.Time
	httpServer *http.Server
}

// Config defines server initialization options.
type Config struct {
	Host    string
	Port    int
	BaseURL string
}

// NewServer constructs the complete AuthLens application server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = 9099
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
	}

	km, err := keys.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KeyManager: %w", err)
	}

	personas := persona.NewRegistry()
	codes := oidc.NewAuthCodeStore()
	traces := pkce.NewTraceStore(200)
	fuzzGen := fuzzer.NewAttackGenerator(km, cfg.BaseURL)

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())

	s := &Server{
		Engine:    engine,
		KM:        km,
		Personas:  personas,
		Codes:     codes,
		Traces:    traces,
		Fuzzer:    fuzzGen,
		BaseURL:   cfg.BaseURL,
		Port:      cfg.Port,
		StartTime: time.Now().UTC(),
	}

	s.setupRoutes()
	return s, nil
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Expose-Headers", "Content-Length, WWW-Authenticate")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (s *Server) setupRoutes() {
	// Standard OpenID Connect & OAuth 2.1 Endpoints
	s.Engine.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, oidc.GetDiscoveryMetadata(s.BaseURL))
	})

	s.Engine.GET("/.well-known/jwks.json", func(c *gin.Context) {
		jwks, err := s.KM.GetJWKS()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build JWKS"})
			return
		}
		c.JSON(http.StatusOK, jwks)
	})

	authHandler := oidc.NewAuthorizeHandler(s.Codes, s.Traces, s.Personas, s.BaseURL)
	s.Engine.GET("/oauth/authorize", authHandler.Handle)
	s.Engine.POST("/oauth/authorize", authHandler.Handle)

	tokenHandler := oidc.NewTokenHandler(s.Codes, s.Traces, s.Personas, s.KM, s.BaseURL)
	s.Engine.POST("/oauth/token", tokenHandler.Handle)

	userInfoHandler := oidc.NewUserInfoHandler(s.KM, s.Personas)
	s.Engine.GET("/userinfo", userInfoHandler.Handle)
	s.Engine.POST("/userinfo", userInfoHandler.Handle)

	introspectHandler := oidc.NewIntrospectHandler(s.KM)
	s.Engine.POST("/oauth/introspect", introspectHandler.Handle)

	revokeHandler := oidc.NewRevokeHandler()
	s.Engine.POST("/oauth/revoke", revokeHandler.Handle)

	// Web Studio Management REST API
	api := s.Engine.Group("/api")
	{
		api.GET("/status", s.handleStatus)
		api.GET("/personas", s.handleListPersonas)
		api.POST("/personas", s.handleCreatePersona)
		api.POST("/personas/:id/token", s.handlePersonaToken)

		api.GET("/pkce/traces", s.handleListTraces)
		api.DELETE("/pkce/traces", s.handleClearTraces)
		api.POST("/pkce/simulate", s.handleSimulatePKCE)

		api.POST("/jwt/decode", s.handleDecodeJWT)
		api.POST("/jwt/verify", s.handleVerifyJWT)
		api.POST("/jwt/sign", s.handleSignJWT)

		api.GET("/fuzzer/vectors", s.handleFuzzerVectors)
		api.POST("/fuzzer/run", s.handleRunFuzzer)

		api.POST("/keys/rotate", s.handleRotateKeys)
		api.GET("/keys/export", s.handleExportKeys)

		api.GET("/events", s.handleEventsSSE)
	}

	// Register embedded frontend static files
	RegisterStatic(s.Engine)
}

func (s *Server) handleStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"name":           "AuthLens",
		"version":        "1.0.0",
		"base_url":       s.BaseURL,
		"port":           s.Port,
		"uptime_seconds": int64(time.Since(s.StartTime).Seconds()),
		"active_rsa_kid": s.KM.ActiveRSA.ID,
		"active_ec_kid":  s.KM.ActiveECDSA.ID,
		"personas_count": len(s.Personas.List()),
		"traces_count":   len(s.Traces.GetAllTraces()),
	})
}

func (s *Server) handleListPersonas(c *gin.Context) {
	c.JSON(http.StatusOK, s.Personas.List())
}

func (s *Server) handleCreatePersona(c *gin.Context) {
	var p persona.Persona
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if p.ID == "" {
		p.ID = "custom_" + uuid.New().String()[:8]
	}
	if p.Sub == "" {
		p.Sub = "usr_" + p.ID
	}
	if p.Status == "" {
		p.Status = "active"
	}
	s.Personas.Register(&p)
	c.JSON(http.StatusCreated, p)
}

func (s *Server) handlePersonaToken(c *gin.Context) {
	personaID := c.Param("id")
	p, err := s.Personas.Get(personaID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	alg := c.DefaultQuery("alg", "RS256")
	tokenStr, err := jwt.SignPersonaToken(p, s.KM, s.BaseURL, s.BaseURL+"/api", alg, 2*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token_type":   "Bearer",
		"access_token": tokenStr,
		"expires_in":   7200,
		"persona":      p,
		"curl":         fmt.Sprintf("curl -H \"Authorization: Bearer %s\" %s/userinfo", tokenStr, s.BaseURL),
	})
}

func (s *Server) handleListTraces(c *gin.Context) {
	c.JSON(http.StatusOK, s.Traces.GetAllTraces())
}

func (s *Server) handleClearTraces(c *gin.Context) {
	s.Traces.Clear()
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

func (s *Server) handleSimulatePKCE(c *gin.Context) {
	var req struct {
		PersonaID string `json:"persona_id"`
		Verifier  string `json:"code_verifier"`
		Method    string `json:"method"`
		ClientID  string `json:"client_id"`
	}
	_ = c.ShouldBindJSON(&req)

	if req.PersonaID == "" {
		req.PersonaID = "admin"
	}
	if req.Method == "" {
		req.Method = "S256"
	}
	if req.ClientID == "" {
		req.ClientID = "authlens-pkce-simulator"
	}
	if req.Verifier == "" {
		req.Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	}

	challenge, err := pkce.ComputeChallenge(req.Verifier, req.Method)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p, _ := s.Personas.Get(req.PersonaID)
	if p == nil {
		p, _ = s.Personas.Get("admin")
	}

	redirectURI := "http://localhost:3000/callback"
	state := uuid.New().String()[:8]

	// 1. Authorize phase
	rec := s.Codes.Create(req.ClientID, redirectURI, "openid profile email", state, req.PersonaID, challenge, req.Method)
	_ = s.Traces.RecordInitiation(rec.Code, req.ClientID, redirectURI, "openid profile email", state, req.PersonaID, challenge, req.Method)

	// 2. Token exchange phase
	computed, computeErr := pkce.ComputeChallenge(req.Verifier, req.Method)
	if computeErr != nil {
		s.Traces.RecordExchange(rec.Code, req.Verifier, "", "failed", computeErr.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": computeErr.Error()})
		return
	}

	if verifyErr := pkce.VerifyChallenge(req.Verifier, challenge, req.Method); verifyErr != nil {
		s.Traces.RecordExchange(rec.Code, req.Verifier, computed, "failed", verifyErr.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": verifyErr.Error()})
		return
	}

	updatedTrace := s.Traces.RecordExchange(rec.Code, req.Verifier, computed, "success", "")

	tokenStr, _ := jwt.SignPersonaToken(p, s.KM, s.BaseURL, s.BaseURL+"/api", "RS256", 1*time.Hour)

	c.JSON(http.StatusOK, gin.H{
		"trace":         updatedTrace,
		"code":          rec.Code,
		"verifier":      req.Verifier,
		"challenge":     challenge,
		"method":        req.Method,
		"access_token":  tokenStr,
		"computed_hash": computed,
	})
}

func (s *Server) handleDecodeJWT(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

	decoded, err := jwt.DecodeOffline(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, decoded)
}

func (s *Server) handleVerifyJWT(c *gin.Context) {
	var req struct {
		Token     string `json:"token"`
		CustomKey string `json:"custom_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

	res, err := jwt.ValidateOffline(req.Token, s.KM, req.CustomKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

func (s *Server) handleSignJWT(c *gin.Context) {
	var req struct {
		Claims    map[string]any `json:"claims"`
		Algorithm string         `json:"algorithm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Algorithm == "" {
		req.Algorithm = "RS256"
	}
	if req.Claims == nil {
		req.Claims = make(map[string]any)
	}

	now := time.Now().UTC()
	if _, ok := req.Claims["iss"]; !ok {
		req.Claims["iss"] = s.BaseURL
	}
	if _, ok := req.Claims["iat"]; !ok {
		req.Claims["iat"] = now.Unix()
	}
	if _, ok := req.Claims["exp"]; !ok {
		req.Claims["exp"] = now.Add(1 * time.Hour).Unix()
	}

	tokenStr, err := jwt.SignCustom(req.Claims, s.KM, req.Algorithm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenStr,
	})
}

func (s *Server) handleFuzzerVectors(c *gin.Context) {
	p, _ := s.Personas.Get("admin")
	vectors, err := s.Fuzzer.GenerateAll(p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, vectors)
}

func (s *Server) handleRunFuzzer(c *gin.Context) {
	var req struct {
		TargetURL    string `json:"target_url"`
		Method       string `json:"method"`
		HeaderFormat string `json:"header_format"`
		PersonaID    string `json:"persona_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.TargetURL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_url is required"})
		return
	}

	p, err := s.Personas.Get(req.PersonaID)
	if err != nil {
		p, _ = s.Personas.Get("admin")
	}

	vectors, err := s.Fuzzer.GenerateAll(p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	report := fuzzer.RunSuite(c.Request.Context(), req.TargetURL, req.Method, req.HeaderFormat, vectors)
	c.JSON(http.StatusOK, report)
}

func (s *Server) handleRotateKeys(c *gin.Context) {
	if err := s.KM.RotateKeys(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":         "rotated",
		"active_rsa_kid": s.KM.ActiveRSA.ID,
		"active_ec_kid":  s.KM.ActiveECDSA.ID,
		"rotated_count":  len(s.KM.RotatedKeys),
	})
}

func (s *Server) handleExportKeys(c *gin.Context) {
	rsaPEM, _ := s.KM.ExportRSAPublicPEM()
	ecPEM, _ := s.KM.ExportECPublicPEM()
	jwks, _ := s.KM.GetJWKS()

	c.JSON(http.StatusOK, gin.H{
		"rsa_public_pem": rsaPEM,
		"ec_public_pem":  ecPEM,
		"jwks":           jwks,
	})
}

func (s *Server) handleEventsSSE(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	ch := s.Traces.Subscribe()
	defer s.Traces.Unsubscribe(ch)

	// Send initial connection event
	c.SSEvent("connected", gin.H{"time": time.Now().UTC()})
	c.Writer.Flush()

	notify := c.Request.Context().Done()
	for {
		select {
		case <-notify:
			return
		case trace, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(trace)
			c.SSEvent("trace", string(b))
			c.Writer.Flush()
		}
	}
}

// Start launches the HTTP server listening on the configured address.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.Port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.Engine,
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully terminates the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
