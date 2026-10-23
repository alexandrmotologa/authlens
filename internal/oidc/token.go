package oidc

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
	"github.com/alexandrmotologa/authlens/internal/pkce"
	"github.com/gin-gonic/gin"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenHandler processes RFC 6749 / RFC 7636 token exchange requests.
type TokenHandler struct {
	codes    *AuthCodeStore
	traces   *pkce.TraceStore
	personas *persona.Registry
	km       *keys.KeyManager
	baseURL  string
}

// NewTokenHandler creates the token endpoint handler.
func NewTokenHandler(codes *AuthCodeStore, traces *pkce.TraceStore, personas *persona.Registry, km *keys.KeyManager, baseURL string) *TokenHandler {
	return &TokenHandler{
		codes:    codes,
		traces:   traces,
		personas: personas,
		km:       km,
		baseURL:  baseURL,
	}
}

// Handle processes POST /oauth/token.
func (h *TokenHandler) Handle(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	if grantType == "" {
		// Fallback to JSON payload if Content-Type is application/json
		var jsonReq struct {
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			CodeVerifier string `json:"code_verifier"`
			ClientID     string `json:"client_id"`
			RefreshToken string `json:"refresh_token"`
			Scope        string `json:"scope"`
		}
		if err := c.ShouldBindJSON(&jsonReq); err == nil {
			grantType = jsonReq.GrantType
			c.Set("json_req", jsonReq)
		}
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCode(c)
	case "client_credentials":
		h.handleClientCredentials(c)
	case "refresh_token":
		h.handleRefreshToken(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("Grant type %q is not supported. Use authorization_code, client_credentials, or refresh_token", grantType),
		})
	}
}

func (h *TokenHandler) handleAuthorizationCode(c *gin.Context) {
	code := c.PostForm("code")
	verifier := c.PostForm("code_verifier")
	clientID := c.PostForm("client_id")

	if code == "" {
		if raw, exists := c.Get("json_req"); exists {
			type jReq struct {
				Code         string `json:"code"`
				CodeVerifier string `json:"code_verifier"`
				ClientID     string `json:"client_id"`
			}
			if r, ok := raw.(jReq); ok {
				code = r.Code
				verifier = r.CodeVerifier
				clientID = r.ClientID
			}
		}
	}

	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing 'code' parameter",
		})
		return
	}

	rec, err := h.codes.Consume(code)
	if err != nil {
		h.traces.RecordExchange(code, verifier, "", "failed", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	// Validate PKCE if challenge was supplied during authorization
	if rec.CodeChallenge != "" {
		if verifier == "" {
			h.traces.RecordExchange(code, "", "", "failed", "code_verifier required for PKCE flow")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "PKCE enforced: 'code_verifier' parameter is missing",
			})
			return
		}

		computedChallenge, computeErr := pkce.ComputeChallenge(verifier, rec.CodeChallengeMethod)
		if computeErr != nil {
			h.traces.RecordExchange(code, verifier, "", "failed", computeErr.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": computeErr.Error(),
			})
			return
		}

		if verifyErr := pkce.VerifyChallenge(verifier, rec.CodeChallenge, rec.CodeChallengeMethod); verifyErr != nil {
			h.traces.RecordExchange(code, verifier, computedChallenge, "failed", verifyErr.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "PKCE verification failed: code_verifier does not match code_challenge",
			})
			return
		}

		h.traces.RecordExchange(code, verifier, computedChallenge, "success", "")
	} else {
		h.traces.RecordExchange(code, verifier, "", "success", "")
	}

	// Retrieve persona
	p, err := h.personas.Get(rec.PersonaID)
	if err != nil {
		p, _ = h.personas.Get("admin")
	}

	now := time.Now().UTC()
	ttl := 1 * time.Hour

	// 1. Generate ID Token (RFC OpenID Connect Core 1.0)
	idClaims := jwtgo.MapClaims{
		"iss":            h.baseURL,
		"sub":            p.Sub,
		"aud":            rec.ClientID,
		"exp":            now.Add(ttl).Unix(),
		"iat":            now.Unix(),
		"auth_time":      now.Unix(),
		"name":           p.Name,
		"email":          p.Email,
		"email_verified": p.EmailVerified,
		"roles":          p.Roles,
		"persona_id":     p.ID,
	}
	idTokenObj := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, idClaims)
	idTokenObj.Header["kid"] = h.km.ActiveRSA.ID
	idToken, err := idTokenObj.SignedString(h.km.ActiveRSA.RSAPriv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign id_token"})
		return
	}

	// 2. Generate Access Token (OAuth 2.1)
	accessClaims := jwtgo.MapClaims{
		"iss":         h.baseURL,
		"sub":         p.Sub,
		"aud":         []string{rec.ClientID, h.baseURL + "/api"},
		"exp":         now.Add(ttl).Unix(),
		"nbf":         now.Unix(),
		"iat":         now.Unix(),
		"jti":         uuid.New().String(),
		"scope":       rec.Scope,
		"client_id":   clientID,
		"roles":       p.Roles,
		"permissions": p.Permissions,
		"status":      p.Status,
		"persona_id":  p.ID,
	}
	accessTokenObj := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, accessClaims)
	accessTokenObj.Header["kid"] = h.km.ActiveRSA.ID
	accessToken, err := accessTokenObj.SignedString(h.km.ActiveRSA.RSAPriv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign access_token"})
		return
	}

	refreshToken := fmt.Sprintf("rt_%s_%s", p.ID, uuid.New().String()[:16])

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"expires_in":    int(ttl.Seconds()),
		"scope":         rec.Scope,
	})
}

func (h *TokenHandler) handleClientCredentials(c *gin.Context) {
	clientID := c.DefaultPostForm("client_id", "service-client-app")
	scope := c.DefaultPostForm("scope", "system:read system:write")

	now := time.Now().UTC()
	ttl := 1 * time.Hour

	claims := jwtgo.MapClaims{
		"iss":         h.baseURL,
		"sub":         "svc_" + clientID,
		"aud":         h.baseURL + "/api",
		"exp":         now.Add(ttl).Unix(),
		"iat":         now.Unix(),
		"jti":         uuid.New().String(),
		"scope":       scope,
		"client_id":   clientID,
		"roles":       []string{"machine", "service_account"},
		"permissions": []string{"*"},
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = h.km.ActiveRSA.ID
	accessToken, err := token.SignedString(h.km.ActiveRSA.RSAPriv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign machine token"})
		return
	}

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"token_type":   "Bearer",
		"access_token": accessToken,
		"expires_in":   int(ttl.Seconds()),
		"scope":        scope,
	})
}

func (h *TokenHandler) handleRefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing refresh_token parameter",
		})
		return
	}

	// Parse persona from refresh token prefix or default to admin
	personaID := "admin"
	if strings.HasPrefix(refreshToken, "rt_") {
		parts := strings.Split(refreshToken, "_")
		if len(parts) >= 2 {
			personaID = parts[1]
		}
	}

	p, err := h.personas.Get(personaID)
	if err != nil {
		p, _ = h.personas.Get("admin")
	}

	now := time.Now().UTC()
	ttl := 1 * time.Hour

	accessClaims := jwtgo.MapClaims{
		"iss":         h.baseURL,
		"sub":         p.Sub,
		"aud":         h.baseURL + "/api",
		"exp":         now.Add(ttl).Unix(),
		"iat":         now.Unix(),
		"jti":         uuid.New().String(),
		"roles":       p.Roles,
		"permissions": p.Permissions,
		"persona_id":  p.ID,
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, accessClaims)
	token.Header["kid"] = h.km.ActiveRSA.ID
	accessToken, err := token.SignedString(h.km.ActiveRSA.RSAPriv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign refreshed token"})
		return
	}

	newRefreshToken := fmt.Sprintf("rt_%s_%s", p.ID, uuid.New().String()[:16])

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    int(ttl.Seconds()),
	})
}
