package oidc

import (
	"net/http"
	"strings"

	"github.com/alexandrmotologa/authlens/internal/jwt"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
	"github.com/gin-gonic/gin"
)

// UserInfoHandler serves the RFC OpenID Connect /userinfo endpoint.
type UserInfoHandler struct {
	km       *keys.KeyManager
	personas *persona.Registry
}

// NewUserInfoHandler creates the userinfo handler.
func NewUserInfoHandler(km *keys.KeyManager, personas *persona.Registry) *UserInfoHandler {
	return &UserInfoHandler{
		km:       km,
		personas: personas,
	}
}

// Handle processes GET and POST /userinfo.
func (h *UserInfoHandler) Handle(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.Header("WWW-Authenticate", "Bearer error=\"unauthorized\", error_description=\"Authorization header missing\"")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "error_description": "Bearer token required"})
		return
	}

	tokenStr := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	valRes, err := jwt.ValidateOffline(tokenStr, h.km, "")
	if err != nil || !valRes.Valid {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Cryptographic validation failed\"")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": valRes.Error,
		})
		return
	}

	decoded, _ := jwt.DecodeOffline(tokenStr)
	personaID, _ := decoded.Payload["persona_id"].(string)

	var p *persona.Persona
	if personaID != "" {
		p, _ = h.personas.Get(personaID)
	}
	if p == nil {
		// Fallback to claims in token
		c.JSON(http.StatusOK, decoded.Payload)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":            p.Sub,
		"name":           p.Name,
		"email":          p.Email,
		"email_verified": p.EmailVerified,
		"roles":          p.Roles,
		"permissions":    p.Permissions,
		"status":         p.Status,
		"persona_id":     p.ID,
	})
}
