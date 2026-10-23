package oidc

import (
	"net/http"
	"strings"

	"github.com/alexandrmotologa/authlens/internal/jwt"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/gin-gonic/gin"
)

// IntrospectHandler serves RFC 7662 OAuth 2.0 Token Introspection.
type IntrospectHandler struct {
	km *keys.KeyManager
}

// NewIntrospectHandler creates the introspection handler.
func NewIntrospectHandler(km *keys.KeyManager) *IntrospectHandler {
	return &IntrospectHandler{km: km}
}

// Handle processes POST /oauth/introspect.
func (h *IntrospectHandler) Handle(c *gin.Context) {
	tokenStr := c.PostForm("token")
	if tokenStr == "" {
		tokenStr = c.Query("token")
	}

	if tokenStr == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	tokenStr = strings.TrimSpace(tokenStr)
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	valRes, err := jwt.ValidateOffline(tokenStr, h.km, "")
	if err != nil || !valRes.Valid {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	decoded, err := jwt.DecodeOffline(tokenStr)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	resp := gin.H{
		"active":    true,
		"sub":       decoded.Subject,
		"iss":       decoded.Issuer,
		"client_id": decoded.Payload["client_id"],
		"scope":     decoded.Payload["scope"],
		"roles":     decoded.Payload["roles"],
	}

	if decoded.ExpiresAt != nil {
		resp["exp"] = decoded.ExpiresAt.Unix()
	}
	if decoded.IssuedAt != nil {
		resp["iat"] = decoded.IssuedAt.Unix()
	}
	if len(decoded.Audience) > 0 {
		resp["aud"] = decoded.Audience
	}

	c.JSON(http.StatusOK, resp)
}
