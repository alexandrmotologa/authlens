package oidc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RevokeHandler processes RFC 7009 token revocation requests.
type RevokeHandler struct{}

// NewRevokeHandler creates the revocation handler.
func NewRevokeHandler() *RevokeHandler {
	return &RevokeHandler{}
}

// Handle processes POST /oauth/revoke.
func (h *RevokeHandler) Handle(c *gin.Context) {
	// RFC 7009 specifies that regardless of whether the token exists or was already revoked,
	// the server returns HTTP 200 OK.
	c.Status(http.StatusOK)
}
