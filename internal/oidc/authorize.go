package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/alexandrmotologa/authlens/internal/persona"
	"github.com/alexandrmotologa/authlens/internal/pkce"
	"github.com/gin-gonic/gin"
)

// AuthorizeHandler processes RFC 6749 / OAuth 2.1 authorization requests.
type AuthorizeHandler struct {
	codes      *AuthCodeStore
	traces     *pkce.TraceStore
	personas   *persona.Registry
	defaultURL string
}

// NewAuthorizeHandler creates the handler instance.
func NewAuthorizeHandler(codes *AuthCodeStore, traces *pkce.TraceStore, personas *persona.Registry, defaultURL string) *AuthorizeHandler {
	return &AuthorizeHandler{
		codes:      codes,
		traces:     traces,
		personas:   personas,
		defaultURL: defaultURL,
	}
}

// Handle processes GET and POST /oauth/authorize.
func (h *AuthorizeHandler) Handle(c *gin.Context) {
	clientID := c.DefaultQuery("client_id", c.PostForm("client_id"))
	redirectURI := c.DefaultQuery("redirect_uri", c.PostForm("redirect_uri"))
	responseType := c.DefaultQuery("response_type", c.PostForm("response_type"))
	scope := c.DefaultQuery("scope", c.PostForm("scope"))
	state := c.DefaultQuery("state", c.PostForm("state"))
	codeChallenge := c.DefaultQuery("code_challenge", c.PostForm("code_challenge"))
	codeChallengeMethod := c.DefaultQuery("code_challenge_method", c.PostForm("code_challenge_method"))
	personaID := c.DefaultQuery("persona", c.PostForm("persona"))

	if clientID == "" {
		clientID = "local-client-app"
	}
	if responseType == "" {
		responseType = "code"
	}
	if !strings.Contains(responseType, "code") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "AuthLens only supports response_type=code (OAuth 2.1)",
		})
		return
	}

	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	if personaID == "" {
		personaID = "admin"
	}

	// Verify persona exists
	p, err := h.personas.Get(personaID)
	if err != nil {
		personaID = "admin"
		p, _ = h.personas.Get("admin")
	}

	if scope == "" {
		scope = strings.Join(p.Scopes, " ")
	}

	// Create authorization code record
	rec := h.codes.Create(clientID, redirectURI, scope, state, personaID, codeChallenge, codeChallengeMethod)

	// Record telemetry trace
	h.traces.RecordInitiation(rec.Code, clientID, redirectURI, scope, state, personaID, codeChallenge, codeChallengeMethod)

	// If redirect_uri is provided, perform browser redirect
	if redirectURI != "" {
		parsedRedirect, err := url.Parse(redirectURI)
		if err == nil {
			q := parsedRedirect.Query()
			q.Set("code", rec.Code)
			if state != "" {
				q.Set("state", state)
			}
			parsedRedirect.RawQuery = q.Encode()

			// Check if client expects JSON or direct redirect
			accept := c.GetHeader("Accept")
			if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
				c.JSON(http.StatusOK, gin.H{
					"code":         rec.Code,
					"state":        state,
					"redirect_url": parsedRedirect.String(),
				})
				return
			}

			c.Redirect(http.StatusFound, parsedRedirect.String())
			return
		}
	}

	// Fallback to JSON response if no redirect_uri provided
	c.JSON(http.StatusOK, gin.H{
		"code":                  rec.Code,
		"state":                 state,
		"client_id":             clientID,
		"persona":               personaID,
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
		"message":               fmt.Sprintf("Authorization granted for persona %s", p.Name),
	})
}
