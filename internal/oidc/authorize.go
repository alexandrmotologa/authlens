package oidc

import (
	"fmt"
	"html/template"
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
	action := c.PostForm("action")
	autoApprove := c.Query("auto_approve") == "true" || c.PostForm("auto_approve") == "true"
	prompt := c.Query("prompt")

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

	// 1. Handle explicit Deny from consent screen
	if action == "deny" {
		if redirectURI != "" {
			if parsedRedirect, err := url.Parse(redirectURI); err == nil {
				q := parsedRedirect.Query()
				q.Set("error", "access_denied")
				q.Set("error_description", "User rejected authorization consent")
				if state != "" {
					q.Set("state", state)
				}
				parsedRedirect.RawQuery = q.Encode()
				c.Redirect(http.StatusFound, parsedRedirect.String())
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "User rejected authorization consent",
		})
		return
	}

	// 2. Interactive Consent Screen for Browsers
	isHTML := strings.Contains(c.GetHeader("Accept"), "text/html")
	if c.Request.Method == "GET" && isHTML && !autoApprove && prompt != "none" {
		h.renderConsentPage(c, clientID, redirectURI, responseType, scope, state, codeChallenge, codeChallengeMethod, personaID)
		return
	}

	// 3. Resolve Persona
	if personaID == "" {
		personaID = "admin"
	}
	p, err := h.personas.Get(personaID)
	if err != nil {
		personaID = "admin"
		p, _ = h.personas.Get("admin")
	}

	if scope == "" {
		scope = strings.Join(p.Scopes, " ")
	}

	// 4. Create authorization code record
	rec := h.codes.Create(clientID, redirectURI, scope, state, personaID, codeChallenge, codeChallengeMethod)

	// 5. Record telemetry trace
	h.traces.RecordInitiation(rec.Code, clientID, redirectURI, scope, state, personaID, codeChallenge, codeChallengeMethod)

	// 6. Redirect or return JSON
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

func (h *AuthorizeHandler) renderConsentPage(c *gin.Context, clientID, redirectURI, responseType, scope, state, challenge, method, currentPersona string) {
	allPersonas := h.personas.List()
	if currentPersona == "" {
		currentPersona = "admin"
	}

	scopeList := strings.Fields(scope)
	if len(scopeList) == 0 {
		scopeList = []string{"openid", "profile", "email"}
	}

	data := struct {
		ClientID            string
		RedirectURI         string
		ResponseType        string
		Scope               string
		Scopes              []string
		State               string
		CodeChallenge       string
		CodeChallengeMethod string
		CurrentPersona      string
		Personas            []*persona.Persona
	}{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		Scopes:              scopeList,
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CurrentPersona:      currentPersona,
		Personas:            allPersonas,
	}

	const tmplHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AuthLens — OAuth 2.1 Consent &amp; Persona Selector</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #070A12;
      color: #E2E8F0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #0B0F19;
      border: 1px solid #1E293B;
      border-radius: 1rem;
      max-width: 480px;
      width: 100%;
      padding: 2rem;
      box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid #1E293B;
    }
    .logo {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: #070A12;
      border: 1px solid #0EA5E9;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .logo img { width: 24px; height: 24px; }
    h1 { font-size: 1.15rem; font-weight: 700; color: #FFF; }
    .subtitle { font-size: 0.8rem; color: #94A3B8; }
    .client-badge {
      background: #141D32;
      border: 1px solid #1E293B;
      padding: 0.75rem 1rem;
      border-radius: 0.75rem;
      margin-bottom: 1.25rem;
      font-size: 0.85rem;
    }
    .client-badge strong { color: #38BDF8; font-family: monospace; }
    .section-title {
      font-size: 0.75rem;
      font-weight: 700;
      color: #94A3B8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.5rem;
    }
    .scopes {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-bottom: 1.25rem;
    }
    .scope-pill {
      background: #090D16;
      border: 1px solid #1E293B;
      color: #38BDF8;
      font-size: 0.75rem;
      font-family: monospace;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
    }
    .persona-list {
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
      margin-bottom: 1.5rem;
    }
    .persona-option {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 1rem;
      border: 1px solid #1E293B;
      border-radius: 0.75rem;
      background: #090D16;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .persona-option:hover {
      border-color: #38BDF8;
      background: #0F172A;
    }
    .persona-option input[type="radio"] {
      accent-color: #0EA5E9;
      width: 16px;
      height: 16px;
    }
    .persona-info { flex: 1; }
    .persona-name { font-size: 0.85rem; font-weight: 600; color: #FFF; }
    .persona-meta { font-size: 0.75rem; color: #64748B; font-family: monospace; }
    .actions {
      display: flex;
      gap: 0.75rem;
    }
    button {
      flex: 1;
      padding: 0.75rem;
      border-radius: 0.6rem;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s;
    }
    .btn-approve {
      background: #0284C7;
      color: #FFF;
      border: none;
    }
    .btn-approve:hover { background: #0EA5E9; }
    .btn-deny {
      background: #1E293B;
      color: #94A3B8;
      border: 1px solid #334155;
    }
    .btn-deny:hover { background: #334155; color: #FFF; }
    .footer-note {
      text-align: center;
      font-size: 0.75rem;
      color: #475569;
      margin-top: 1.25rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="logo">
        <img src="/logo.svg" alt="AuthLens">
      </div>
      <div>
        <h1>AuthLens Authorization</h1>
        <div class="subtitle">OAuth 2.1 PKCE Consent &amp; Identity Picker</div>
      </div>
    </div>

    <div class="client-badge">
      Application <strong>{{.ClientID}}</strong> is requesting authorization.
    </div>

    <div class="section-title">Requested Scopes</div>
    <div class="scopes">
      {{range .Scopes}}
        <span class="scope-pill">{{.}}</span>
      {{end}}
    </div>

    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="{{.ClientID}}">
      <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
      <input type="hidden" name="response_type" value="{{.ResponseType}}">
      <input type="hidden" name="scope" value="{{.Scope}}">
      <input type="hidden" name="state" value="{{.State}}">
      <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
      <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

      <div class="section-title">Choose Simulated User Persona</div>
      <div class="persona-list">
        {{range .Personas}}
        <label class="persona-option">
          <input type="radio" name="persona" value="{{.ID}}" {{if eq .ID $.CurrentPersona}}checked{{end}}>
          <div class="persona-info">
            <div class="persona-name">{{.Name}}</div>
            <div class="persona-meta">{{.Email}} &bull; roles: [{{range $i, $r := .Roles}}{{if $i}}, {{end}}{{$r}}{{end}}]</div>
          </div>
        </label>
        {{end}}
      </div>

      <div class="actions">
        <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
        <button type="submit" name="action" value="approve" class="btn-approve">Approve Access</button>
      </div>
    </form>

    <div class="footer-note">
      AuthLens Local Provider &bull; Append <code>&amp;auto_approve=true</code> to bypass
    </div>
  </div>
</body>
</html>`

	t, err := template.New("consent").Parse(tmplHTML)
	if err != nil {
		c.String(http.StatusInternalServerError, "template error")
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(c.Writer, data)
}
