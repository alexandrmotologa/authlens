package server

// BuildPostmanCollection constructs a Postman v2.1 collection JSON map.
func BuildPostmanCollection(baseURL string) map[string]any {
	return map[string]any{
		"info": map[string]any{
			"_postman_id": "authlens-postman-collection",
			"name":        "AuthLens Local OIDC & OAuth 2.1 Suite",
			"description": "Pre-configured test collection for AuthLens local OIDC provider, PKCE code exchange, and JWT security endpoints.",
			"schema":      "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		"variable": []map[string]any{
			{"key": "baseUrl", "value": baseURL, "type": "string"},
			{"key": "clientId", "value": "my-local-app", "type": "string"},
			{"key": "codeVerifier", "value": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "type": "string"},
			{"key": "codeChallenge", "value": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "type": "string"},
			{"key": "accessToken", "value": "", "type": "string"},
		},
		"item": []map[string]any{
			{
				"name": "01. OIDC Discovery",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/.well-known/openid-configuration",
						"host": []string{"{{baseUrl}}"},
						"path": []string{".well-known", "openid-configuration"},
					},
					"description": "Fetch RFC 8414 OpenID Connect discovery metadata.",
				},
			},
			{
				"name": "02. JWKS Public Keystore",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/.well-known/jwks.json",
						"host": []string{"{{baseUrl}}"},
						"path": []string{".well-known", "jwks.json"},
					},
					"description": "Fetch RFC 7517 JSON Web Key Set with active and rotated RSA, ECDSA, and Ed25519 keys.",
				},
			},
			{
				"name": "03. Authorize with PKCE (Auto-Approve Admin)",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{
						{"key": "Accept", "value": "application/json", "type": "text"},
					},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/oauth/authorize?client_id={{clientId}}&response_type=code&scope=openid profile email admin&code_challenge={{codeChallenge}}&code_challenge_method=S256&persona=admin&auto_approve=true",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"oauth", "authorize"},
						"query": []map[string]any{
							{"key": "client_id", "value": "{{clientId}}"},
							{"key": "response_type", "value": "code"},
							{"key": "scope", "value": "openid profile email admin"},
							{"key": "code_challenge", "value": "{{codeChallenge}}"},
							{"key": "code_challenge_method", "value": "S256"},
							{"key": "persona", "value": "admin"},
							{"key": "auto_approve", "value": "true"},
						},
					},
				},
			},
			{
				"name": "04. Token Exchange (PKCE S256)",
				"request": map[string]any{
					"method": "POST",
					"header": []map[string]any{
						{"key": "Content-Type", "value": "application/x-www-form-urlencoded", "type": "text"},
					},
					"body": map[string]any{
						"mode": "urlencoded",
						"urlencoded": []map[string]any{
							{"key": "grant_type", "value": "authorization_code", "type": "text"},
							{"key": "client_id", "value": "{{clientId}}", "type": "text"},
							{"key": "code_verifier", "value": "{{codeVerifier}}", "type": "text"},
							{"key": "code", "value": "PASTE_CODE_HERE", "type": "text"},
						},
					},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/oauth/token",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"oauth", "token"},
					},
				},
			},
			{
				"name": "05. UserInfo (Bearer Auth)",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{
						{"key": "Authorization", "value": "Bearer {{accessToken}}", "type": "text"},
					},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/userinfo",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"userinfo"},
					},
				},
			},
			{
				"name": "06. Token Introspection (RFC 7662)",
				"request": map[string]any{
					"method": "POST",
					"header": []map[string]any{
						{"key": "Content-Type", "value": "application/x-www-form-urlencoded", "type": "text"},
					},
					"body": map[string]any{
						"mode": "urlencoded",
						"urlencoded": []map[string]any{
							{"key": "token", "value": "{{accessToken}}", "type": "text"},
						},
					},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/oauth/introspect",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"oauth", "introspect"},
					},
				},
			},
			{
				"name": "07. Mock Protected Resource (Valid Token)",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{
						{"key": "Authorization", "value": "Bearer {{accessToken}}", "type": "text"},
					},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/api/mock/protected",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"api", "mock", "protected"},
					},
					"description": "Tests AuthLens built-in protected resource sandbox. Expects 200 OK when bearer token is valid.",
				},
			},
			{
				"name": "08. Mock Protected Resource (Missing Token - Expect 401)",
				"request": map[string]any{
					"method": "GET",
					"header": []map[string]any{},
					"url": map[string]any{
						"raw":  "{{baseUrl}}/api/mock/protected",
						"host": []string{"{{baseUrl}}"},
						"path": []string{"api", "mock", "protected"},
					},
					"description": "Tests that unauthenticated requests are properly rejected with 401 Unauthorized.",
				},
			},
		},
	}
}

// BuildBrunoCollection constructs a Bruno JSON export.
func BuildBrunoCollection(baseURL string) map[string]any {
	return map[string]any{
		"name":    "AuthLens Local OIDC Suite",
		"version": "1",
		"type":    "collection",
		"environment": map[string]any{
			"baseUrl":      baseURL,
			"clientId":     "my-local-app",
			"codeVerifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"requests": []map[string]any{
			{
				"name":   "Discovery",
				"method": "GET",
				"url":    baseURL + "/.well-known/openid-configuration",
			},
			{
				"name":   "JWKS",
				"method": "GET",
				"url":    baseURL + "/.well-known/jwks.json",
			},
			{
				"name":   "UserInfo",
				"method": "GET",
				"url":    baseURL + "/userinfo",
				"headers": map[string]string{
					"Authorization": "Bearer {{accessToken}}",
				},
			},
			{
				"name":   "Mock Protected Resource",
				"method": "GET",
				"url":    baseURL + "/api/mock/protected",
				"headers": map[string]string{
					"Authorization": "Bearer {{accessToken}}",
				},
			},
		},
	}
}
