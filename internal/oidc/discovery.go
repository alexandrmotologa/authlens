package oidc

// DiscoveryMetadata holds RFC 8414 OpenID Connect provider configuration.
type DiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

// GetDiscoveryMetadata returns the OIDC discovery payload for a given base URL.
func GetDiscoveryMetadata(baseURL string) DiscoveryMetadata {
	return DiscoveryMetadata{
		Issuer:                            baseURL,
		AuthorizationEndpoint:             baseURL + "/oauth/authorize",
		TokenEndpoint:                     baseURL + "/oauth/token",
		UserinfoEndpoint:                  baseURL + "/userinfo",
		JwksURI:                           baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:             baseURL + "/oauth/introspect",
		RevocationEndpoint:                baseURL + "/oauth/revoke",
		ResponseTypesSupported:            []string{"code", "token", "id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "ES256", "HS256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "admin", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "nbf", "iat", "jti",
			"name", "email", "email_verified", "roles", "permissions",
		},
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
	}
}
