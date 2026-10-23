package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SignPersonaToken generates an authentic signed JWT for a given simulated persona.
func SignPersonaToken(p *persona.Persona, km *keys.KeyManager, issuer, audience, alg string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	now := time.Now().UTC()

	claims := jwtgo.MapClaims{
		"iss":            issuer,
		"sub":            p.Sub,
		"aud":            audience,
		"exp":            now.Add(ttl).Unix(),
		"nbf":            now.Unix(),
		"iat":            now.Unix(),
		"jti":            uuid.New().String(),
		"name":           p.Name,
		"email":          p.Email,
		"email_verified": p.EmailVerified,
		"roles":          p.Roles,
		"permissions":    p.Permissions,
		"status":         p.Status,
		"persona_id":     p.ID,
	}

	for k, v := range p.CustomClaims {
		claims[k] = v
	}

	return SignCustom(claims, km, alg)
}

// SignCustom creates a signed JWT from arbitrary claims using the specified algorithm.
func SignCustom(claims map[string]any, km *keys.KeyManager, alg string) (string, error) {
	if alg == "" {
		alg = "RS256"
	}

	var method jwtgo.SigningMethod
	var key any
	var kid string

	switch alg {
	case "RS256":
		method = jwtgo.SigningMethodRS256
		if km.ActiveRSA == nil || km.ActiveRSA.RSAPriv == nil {
			return "", errors.New("active RSA private key not available")
		}
		key = km.ActiveRSA.RSAPriv
		kid = km.ActiveRSA.ID
	case "ES256":
		method = jwtgo.SigningMethodES256
		if km.ActiveECDSA == nil || km.ActiveECDSA.ECPriv == nil {
			return "", errors.New("active ECDSA private key not available")
		}
		key = km.ActiveECDSA.ECPriv
		kid = km.ActiveECDSA.ID
	case "HS256":
		method = jwtgo.SigningMethodHS256
		key = km.HMACSecret
		kid = "authlens-hmac-key"
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	token := jwtgo.NewWithClaims(method, jwtgo.MapClaims(claims))
	if kid != "" {
		token.Header["kid"] = kid
	}
	token.Header["typ"] = "JWT"

	return token.SignedString(key)
}
