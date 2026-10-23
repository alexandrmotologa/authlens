package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DecodedJWT represents a full offline dissection of a JSON Web Token.
type DecodedJWT struct {
	RawToken      string         `json:"raw_token"`
	HeaderRaw     string         `json:"header_raw"`
	PayloadRaw    string         `json:"payload_raw"`
	SignatureRaw  string         `json:"signature_raw"`
	Header        map[string]any `json:"header"`
	Payload       map[string]any `json:"payload"`
	Algorithm     string         `json:"algorithm"`
	KeyID         string         `json:"key_id,omitempty"`
	TokenType     string         `json:"token_type,omitempty"`
	Subject       string         `json:"subject,omitempty"`
	Issuer        string         `json:"issuer,omitempty"`
	Audience      []string       `json:"audience,omitempty"`
	IssuedAt      *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	NotBefore     *time.Time     `json:"not_before,omitempty"`
	IsExpired     bool           `json:"is_expired"`
	TTLSeconds    int64          `json:"ttl_seconds"`
	HasSignature  bool           `json:"has_signature"`
	SignatureSize int            `json:"signature_size_bytes"`
	ParseError    string         `json:"parse_error,omitempty"`
}

// DecodeOffline unpacks a JWT string strictly in memory without contacting any remote server.
func DecodeOffline(tokenStr string) (*DecodedJWT, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	// Strip "Bearer " prefix if user pasted cURL authorization header
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 2 or 3 dot-separated segments, got %d", len(parts))
	}

	res := &DecodedJWT{
		RawToken:   tokenStr,
		HeaderRaw:  parts[0],
		PayloadRaw: parts[1],
		Header:     make(map[string]any),
		Payload:    make(map[string]any),
	}

	if len(parts) == 3 {
		res.SignatureRaw = parts[2]
		res.HasSignature = len(parts[2]) > 0
		sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		res.SignatureSize = len(sigBytes)
	}

	// Decode Header
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		res.ParseError = fmt.Sprintf("invalid base64url header: %v", err)
		return res, nil
	}
	if err := json.Unmarshal(headerBytes, &res.Header); err != nil {
		res.ParseError = fmt.Sprintf("header is not valid JSON: %v", err)
		return res, nil
	}

	if alg, ok := res.Header["alg"].(string); ok {
		res.Algorithm = alg
	}
	if kid, ok := res.Header["kid"].(string); ok {
		res.KeyID = kid
	}
	if typ, ok := res.Header["typ"].(string); ok {
		res.TokenType = typ
	}

	// Decode Payload
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		res.ParseError = fmt.Sprintf("invalid base64url payload: %v", err)
		return res, nil
	}
	if err := json.Unmarshal(payloadBytes, &res.Payload); err != nil {
		res.ParseError = fmt.Sprintf("payload is not valid JSON: %v", err)
		return res, nil
	}

	// Extract standard claims
	if sub, ok := res.Payload["sub"].(string); ok {
		res.Subject = sub
	}
	if iss, ok := res.Payload["iss"].(string); ok {
		res.Issuer = iss
	}

	switch aud := res.Payload["aud"].(type) {
	case string:
		res.Audience = []string{aud}
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok {
				res.Audience = append(res.Audience, s)
			}
		}
	}

	now := time.Now().UTC()

	if expVal, ok := res.Payload["exp"].(float64); ok {
		expTime := time.Unix(int64(expVal), 0).UTC()
		res.ExpiresAt = &expTime
		res.TTLSeconds = int64(expVal) - now.Unix()
		res.IsExpired = res.TTLSeconds <= 0
	}

	if nbfVal, ok := res.Payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbfVal), 0).UTC()
		res.NotBefore = &nbfTime
	}

	if iatVal, ok := res.Payload["iat"].(float64); ok {
		iatTime := time.Unix(int64(iatVal), 0).UTC()
		res.IssuedAt = &iatTime
	}

	return res, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
