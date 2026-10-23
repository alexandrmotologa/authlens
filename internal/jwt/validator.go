package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/alexandrmotologa/authlens/internal/keys"
	jwtgo "github.com/golang-jwt/jwt/v5"
)

// ValidationResult reports cryptographic integrity and temporal compliance.
type ValidationResult struct {
	Valid          bool   `json:"valid"`
	SignatureValid bool   `json:"signature_valid"`
	TemporalValid  bool   `json:"temporal_valid"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id,omitempty"`
	KeySource      string `json:"key_source"` // "local_rsa", "local_ecdsa", "local_hmac", "custom_pem", "none"
	Error          string `json:"error,omitempty"`
	Warning        string `json:"warning,omitempty"`
}

// ValidateOffline performs cryptographic verification against local AuthLens keys.
func ValidateOffline(tokenStr string, km *keys.KeyManager, customKey string) (*ValidationResult, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = strings.TrimSpace(tokenStr[7:])
	}

	res := &ValidationResult{
		Valid: false,
	}

	decoded, err := DecodeOffline(tokenStr)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.Algorithm = decoded.Algorithm
	res.KeyID = decoded.KeyID

	// Check alg: none
	if strings.ToLower(decoded.Algorithm) == "none" {
		res.KeySource = "none"
		res.Error = "VULNERABILITY: token specifies 'alg: none' (unsecured token without cryptographic signature)"
		return res, nil
	}

	// Determine key resolver
	keyFunc := func(t *jwtgo.Token) (any, error) {
		alg := t.Method.Alg()

		// 1. If custom key is provided, attempt to parse it
		if strings.TrimSpace(customKey) != "" {
			res.KeySource = "custom_pem"
			return parseCustomKey(customKey, alg)
		}

		// 2. Otherwise verify against local KeyManager
		if km == nil {
			return nil, errors.New("key manager is nil and no custom key provided")
		}

		kid, _ := t.Header["kid"].(string)

		switch alg {
		case "RS256", "RS384", "RS512":
			res.KeySource = "local_rsa"
			if kid != "" {
				kp := km.FindKeyByID(kid)
				if kp != nil && kp.RSAPub != nil {
					return kp.RSAPub, nil
				}
			}
			if km.ActiveRSA != nil && km.ActiveRSA.RSAPub != nil {
				return km.ActiveRSA.RSAPub, nil
			}
			return nil, fmt.Errorf("no RSA public key found for kid %q", kid)

		case "ES256", "ES384", "ES512":
			res.KeySource = "local_ecdsa"
			if kid != "" {
				kp := km.FindKeyByID(kid)
				if kp != nil && kp.ECPub != nil {
					return kp.ECPub, nil
				}
			}
			if km.ActiveECDSA != nil && km.ActiveECDSA.ECPub != nil {
				return km.ActiveECDSA.ECPub, nil
			}
			return nil, fmt.Errorf("no ECDSA public key found for kid %q", kid)

		case "HS256", "HS384", "HS512":
			res.KeySource = "local_hmac"
			return km.HMACSecret, nil

		default:
			return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
		}
	}

	// Now parse with cryptographic verification
	verifiedToken, parseErr := jwtgo.Parse(tokenStr, keyFunc)

	if parseErr != nil {
		// Distinguish between signature failure and claims expiration failure
		if errors.Is(parseErr, jwtgo.ErrTokenSignatureInvalid) {
			res.SignatureValid = false
			res.Error = "invalid signature: cryptographic verification failed against public key"
			return res, nil
		}
		if errors.Is(parseErr, jwtgo.ErrTokenExpired) {
			res.SignatureValid = true
			res.TemporalValid = false
			res.Error = "token is expired (exp timestamp is in the past)"
			return res, nil
		}
		if errors.Is(parseErr, jwtgo.ErrTokenNotValidYet) {
			res.SignatureValid = true
			res.TemporalValid = false
			res.Error = "token not valid yet (nbf timestamp is in the future)"
			return res, nil
		}

		res.Error = parseErr.Error()
		return res, nil
	}

	if verifiedToken.Valid {
		res.Valid = true
		res.SignatureValid = true
		res.TemporalValid = true
	} else {
		res.Error = "token validation returned false"
	}

	return res, nil
}

func parseCustomKey(keyStr, alg string) (any, error) {
	keyStr = strings.TrimSpace(keyStr)

	// Check if HMAC secret string
	if strings.HasPrefix(alg, "HS") {
		return []byte(keyStr), nil
	}

	// Parse PEM
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block from custom key string")
	}

	// Try PKIX public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		switch alg {
		case "RS256", "RS384", "RS512":
			if rsaPub, ok := pub.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
			return nil, errors.New("custom key is not an RSA public key")
		case "ES256", "ES384", "ES512":
			if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
				return ecPub, nil
			}
			return nil, errors.New("custom key is not an ECDSA public key")
		}
	}

	// Try PKCS1 RSA Public Key
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return rsaPub, nil
	}

	// Try Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		return cert.PublicKey, nil
	}

	return nil, fmt.Errorf("unrecognized public key PEM format for algorithm %s", alg)
}
