package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

var (
	// RFC 7636 Section 4.1 unreserved characters: [A-Z], [a-z], [0-9], "-", ".", "_", "~"
	verifierFormatRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

	ErrInvalidVerifierLength = errors.New("code_verifier must be between 43 and 128 characters")
	ErrInvalidVerifierFormat = errors.New("code_verifier contains invalid characters; only [A-Za-z0-9-._~] allowed")
	ErrChallengeMismatch     = errors.New("code_verifier does not match code_challenge")
	ErrUnsupportedMethod     = errors.New("unsupported code_challenge_method; only S256 and plain supported")
)

// ComputeChallenge derives the code_challenge for a given verifier and method.
func ComputeChallenge(verifier, method string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return "", ErrInvalidVerifierLength
	}
	if !verifierFormatRegex.MatchString(verifier) {
		return "", ErrInvalidVerifierFormat
	}

	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	case "plain":
		return verifier, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
	}
}

// VerifyChallenge validates a code_verifier against the registered code_challenge and method.
func VerifyChallenge(verifier, challenge, method string) error {
	computed, err := ComputeChallenge(verifier, method)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrChallengeMismatch
	}

	return nil
}
