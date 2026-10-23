package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeyPair holds asymmetric keys and metadata for signing and verification.
type KeyPair struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	Use       string    `json:"use"`
	CreatedAt time.Time `json:"createdAt"`
	RSAPriv   *rsa.PrivateKey
	RSAPub    *rsa.PublicKey
	ECPriv    *ecdsa.PrivateKey
	ECPub     *ecdsa.PublicKey
	EdPriv    ed25519.PrivateKey
	EdPub     ed25519.PublicKey
}

// KeyManager handles generation, rotation, and JWKS publishing of cryptographic keys.
type KeyManager struct {
	mu            sync.RWMutex
	ActiveRSA     *KeyPair
	ActiveECDSA   *KeyPair
	ActiveEd25519 *KeyPair
	HMACSecret    []byte
	RotatedKeys   []*KeyPair
	generation    int
}

// NewKeyManager initializes standard RSA 2048, ECDSA P-256, Ed25519, and HMAC keys.
func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{
		HMACSecret:  []byte("authlens-local-hmac-secret-development-key-32bytes"),
		RotatedKeys: make([]*KeyPair, 0),
		generation:  1,
	}

	rsaPair, err := km.generateRSA(km.generation)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	km.ActiveRSA = rsaPair

	ecPair, err := km.generateECDSA(km.generation)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	km.ActiveECDSA = ecPair

	edPair, err := km.generateEd25519(km.generation)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	km.ActiveEd25519 = edPair

	return km, nil
}

func (km *KeyManager) generateRSA(gen int) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:        fmt.Sprintf("authlens-rsa-key-%d", gen),
		Algorithm: "RS256",
		Use:       "sig",
		CreatedAt: time.Now().UTC(),
		RSAPriv:   priv,
		RSAPub:    &priv.PublicKey,
	}, nil
}

func (km *KeyManager) generateECDSA(gen int) (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:        fmt.Sprintf("authlens-ec-key-%d", gen),
		Algorithm: "ES256",
		Use:       "sig",
		CreatedAt: time.Now().UTC(),
		ECPriv:    priv,
		ECPub:     &priv.PublicKey,
	}, nil
}

func (km *KeyManager) generateEd25519(gen int) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:        fmt.Sprintf("authlens-ed-key-%d", gen),
		Algorithm: "EdDSA",
		Use:       "sig",
		CreatedAt: time.Now().UTC(),
		EdPriv:    priv,
		EdPub:     pub,
	}, nil
}

// RotateKeys generates a new generation of keys and retains old keys for validation.
func (km *KeyManager) RotateKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.generation++
	newRSA, err := km.generateRSA(km.generation)
	if err != nil {
		return err
	}
	newEC, err := km.generateECDSA(km.generation)
	if err != nil {
		return err
	}
	newEd, err := km.generateEd25519(km.generation)
	if err != nil {
		return err
	}

	km.RotatedKeys = append(km.RotatedKeys, km.ActiveRSA, km.ActiveECDSA, km.ActiveEd25519)
	km.ActiveRSA = newRSA
	km.ActiveECDSA = newEC
	km.ActiveEd25519 = newEd

	return nil
}

// GetJWKS constructs the RFC 7517 / RFC 8037 compliant JSON Web Key Set.
func (km *KeyManager) GetJWKS() (jwk.Set, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	set := jwk.NewSet()

	// Active RSA
	if km.ActiveRSA != nil && km.ActiveRSA.RSAPub != nil {
		key, err := jwk.FromRaw(km.ActiveRSA.RSAPub)
		if err == nil {
			_ = key.Set(jwk.KeyIDKey, km.ActiveRSA.ID)
			_ = key.Set(jwk.AlgorithmKey, "RS256")
			_ = key.Set(jwk.KeyUsageKey, "sig")
			_ = set.AddKey(key)
		}
	}

	// Active ECDSA
	if km.ActiveECDSA != nil && km.ActiveECDSA.ECPub != nil {
		key, err := jwk.FromRaw(km.ActiveECDSA.ECPub)
		if err == nil {
			_ = key.Set(jwk.KeyIDKey, km.ActiveECDSA.ID)
			_ = key.Set(jwk.AlgorithmKey, "ES256")
			_ = key.Set(jwk.KeyUsageKey, "sig")
			_ = set.AddKey(key)
		}
	}

	// Active Ed25519
	if km.ActiveEd25519 != nil && km.ActiveEd25519.EdPub != nil {
		key, err := jwk.FromRaw(km.ActiveEd25519.EdPub)
		if err == nil {
			_ = key.Set(jwk.KeyIDKey, km.ActiveEd25519.ID)
			_ = key.Set(jwk.AlgorithmKey, "EdDSA")
			_ = key.Set(jwk.KeyUsageKey, "sig")
			_ = set.AddKey(key)
		}
	}

	// Rotated keys
	for _, old := range km.RotatedKeys {
		if old.RSAPub != nil {
			key, err := jwk.FromRaw(old.RSAPub)
			if err == nil {
				_ = key.Set(jwk.KeyIDKey, old.ID)
				_ = key.Set(jwk.AlgorithmKey, old.Algorithm)
				_ = key.Set(jwk.KeyUsageKey, old.Use)
				_ = set.AddKey(key)
			}
		} else if old.ECPub != nil {
			key, err := jwk.FromRaw(old.ECPub)
			if err == nil {
				_ = key.Set(jwk.KeyIDKey, old.ID)
				_ = key.Set(jwk.AlgorithmKey, old.Algorithm)
				_ = key.Set(jwk.KeyUsageKey, old.Use)
				_ = set.AddKey(key)
			}
		} else if old.EdPub != nil {
			key, err := jwk.FromRaw(old.EdPub)
			if err == nil {
				_ = key.Set(jwk.KeyIDKey, old.ID)
				_ = key.Set(jwk.AlgorithmKey, old.Algorithm)
				_ = key.Set(jwk.KeyUsageKey, old.Use)
				_ = set.AddKey(key)
			}
		}
	}

	return set, nil
}

// FindKeyByID searches active and rotated keys by Key ID.
func (km *KeyManager) FindKeyByID(kid string) *KeyPair {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.ActiveRSA != nil && km.ActiveRSA.ID == kid {
		return km.ActiveRSA
	}
	if km.ActiveECDSA != nil && km.ActiveECDSA.ID == kid {
		return km.ActiveECDSA
	}
	if km.ActiveEd25519 != nil && km.ActiveEd25519.ID == kid {
		return km.ActiveEd25519
	}
	for _, k := range km.RotatedKeys {
		if k.ID == kid {
			return k
		}
	}
	return nil
}

// ExportRSAPublicPEM encodes the active RSA public key into PKIX PEM string.
func (km *KeyManager) ExportRSAPublicPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	der, err := x509.MarshalPKIXPublicKey(km.ActiveRSA.RSAPub)
	if err != nil {
		return "", err
	}
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(b), nil
}

// ExportECPublicPEM encodes the active ECDSA public key into PKIX PEM string.
func (km *KeyManager) ExportECPublicPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	der, err := x509.MarshalPKIXPublicKey(km.ActiveECDSA.ECPub)
	if err != nil {
		return "", err
	}
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(b), nil
}

// ExportEdPublicPEM encodes the active Ed25519 public key into PKIX PEM string.
func (km *KeyManager) ExportEdPublicPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	der, err := x509.MarshalPKIXPublicKey(km.ActiveEd25519.EdPub)
	if err != nil {
		return "", err
	}
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(b), nil
}
