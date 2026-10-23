package oidc

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuthCodeRecord holds state for an issued OAuth 2.1 authorization code.
type AuthCodeRecord struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	PersonaID           string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
}

// AuthCodeStore provides in-memory thread-safe management of authorization codes.
type AuthCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*AuthCodeRecord
}

// NewAuthCodeStore initializes the storage map.
func NewAuthCodeStore() *AuthCodeStore {
	return &AuthCodeStore{
		codes: make(map[string]*AuthCodeRecord),
	}
}

// Create generates a single-use code valid for 10 minutes.
func (s *AuthCodeStore) Create(clientID, redirectURI, scope, state, personaID, challenge, method string) *AuthCodeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	code := fmt.Sprintf("auth_%s", uuid.New().String()[:12])
	rec := &AuthCodeRecord{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		PersonaID:           personaID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	s.codes[code] = rec
	return rec
}

// Consume retrieves and immediately invalidates an authorization code.
func (s *AuthCodeStore) Consume(code string) (*AuthCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.codes[code]
	if !exists {
		return nil, errors.New("authorization code not found")
	}

	if rec.Used {
		return nil, errors.New("authorization code has already been used")
	}

	if time.Now().After(rec.ExpiresAt) {
		return nil, errors.New("authorization code has expired")
	}

	rec.Used = true
	return rec, nil
}
