package pkce

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// TraceStep records an individual milestone in the PKCE authorization handshake.
type TraceStep struct {
	Index       int       `json:"index"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Payload     any       `json:"payload,omitempty"`
	Status      string    `json:"status"` // "ok", "error", "pending"
}

// FlowTrace stores end-to-end telemetry for an OAuth 2.1 authorization code exchange.
type FlowTrace struct {
	ID                  string      `json:"id"`
	AuthCode            string      `json:"authCode,omitempty"`
	ClientID            string      `json:"clientId"`
	RedirectURI         string      `json:"redirectUri"`
	Scope               string      `json:"scope"`
	State               string      `json:"state"`
	Persona             string      `json:"persona"`
	CodeChallenge       string      `json:"codeChallenge"`
	CodeChallengeMethod string      `json:"codeChallengeMethod"`
	CodeVerifier        string      `json:"codeVerifier,omitempty"`
	ComputedChallenge   string      `json:"computedChallenge,omitempty"`
	Status              string      `json:"status"` // "initiated", "exchanged", "failed"
	ErrorReason         string      `json:"errorReason,omitempty"`
	CreatedAt           time.Time   `json:"createdAt"`
	ExchangedAt         *time.Time  `json:"exchangedAt,omitempty"`
	Steps               []TraceStep `json:"steps"`
}

// TraceStore manages historical PKCE traces and notifies live SSE subscribers.
type TraceStore struct {
	mu          sync.RWMutex
	traces      []*FlowTrace
	maxTraces   int
	subscribers map[chan *FlowTrace]struct{}
}

// NewTraceStore creates a ring-buffered thread-safe trace repository.
func NewTraceStore(maxTraces int) *TraceStore {
	if maxTraces <= 0 {
		maxTraces = 100
	}
	return &TraceStore{
		traces:      make([]*FlowTrace, 0),
		maxTraces:   maxTraces,
		subscribers: make(map[chan *FlowTrace]struct{}),
	}
}

// RecordInitiation creates a new trace entry when /oauth/authorize is hit.
func (ts *TraceStore) RecordInitiation(authCode, clientID, redirectURI, scope, state, persona, challenge, method string) *FlowTrace {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	trace := &FlowTrace{
		ID:                  uuid.New().String(),
		AuthCode:            authCode,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Persona:             persona,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Status:              "initiated",
		CreatedAt:           time.Now().UTC(),
		Steps: []TraceStep{
			{
				Index:       1,
				Name:        "Authorization Request Received",
				Description: "Client dispatched authorization request with PKCE challenge.",
				Timestamp:   time.Now().UTC(),
				Status:      "ok",
				Payload: map[string]string{
					"client_id":             clientID,
					"redirect_uri":          redirectURI,
					"code_challenge":        challenge,
					"code_challenge_method": method,
				},
			},
			{
				Index:       2,
				Name:        "Persona Selected & Code Issued",
				Description: "User identity approved. Single-use authorization code generated.",
				Timestamp:   time.Now().UTC(),
				Status:      "ok",
				Payload: map[string]string{
					"persona":   persona,
					"auth_code": authCode,
				},
			},
		},
	}

	if len(ts.traces) >= ts.maxTraces {
		ts.traces = ts.traces[1:]
	}
	ts.traces = append(ts.traces, trace)

	ts.broadcast(trace)
	return trace
}

// RecordExchange updates a trace with code_verifier and cryptographic verification status.
func (ts *TraceStore) RecordExchange(authCode, verifier, computedChallenge, status, errorReason string) *FlowTrace {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	var target *FlowTrace
	for _, t := range ts.traces {
		if t.AuthCode == authCode {
			target = t
			break
		}
	}

	now := time.Now().UTC()
	if target == nil {
		// Create standalone entry if exchange was called directly
		target = &FlowTrace{
			ID:          uuid.New().String(),
			AuthCode:    authCode,
			CreatedAt:   now,
			Steps:       make([]TraceStep, 0),
		}
		if len(ts.traces) >= ts.maxTraces {
			ts.traces = ts.traces[1:]
		}
		ts.traces = append(ts.traces, target)
	}

	target.CodeVerifier = verifier
	target.ComputedChallenge = computedChallenge
	target.Status = status
	target.ErrorReason = errorReason
	target.ExchangedAt = &now

	stepIndex := len(target.Steps) + 1
	stepStatus := "ok"
	stepDesc := "Client submitted code_verifier. Challenge cryptographic match confirmed."
	if status == "failed" {
		stepStatus = "error"
		stepDesc = "PKCE verification failed: " + errorReason
	}

	target.Steps = append(target.Steps,
		TraceStep{
			Index:       stepIndex,
			Name:        "Code Verifier Submitted",
			Description: "Client dispatched token exchange request containing original code_verifier.",
			Timestamp:   now,
			Status:      "ok",
			Payload: map[string]string{
				"code_verifier": verifier,
			},
		},
		TraceStep{
			Index:       stepIndex + 1,
			Name:        "Cryptographic Comparison (SHA-256)",
			Description: stepDesc,
			Timestamp:   now,
			Status:      stepStatus,
			Payload: map[string]string{
				"expected_challenge": target.CodeChallenge,
				"computed_challenge": computedChallenge,
				"method":             target.CodeChallengeMethod,
				"match":              status,
			},
		},
	)

	ts.broadcast(target)
	return target
}

// GetAllTraces returns all recorded traces in reverse chronological order.
func (ts *TraceStore) GetAllTraces() []*FlowTrace {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	result := make([]*FlowTrace, len(ts.traces))
	for i, t := range ts.traces {
		result[len(ts.traces)-1-i] = t
	}
	return result
}

// Clear removes all recorded traces.
func (ts *TraceStore) Clear() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.traces = make([]*FlowTrace, 0)
}

// Subscribe registers a channel for live updates.
func (ts *TraceStore) Subscribe() chan *FlowTrace {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ch := make(chan *FlowTrace, 20)
	ts.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes an active listener.
func (ts *TraceStore) Unsubscribe(ch chan *FlowTrace) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	delete(ts.subscribers, ch)
	close(ch)
}

func (ts *TraceStore) broadcast(trace *FlowTrace) {
	for ch := range ts.subscribers {
		select {
		case ch <- trace:
		default:
			// Non-blocking drop if channel is full
		}
	}
}
