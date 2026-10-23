package persona

import (
	"fmt"
	"sync"
)

// Persona represents a simulated user identity with role claims.
type Persona struct {
	ID            string         `json:"id"`
	Sub           string         `json:"sub"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Roles         []string       `json:"roles"`
	Permissions   []string       `json:"permissions"`
	Scopes        []string       `json:"scopes"`
	Status        string         `json:"status"` // "active", "suspended", "pending"
	CustomClaims  map[string]any `json:"custom_claims,omitempty"`
}

// Registry maintains built-in and user-defined personas.
type Registry struct {
	mu       sync.RWMutex
	personas map[string]*Persona
}

// NewRegistry initializes default development personas.
func NewRegistry() *Registry {
	r := &Registry{
		personas: make(map[string]*Persona),
	}

	r.Register(&Persona{
		ID:            "admin",
		Sub:           "usr_authlens_admin_001",
		Name:          "Alice Admin",
		Email:         "admin@local.test",
		EmailVerified: true,
		Roles:         []string{"admin", "billing_admin", "security_auditor"},
		Permissions:   []string{"*"},
		Scopes:        []string{"openid", "profile", "email", "admin", "billing"},
		Status:        "active",
		CustomClaims: map[string]any{
			"tenant_id": "org_enterprise_root",
			"tier":      "enterprise",
		},
	})

	r.Register(&Persona{
		ID:            "developer",
		Sub:           "usr_authlens_dev_002",
		Name:          "Bob Developer",
		Email:         "dev@local.test",
		EmailVerified: true,
		Roles:         []string{"developer", "member"},
		Permissions:   []string{"read", "write", "deploy"},
		Scopes:        []string{"openid", "profile", "email"},
		Status:        "active",
		CustomClaims: map[string]any{
			"tenant_id": "org_engineering_team",
			"tier":      "pro",
		},
	})

	r.Register(&Persona{
		ID:            "suspended",
		Sub:           "usr_authlens_susp_003",
		Name:          "Charlie Suspended",
		Email:         "suspended@local.test",
		EmailVerified: false,
		Roles:         []string{"guest"},
		Permissions:   []string{},
		Scopes:        []string{"openid", "profile", "email"},
		Status:        "suspended",
		CustomClaims: map[string]any{
			"suspension_reason": "payment_failure_and_terms_breach",
		},
	})

	return r
}

// Register stores a persona in the in-memory registry.
func (r *Registry) Register(p *Persona) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.personas[p.ID] = p
}

// Get retrieves a persona by ID.
func (r *Registry) Get(id string) (*Persona, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.personas[id]
	if !exists {
		return nil, fmt.Errorf("persona %q not found", id)
	}
	return p, nil
}

// List returns all registered personas.
func (r *Registry) List() []*Persona {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*Persona, 0, len(r.personas))
	// Always put admin first, then developer, then suspended, then others
	orderedIDs := []string{"admin", "developer", "suspended"}
	for _, id := range orderedIDs {
		if p, ok := r.personas[id]; ok {
			list = append(list, p)
		}
	}
	for id, p := range r.personas {
		if id != "admin" && id != "developer" && id != "suspended" {
			list = append(list, p)
		}
	}
	return list
}
