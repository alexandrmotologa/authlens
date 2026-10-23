package server

import (
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuditLogEntry represents a recorded HTTP request and response cycle.
type AuditLogEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	StatusCode int       `json:"status_code"`
	LatencyMs  int64     `json:"latency_ms"`
	ClientIP   string    `json:"client_ip"`
	UserAgent  string    `json:"user_agent"`
}

// AuditLogStore stores a bounded buffer of request logs and notifies SSE subscribers.
type AuditLogStore struct {
	mu          sync.RWMutex
	logs        []*AuditLogEntry
	maxLogs     int
	subscribers map[chan *AuditLogEntry]struct{}
}

// NewAuditLogStore creates a ring-buffer audit store.
func NewAuditLogStore(maxLogs int) *AuditLogStore {
	if maxLogs <= 0 {
		maxLogs = 200
	}
	return &AuditLogStore{
		logs:        make([]*AuditLogEntry, 0),
		maxLogs:     maxLogs,
		subscribers: make(map[chan *AuditLogEntry]struct{}),
	}
}

// Record appends a new entry and broadcasts to SSE subscribers.
func (s *AuditLogStore) Record(entry *AuditLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.logs) >= s.maxLogs {
		s.logs = s.logs[1:]
	}
	s.logs = append(s.logs, entry)

	for ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

// GetAll returns logs in reverse chronological order.
func (s *AuditLogStore) GetAll() []*AuditLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*AuditLogEntry, len(s.logs))
	for i, l := range s.logs {
		result[len(s.logs)-1-i] = l
	}
	return result
}

// Clear flushes all recorded logs.
func (s *AuditLogStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = make([]*AuditLogEntry, 0)
}

// Subscribe opens a channel for live telemetry stream.
func (s *AuditLogStore) Subscribe() chan *AuditLogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan *AuditLogEntry, 50)
	s.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe releases an SSE subscriber channel.
func (s *AuditLogStore) Unsubscribe(ch chan *AuditLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.subscribers, ch)
	close(ch)
}

// AuditMiddleware logs incoming HTTP requests to AuthLens endpoints.
func AuditMiddleware(store *AuditLogStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip static assets and SSE events endpoint itself to avoid recursion
		if strings.HasPrefix(path, "/assets/") || path == "/logo.svg" || path == "/favicon.ico" || path == "/api/events" {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		latency := time.Since(start).Milliseconds()

		entry := &AuditLogEntry{
			ID:         uuid.New().String(),
			Timestamp:  time.Now().UTC(),
			Method:     c.Request.Method,
			Path:       path,
			Query:      c.Request.URL.RawQuery,
			StatusCode: c.Writer.Status(),
			LatencyMs:  latency,
			ClientIP:   c.ClientIP(),
			UserAgent:  c.Request.UserAgent(),
		}

		store.Record(entry)
	}
}
