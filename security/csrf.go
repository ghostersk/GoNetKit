package security

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// CSRFManager handles CSRF token generation and validation
type CSRFManager struct {
	tokens map[string]time.Time
	mutex  sync.RWMutex
	expiry time.Duration
}

// NewCSRFManager creates a new CSRF manager with the specified token expiry duration
func NewCSRFManager(expiry time.Duration) *CSRFManager {
	return &CSRFManager{
		tokens: make(map[string]time.Time),
		expiry: expiry,
	}
}

// GenerateToken creates a new CSRF token
func (c *CSRFManager) GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(bytes)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.tokens[token] = time.Now()
	c.cleanupExpiredTokensUnsafe()

	return token, nil
}

// ValidateToken validates a CSRF token and removes it (one-time use)
func (c *CSRFManager) ValidateToken(token string) bool {
	if token == "" {
		return false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	createdAt, exists := c.tokens[token]
	if !exists {
		return false
	}

	// Check if token has expired
	if time.Since(createdAt) > c.expiry {
		delete(c.tokens, token)
		return false
	}

	// Remove token after use (one-time use)
	delete(c.tokens, token)
	return true
}

// cleanupExpiredTokensUnsafe removes expired tokens (must be called with mutex locked)
func (c *CSRFManager) cleanupExpiredTokensUnsafe() {
	now := time.Now()
	for token, createdAt := range c.tokens {
		if now.Sub(createdAt) > c.expiry {
			delete(c.tokens, token)
		}
	}
}

// CleanupExpiredTokens removes expired tokens (thread-safe)
func (c *CSRFManager) CleanupExpiredTokens() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cleanupExpiredTokensUnsafe()
}
