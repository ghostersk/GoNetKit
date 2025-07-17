package pwpusher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type PWPusher struct {
	db             *sql.DB
	encryptionKey  []byte
	pushTemplates  *template.Template
	viewTemplates  *template.Template
	failedAttempts map[string]*FailedAttempts
	csrfTokens     map[string]time.Time // Map of CSRF tokens to their creation time
}

type FailedAttempts struct {
	Count        int
	LastAttempt  time.Time
	BlockedUntil time.Time
}

type PushRequest struct {
	Text         string `json:"text"`
	ExpiryDays   int    `json:"expiry_days"`
	MaxViews     int    `json:"max_views"`
	RequireClick bool   `json:"require_click"`
	AutoDelete   bool   `json:"auto_delete"`
	TrackHistory bool   `json:"track_history"`
	Password     string `json:"password,omitempty"`
}

type PushResponse struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

type PushData struct {
	ID            string    `json:"id"`
	EncryptedText string    `json:"encrypted_text"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	MaxViews      int       `json:"max_views"`
	CurrentViews  int       `json:"current_views"`
	RequireClick  bool      `json:"require_click"`
	AutoDelete    bool      `json:"auto_delete"`
	CreatorIP     string    `json:"creator_ip"`
	IsDeleted     bool      `json:"is_deleted"`
	PasswordHash  string    `json:"password_hash,omitempty"`
}

type ViewData struct {
	CurrentPage      string    `json:"current_page"` // Add this for base template
	Push             *PushData `json:"push"`
	Text             string    `json:"text,omitempty"`
	ShowText         bool      `json:"show_text"`
	Error            string    `json:"error,omitempty"`
	RequireClick     bool      `json:"require_click"`
	CanReveal        bool      `json:"can_reveal"`
	RequirePassword  bool      `json:"require_password"`
	PasswordRequired bool      `json:"password_required"`
	InvalidPassword  bool      `json:"invalid_password"`
	Revealed         bool      `json:"revealed"` // Add this for template logic
	AttemptsLeft     int       `json:"attempts_left,omitempty"`
	IsBlocked        bool      `json:"is_blocked"`
	BlockedUntil     time.Time `json:"blocked_until,omitempty"`
	CSRFToken        string    `json:"csrf_token,omitempty"` // CSRF token for forms
}

type HistoryItem struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxViews     int       `json:"max_views"`
	CurrentViews int       `json:"current_views"`
	IsExpired    bool      `json:"is_expired"`
	Preview      string    `json:"preview"`
}

var defaultEncryptionKey = "your-secret-32-char-encryption-key!!"

// Security constants
const (
	MaxTextLength     = 100000        // 100KB max text
	MaxPasswordLength = 128           // Max password length
	MinPasswordLength = 1             // Min password length
	MaxExpiryDays     = 90            // Max 90 days
	MinExpiryDays     = 1             // Min 1 day
	MaxViews          = 100           // Max 100 views
	MinViews          = 1             // Min 1 view
	CSRFTokenExpiry   = 1 * time.Hour // CSRF tokens expire after 1 hour
)

// Input validation patterns
var (
	allowedActionPattern = regexp.MustCompile(`^(reveal|verify_password|delete)$`)
	safeStringPattern    = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Z}\p{S}\s]*$`)
)

// NewPWPusher creates a new PWPusher instance
func NewPWPusher(embeddedFS fs.FS, encryptionKey string) (*PWPusher, error) {
	if encryptionKey == "" {
		encryptionKey = os.Getenv("PWPUSH_ENCRYPTION_KEY")
		if encryptionKey == "" {
			encryptionKey = defaultEncryptionKey
		}
	}

	// Ensure key is 32 bytes for AES-256
	key := sha256.Sum256([]byte(encryptionKey))

	// Initialize database
	db, err := initDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	// Load templates separately
	pushTemplates, err := loadPushTemplates(embeddedFS)
	if err != nil {
		return nil, fmt.Errorf("failed to load push templates: %v", err)
	}

	viewTemplates, err := loadViewTemplates(embeddedFS)
	if err != nil {
		return nil, fmt.Errorf("failed to load view templates: %v", err)
	}

	return &PWPusher{
		db:             db,
		encryptionKey:  key[:],
		pushTemplates:  pushTemplates,
		viewTemplates:  viewTemplates,
		failedAttempts: make(map[string]*FailedAttempts),
		csrfTokens:     make(map[string]time.Time),
	}, nil
}

func initDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "pwpusher.db")
	if err != nil {
		return nil, err
	}

	query := `
	CREATE TABLE IF NOT EXISTS pushes (
		id TEXT PRIMARY KEY,
		encrypted_text TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		max_views INTEGER NOT NULL,
		current_views INTEGER DEFAULT 0,
		require_click BOOLEAN DEFAULT 1,
		auto_delete BOOLEAN DEFAULT 1,
		creator_ip TEXT,
		is_deleted BOOLEAN DEFAULT 0,
		password_hash TEXT
	);
	
	CREATE INDEX IF NOT EXISTS idx_expires_at ON pushes(expires_at);
	CREATE INDEX IF NOT EXISTS idx_creator_ip ON pushes(creator_ip);
	`

	_, err = db.Exec(query)
	if err != nil {
		return nil, err
	}

	// For existing databases that don't have the password_hash column, add it
	_, err = db.Exec("ALTER TABLE pushes ADD COLUMN password_hash TEXT")
	if err != nil {
		// Ignore error if column already exists
		if !strings.Contains(err.Error(), "duplicate column name") {
			return nil, fmt.Errorf("failed to add password_hash column: %v", err)
		}
	}

	return db, nil
}

func loadPushTemplates(embeddedFS fs.FS) (*template.Template, error) {
	log.Printf("Loading PWPusher push templates...")

	templates := template.New("").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"eq": func(a, b interface{}) bool {
			return a == b
		},
	})

	// Load only base and pwpush templates
	_, err := templates.ParseFS(embeddedFS, "web/base.html", "web/pwpush.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse push templates: %v", err)
	}

	log.Printf("PWPusher push templates loaded successfully")
	return templates, nil
}

func loadViewTemplates(embeddedFS fs.FS) (*template.Template, error) {
	log.Printf("Loading PWPusher view templates...")

	templates := template.New("").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"timeUntil": func(t time.Time) string {
			duration := time.Until(t)
			if duration <= 0 {
				return "Expired"
			}

			days := int(duration.Hours() / 24)
			hours := int(duration.Hours()) % 24
			minutes := int(duration.Minutes()) % 60

			if days > 0 {
				return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
			} else if hours > 0 {
				return fmt.Sprintf("%dh %dm", hours, minutes)
			} else {
				return fmt.Sprintf("%dm", minutes)
			}
		},
		"eq": func(a, b interface{}) bool {
			return a == b
		},
		"sub": func(a, b int) int {
			return a - b
		},
	})

	// Load only base and pwview templates
	_, err := templates.ParseFS(embeddedFS, "web/base.html", "web/pwview.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse view templates: %v", err)
	}

	log.Printf("PWPusher view templates loaded successfully")
	return templates, nil
}

func (p *PWPusher) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (p *PWPusher) encrypt(text string) (string, error) {
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (p *PWPusher) decrypt(encryptedText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Rate limiting methods for password attempts
func (p *PWPusher) isBlocked(clientIP string) bool {
	if attempts, exists := p.failedAttempts[clientIP]; exists {
		// Check if user has reached the limit and is still within block period
		if attempts.Count >= 5 && !attempts.BlockedUntil.IsZero() && time.Now().Before(attempts.BlockedUntil) {
			log.Printf("IP %s is blocked until %v", clientIP, attempts.BlockedUntil)
			return true
		}
		// If block period has expired, reset the attempts
		if !attempts.BlockedUntil.IsZero() && time.Now().After(attempts.BlockedUntil) {
			log.Printf("Block period expired for IP %s, resetting attempts", clientIP)
			delete(p.failedAttempts, clientIP)
		}
	}
	return false
}

func (p *PWPusher) recordFailedAttempt(clientIP string) {
	now := time.Now()

	if attempts, exists := p.failedAttempts[clientIP]; exists {
		attempts.Count++
		attempts.LastAttempt = now

		// Block for 10 minutes after 5 failed attempts
		if attempts.Count >= 5 {
			attempts.BlockedUntil = now.Add(10 * time.Minute)
		}
	} else {
		p.failedAttempts[clientIP] = &FailedAttempts{
			Count:       1,
			LastAttempt: now,
		}
	}

	// Log for debugging
	log.Printf("Failed attempt recorded for IP %s: Count=%d, BlockedUntil=%v",
		clientIP, p.failedAttempts[clientIP].Count, p.failedAttempts[clientIP].BlockedUntil)
}

func (p *PWPusher) resetFailedAttempts(clientIP string) {
	delete(p.failedAttempts, clientIP)
}

func (p *PWPusher) getRemainingAttempts(clientIP string) int {
	if attempts, exists := p.failedAttempts[clientIP]; exists {
		return 5 - attempts.Count
	}
	return 5
}

func (p *PWPusher) getBlockedUntil(clientIP string) time.Time {
	if attempts, exists := p.failedAttempts[clientIP]; exists {
		return attempts.BlockedUntil
	}
	return time.Time{}
}

func (p *PWPusher) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header for real IP behind proxy
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get the first IP in the list
		ips := strings.Split(forwarded, ",")
		clientIP := strings.TrimSpace(ips[0])
		log.Printf("Using X-Forwarded-For IP: %s", clientIP)
		return clientIP
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		log.Printf("Using X-Real-IP: %s", realIP)
		return realIP
	}

	// Fall back to remote address
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("Using RemoteAddr IP: %s", clientIP)
	return clientIP
} // HTTP Handlers

func (p *PWPusher) IndexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("PWPusher IndexHandler called: %s %s", r.Method, r.URL.Path)

	if r.Method == http.MethodPost {
		p.handleCreatePush(w, r)
		return
	}

	// For GET requests, render the form with CurrentPage
	csrfToken, err := p.generateCSRFToken()
	if err != nil {
		log.Printf("Error generating CSRF token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	data := struct {
		CurrentPage  string
		TemplateName string
		Error        string // Add this to prevent template errors
		Success      bool   // Add this for consistency
		CSRFToken    string
	}{
		CurrentPage:  "pwpush",
		TemplateName: "pwpush.html",
		Error:        "", // Empty error for pwpush
		Success:      false,
		CSRFToken:    csrfToken,
	}
	log.Printf("Rendering pwpush.html template with data: %+v", data)
	p.renderTemplate(w, "pwpush.html", data)
}

func (p *PWPusher) handleCreatePush(w http.ResponseWriter, r *http.Request) {
	var req PushRequest

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, MaxTextLength+1024) // Text + some overhead for JSON

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Handle form data - limit request size
		r.Body = http.MaxBytesReader(w, r.Body, MaxTextLength+1024)

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		// Validate CSRF token for form submissions
		csrfToken := r.FormValue("csrf_token")
		if !p.validateCSRFToken(csrfToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Parse and sanitize form values
		req.Text = r.FormValue("text")

		var err error
		req.ExpiryDays, err = strconv.Atoi(r.FormValue("expiry_days"))
		if err != nil {
			req.ExpiryDays = 7 // Default
		}

		req.MaxViews, err = strconv.Atoi(r.FormValue("max_views"))
		if err != nil {
			req.MaxViews = 10 // Default
		}

		req.RequireClick = r.FormValue("require_click") == "on"
		req.AutoDelete = r.FormValue("auto_delete") == "on"
		req.TrackHistory = r.FormValue("track_history") == "on"
		req.Password = r.FormValue("password")
	}

	// Comprehensive input validation
	sanitizedText, err := p.validateAndSanitizeText(req.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Text = sanitizedText

	if err := p.validatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := p.validateInteger(req.ExpiryDays, MinExpiryDays, MaxExpiryDays, "expiry days"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := p.validateInteger(req.MaxViews, MinViews, MaxViews, "max views"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Encrypt text
	encryptedText, err := p.encrypt(req.Text)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		http.Error(w, "Failed to encrypt text", http.StatusInternalServerError)
		return
	}

	// Create push data
	id := p.generateID()
	now := time.Now()
	expiresAt := now.AddDate(0, 0, req.ExpiryDays)
	creatorIP := p.getClientIP(r)

	// Hash password if provided
	var passwordHash sql.NullString
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Failed to hash password: %v", err)
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}
		passwordHash = sql.NullString{String: string(hashedPassword), Valid: true}
	}

	// Save to database
	_, err = p.db.Exec(`
		INSERT INTO pushes 
		(id, encrypted_text, created_at, expires_at, max_views, require_click, auto_delete, creator_ip, password_hash) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, encryptedText, now, expiresAt, req.MaxViews, req.RequireClick, req.AutoDelete, creatorIP, passwordHash)

	if err != nil {
		log.Printf("Failed to save push: %v", err)
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}

	// Prepare response URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s/pwview/%s", scheme, r.Host, id)

	// Save to user's history if tracking is enabled
	if req.TrackHistory {
		p.saveToHistory(w, r, id, now, expiresAt, req.MaxViews, fullURL)
	}

	// Prepare response
	response := PushResponse{
		ID:        id,
		URL:       fullURL,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		// Render success page with the link
		p.renderTemplate(w, "pwpush.html", map[string]interface{}{
			"Success":     true,
			"PushURL":     fullURL,
			"ID":          id,
			"ExpiresAt":   expiresAt.Format("2006-01-02 15:04:05"),
			"CurrentPage": "pwpush",
		})
	}
}

func (p *PWPusher) ViewHandler(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL path
	var path string
	if strings.HasPrefix(r.URL.Path, "/pwview/") {
		path = strings.TrimPrefix(r.URL.Path, "/pwview/")
	} else if strings.HasPrefix(r.URL.Path, "/pwpush/view/") {
		path = strings.TrimPrefix(r.URL.Path, "/pwpush/view/")
	} else {
		path = strings.TrimPrefix(r.URL.Path, "/pwpush/")
	}

	if path == "" {
		http.Error(w, "Invalid push ID", http.StatusBadRequest)
		return
	}

	log.Printf("ViewHandler: Extracted ID '%s' from URL '%s'", path, r.URL.Path)

	// Handle POST requests (reveal actions and password verification)
	if r.Method == http.MethodPost {
		r.ParseForm()

		// Validate CSRF token for form submissions
		csrfToken := r.FormValue("csrf_token")
		if !p.validateCSRFToken(csrfToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		action := r.FormValue("action")

		if action == "reveal" {
			// Redirect to same URL with show=true parameter
			http.Redirect(w, r, r.URL.Path+"?show=true", http.StatusSeeOther)
			return
		} else if action == "verify_password" {
			// Handle password verification with rate limiting
			clientIP := p.getClientIP(r)
			log.Printf("Password verification attempt from IP: %s", clientIP)

			// Check if client is blocked
			if p.isBlocked(clientIP) {
				blockedUntil := p.getBlockedUntil(clientIP)
				log.Printf("IP %s is blocked until %v", clientIP, blockedUntil)
				p.renderTemplate(w, "pwview.html", ViewData{
					CurrentPage:     "pwpush",
					Push:            &PushData{ID: path}, // Minimal push data for display
					RequirePassword: true,
					IsBlocked:       true,
					BlockedUntil:    blockedUntil,
					Error:           fmt.Sprintf("Too many failed attempts. Please try again after %s.", blockedUntil.Format("15:04:05")),
				})
				return
			}

			password := r.FormValue("password")

			// Get push data to check password
			push, err := p.getPushByID(path)
			if err != nil {
				http.Error(w, "Link not found", http.StatusNotFound)
				return
			}

			// Verify password
			if push.PasswordHash != "" {
				err := bcrypt.CompareHashAndPassword([]byte(push.PasswordHash), []byte(password))
				if err != nil {
					// Invalid password - record failed attempt
					p.recordFailedAttempt(clientIP)
					remainingAttempts := p.getRemainingAttempts(clientIP)
					log.Printf("Invalid password for IP %s, remaining attempts: %d", clientIP, remainingAttempts)

					var errorMsg string
					if remainingAttempts <= 0 {
						blockedUntil := p.getBlockedUntil(clientIP)
						errorMsg = fmt.Sprintf("Too many failed attempts. Access blocked until %s.", blockedUntil.Format("15:04:05"))
					} else {
						errorMsg = fmt.Sprintf("Incorrect password. You have %d attempt(s) remaining.", remainingAttempts)
					}

					p.renderTemplate(w, "pwview.html", ViewData{
						CurrentPage:     "pwpush",
						Push:            push,
						RequirePassword: true,
						InvalidPassword: true,
						AttemptsLeft:    remainingAttempts,
						IsBlocked:       remainingAttempts <= 0,
						Error:           errorMsg,
					})
					return
				}
			}

			// Password is correct - reset failed attempts and redirect
			log.Printf("Correct password for IP %s, resetting attempts", clientIP)
			p.resetFailedAttempts(clientIP)
			http.Redirect(w, r, r.URL.Path+"?show=true&verified=true", http.StatusSeeOther)
			return
		} else if action == "delete" {
			// Manual delete action
			_, err := p.db.Exec("UPDATE pushes SET is_deleted = 1 WHERE id = ?", path)
			if err != nil {
				log.Printf("Failed to mark as deleted: %v", err)
			}
			p.renderTemplate(w, "pwview.html", ViewData{
				CurrentPage: "pwpush",
				Error:       "This content has been deleted.",
			})
			return
		}
	}

	// Check if this is a reveal request
	showText := r.URL.Query().Get("show") == "true"

	// Get push data
	push, err := p.getPushByID(path)
	if err != nil {
		if err == sql.ErrNoRows {
			p.renderTemplate(w, "pwview.html", ViewData{
				CurrentPage: "pwpush",
				Error:       "This link has expired or does not exist.",
			})
		} else {
			log.Printf("Database error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Check if expired
	if time.Now().After(push.ExpiresAt) || push.IsDeleted {
		p.renderTemplate(w, "pwview.html", ViewData{
			CurrentPage: "pwpush",
			Error:       "This link has expired or been deleted.",
		})
		return
	}

	// Check if max views reached
	if push.CurrentViews >= push.MaxViews {
		p.renderTemplate(w, "pwview.html", ViewData{
			CurrentPage: "pwpush",
			Error:       "This link has reached its maximum view limit.",
		})
		return
	}

	// Check if password is required and not yet verified
	passwordVerified := r.URL.Query().Get("verified") == "true"
	if push.PasswordHash != "" && !passwordVerified {
		clientIP := p.getClientIP(r)

		// Check if client is blocked
		if p.isBlocked(clientIP) {
			blockedUntil := p.getBlockedUntil(clientIP)
			p.renderTemplate(w, "pwview.html", ViewData{
				CurrentPage:     "pwpush",
				Push:            push,
				RequirePassword: true,
				IsBlocked:       true,
				BlockedUntil:    blockedUntil,
				Error:           fmt.Sprintf("Too many failed attempts. Please try again after %s.", blockedUntil.Format("15:04:05")),
			})
			return
		}

		// Show password form with remaining attempts
		remainingAttempts := p.getRemainingAttempts(clientIP)
		p.renderTemplate(w, "pwview.html", ViewData{
			CurrentPage:     "pwpush",
			Push:            push,
			RequirePassword: true,
			AttemptsLeft:    remainingAttempts,
		})
		return
	}

	// If require click is enabled and showText is not true, show the reveal page
	if push.RequireClick && !showText && push.PasswordHash == "" {
		p.renderTemplate(w, "pwview.html", ViewData{
			CurrentPage:  "pwpush",
			Push:         push,
			RequireClick: true,
			CanReveal:    true,
		})
		return
	}

	// Increment view count only when actually viewing content
	if showText || !push.RequireClick {
		_, err = p.db.Exec("UPDATE pushes SET current_views = current_views + 1 WHERE id = ?", path)
		if err != nil {
			log.Printf("Failed to increment view count: %v", err)
		}

		// Refresh push data to get updated view count
		push, err = p.getPushByID(path)
		if err != nil {
			log.Printf("Failed to get updated push data: %v", err)
		}
	}

	// Decrypt text
	text, err := p.decrypt(push.EncryptedText)
	if err != nil {
		log.Printf("Failed to decrypt text: %v", err)
		http.Error(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	// Render the text with delete option if auto-delete is enabled
	p.renderTemplate(w, "pwview.html", ViewData{
		CurrentPage: "pwpush",
		Push:        push,
		Text:        text,
		ShowText:    true,
		Revealed:    true,
	})
}

// StatusHandler provides API endpoint to check the status of links
func (p *PWPusher) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON request body containing array of link IDs
	type StatusRequest struct {
		IDs []string `json:"ids"`
	}

	type LinkStatus struct {
		ID           string `json:"id"`
		Exists       bool   `json:"exists"`
		IsExpired    bool   `json:"is_expired"`
		IsDeleted    bool   `json:"is_deleted"`
		CurrentViews int    `json:"current_views"`
		MaxViews     int    `json:"max_views"`
		ExpiresAt    string `json:"expires_at,omitempty"`
	}

	var req StatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var statuses []LinkStatus

	for _, id := range req.IDs {
		var push PushData
		var status LinkStatus
		status.ID = id

		// Query database for the push
		err := p.db.QueryRow(`
			SELECT id, expires_at, max_views, current_views, is_deleted
			FROM pushes 
			WHERE id = ?
		`, id).Scan(
			&push.ID,
			&push.ExpiresAt,
			&push.MaxViews,
			&push.CurrentViews,
			&push.IsDeleted,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				// Link doesn't exist in database
				status.Exists = false
			} else {
				log.Printf("Database error checking status for %s: %v", id, err)
				status.Exists = false
			}
		} else {
			status.Exists = true
			status.IsDeleted = push.IsDeleted
			status.CurrentViews = push.CurrentViews
			status.MaxViews = push.MaxViews
			status.ExpiresAt = push.ExpiresAt.Format(time.RFC3339)

			// Check if expired
			status.IsExpired = time.Now().After(push.ExpiresAt) ||
				push.CurrentViews >= push.MaxViews ||
				push.IsDeleted
		}

		statuses = append(statuses, status)
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statuses); err != nil {
		log.Printf("Failed to encode status response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Input validation and sanitization functions
func (p *PWPusher) validateAndSanitizeText(text string) (string, error) {
	if text == "" {
		return "", fmt.Errorf("text cannot be empty")
	}

	if len(text) > MaxTextLength {
		return "", fmt.Errorf("text too long (max %d characters)", MaxTextLength)
	}

	if !utf8.ValidString(text) {
		return "", fmt.Errorf("text contains invalid UTF-8 characters")
	}

	// Sanitize HTML
	sanitized := html.EscapeString(text)
	return sanitized, nil
}

func (p *PWPusher) validatePassword(password string) error {
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password too long (max %d characters)", MaxPasswordLength)
	}

	if len(password) > 0 && len(password) < MinPasswordLength {
		return fmt.Errorf("password too short (min %d characters)", MinPasswordLength)
	}

	if !utf8.ValidString(password) {
		return fmt.Errorf("password contains invalid UTF-8 characters")
	}

	return nil
}

func (p *PWPusher) validateInteger(value, min, max int, fieldName string) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d", fieldName, min, max)
	}
	return nil
}

func (p *PWPusher) validateAction(action string) error {
	if !allowedActionPattern.MatchString(action) {
		return fmt.Errorf("invalid action")
	}
	return nil
}

func (p *PWPusher) sanitizeString(input string) string {
	// Remove any potentially dangerous characters and HTML escape
	sanitized := html.EscapeString(strings.TrimSpace(input))

	// Limit length
	if len(sanitized) > 1000 {
		sanitized = sanitized[:1000]
	}

	return sanitized
}

// CSRF token management
func (p *PWPusher) generateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(bytes)
	p.csrfTokens[token] = time.Now()

	// Clean up expired tokens
	p.cleanupExpiredCSRFTokens()

	return token, nil
}

func (p *PWPusher) validateCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	createdAt, exists := p.csrfTokens[token]
	if !exists {
		return false
	}

	// Check if token has expired
	if time.Since(createdAt) > CSRFTokenExpiry {
		delete(p.csrfTokens, token)
		return false
	}

	// Remove token after use (one-time use)
	delete(p.csrfTokens, token)
	return true
}

func (p *PWPusher) cleanupExpiredCSRFTokens() {
	now := time.Now()
	for token, createdAt := range p.csrfTokens {
		if now.Sub(createdAt) > CSRFTokenExpiry {
			delete(p.csrfTokens, token)
		}
	}
}

// Add CSRF token to ViewData
func (p *PWPusher) addCSRFToken(data *ViewData) error {
	token, err := p.generateCSRFToken()
	if err != nil {
		return err
	}
	data.CSRFToken = token
	return nil
}

// Helper methods

func (p *PWPusher) getPushByID(id string) (*PushData, error) {
	var push PushData
	var passwordHash sql.NullString
	err := p.db.QueryRow(`
		SELECT id, encrypted_text, created_at, expires_at, max_views, current_views, 
		       require_click, auto_delete, creator_ip, is_deleted, password_hash
		FROM pushes WHERE id = ?`, id).Scan(
		&push.ID, &push.EncryptedText, &push.CreatedAt, &push.ExpiresAt,
		&push.MaxViews, &push.CurrentViews, &push.RequireClick, &push.AutoDelete,
		&push.CreatorIP, &push.IsDeleted, &passwordHash)

	if err != nil {
		return nil, err
	}

	// Convert sql.NullString to string
	if passwordHash.Valid {
		push.PasswordHash = passwordHash.String
	}

	return &push, nil
}

func (p *PWPusher) saveToHistory(w http.ResponseWriter, r *http.Request, id string, createdAt, expiresAt time.Time, maxViews int, fullURL string) {
	// Get existing history from cookies (JavaScript format)
	history := p.getHistoryFromCookies(r)

	// Create full URL for history
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fullURL == "" {
		fullURL = fmt.Sprintf("%s://%s/pwview/%s", scheme, r.Host, id)
	}

	// Add new item to front (matching JavaScript HistoryItem structure)
	newItem := map[string]interface{}{
		"id":          id,
		"url":         fullURL,
		"createdAt":   createdAt.Format(time.RFC3339),
		"expiresAt":   expiresAt.Format(time.RFC3339),
		"maxViews":    maxViews,
		"viewCount":   0,
		"previewText": "Hidden content", // Default preview
	}

	// Convert to array of maps for easier manipulation
	var historyArray []map[string]interface{}
	if len(history) > 0 {
		historyArray = history
	}

	// Add new item to front
	historyArray = append([]map[string]interface{}{newItem}, historyArray...)

	// Keep only last 50 items
	if len(historyArray) > 50 {
		historyArray = historyArray[:50]
	}

	// Save back to cookies (JavaScript compatible format)
	p.setHistoryCookies(w, historyArray)
}

func (p *PWPusher) getHistoryFromCookies(r *http.Request) []map[string]interface{} {
	cookie, err := r.Cookie("pwpush_history")
	if err != nil {
		return []map[string]interface{}{}
	}

	// Decode URL-encoded JSON (JavaScript format)
	decodedValue, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return []map[string]interface{}{}
	}

	var history []map[string]interface{}
	if err := json.Unmarshal([]byte(decodedValue), &history); err != nil {
		return []map[string]interface{}{}
	}

	return history
}

func (p *PWPusher) setHistoryCookies(w http.ResponseWriter, history []map[string]interface{}) {
	data, err := json.Marshal(history)
	if err != nil {
		return
	}

	// URL encode the JSON (JavaScript compatible)
	encoded := url.QueryEscape(string(data))

	http.SetCookie(w, &http.Cookie{
		Name:     "pwpush_history",
		Value:    encoded,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
		HttpOnly: false,             // Allow JavaScript access
		Secure:   false,             // Allow HTTP for development
	})
}

func (p *PWPusher) clearHistoryCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pwpush_history",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func (p *PWPusher) renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	log.Printf("Attempting to render template: %s", templateName)

	// Auto-add CSRF token for ViewData structs
	if viewData, ok := data.(*ViewData); ok && viewData.CSRFToken == "" {
		if err := p.addCSRFToken(viewData); err != nil {
			log.Printf("Error adding CSRF token: %v", err)
		}
	} else if viewDataValue, ok := data.(ViewData); ok && viewDataValue.CSRFToken == "" {
		// Handle by value ViewData
		if err := p.addCSRFToken(&viewDataValue); err != nil {
			log.Printf("Error adding CSRF token: %v", err)
		} else {
			data = viewDataValue // Update data with new CSRF token
		}
	}

	// Choose the appropriate template set based on the template name
	var templates *template.Template
	if templateName == "pwpush.html" {
		templates = p.pushTemplates
	} else if templateName == "pwview.html" {
		templates = p.viewTemplates
	} else {
		log.Printf("Unknown template: %s, using basic page", templateName)
		p.renderBasicPage(w, templateName, data)
		return
	}

	// Check if template exists
	if templates.Lookup(templateName) == nil {
		log.Printf("Template %s not found, using basic page", templateName)
		p.renderBasicPage(w, templateName, data)
		return
	}

	log.Printf("Template %s found, executing with data: %+v", templateName, data)
	// Execute the specific template directly
	if err := templates.ExecuteTemplate(w, templateName, data); err != nil {
		log.Printf("Template error: %v", err)
		// Fallback to basic HTML
		w.Write([]byte(`<!DOCTYPE html><html><head><title>PWPusher</title></head><body>
			<h1>PWPusher - Template Error</h1>
			<p>Error: ` + err.Error() + `</p>
			<p>Template: ` + templateName + `</p>
		</body></html>`))
	}
}

func (p *PWPusher) renderBasicPage(w http.ResponseWriter, templateName string, data interface{}) {
	// Basic fallback templates
	switch templateName {
	case "pwpush.html":
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Password Pusher</title></head><body>
<h1>Share Text Securely</h1>
<form method="post">
<textarea name="text" placeholder="Enter text to share..." required></textarea><br>
<label>Expire after: <input type="number" name="expiry_days" value="7" min="1" max="90"> days</label><br>
<label>Max views: <input type="number" name="max_views" value="10" min="1" max="100"></label><br>
<label><input type="checkbox" name="require_click" checked> Require click to reveal</label><br>
<label><input type="checkbox" name="auto_delete" checked> Auto-delete after viewing</label><br>
<label><input type="checkbox" name="track_history"> Save to history</label><br>
<button type="submit">Create Secure Link</button>
</form>
</body></html>`)

	case "pwview.html":
		viewData := data.(ViewData)
		if viewData.Error != "" {
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Error</title></head><body>
<h1>Error</h1><p>%s</p>
<a href="/pwpush">Create New Link</a>
</body></html>`, viewData.Error)
		} else if viewData.RequireClick && viewData.CanReveal {
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Reveal Content</title></head><body>
<h1>Protected Content</h1>
<p>This content is protected. Click below to reveal it.</p>
<p><strong>Note:</strong> This will count as a view and may auto-delete the content.</p>
<a href="?show=true" style="background: #007cba; color: white; padding: 10px 20px; text-decoration: none;">Reveal Content</a>
</body></html>`)
		} else if viewData.ShowText {
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Shared Content</title></head><body>
<h1>Shared Content</h1>
<div style="background: #f5f5f5; padding: 20px; border: 1px solid #ddd;">
<pre>%s</pre>
</div>
<p><small>Views: %d/%d | Expires: %s</small></p>
<a href="/pwpush">Create New Link</a>
</body></html>`, viewData.Text, viewData.Push.CurrentViews+1, viewData.Push.MaxViews, viewData.Push.ExpiresAt.Format("2006-01-02 15:04:05"))
		}
	}
}

// Cleanup expired entries
func (p *PWPusher) CleanupExpired() {
	_, err := p.db.Exec("DELETE FROM pushes WHERE expires_at < ? OR is_deleted = 1", time.Now())
	if err != nil {
		log.Printf("Failed to cleanup expired pushes: %v", err)
	}
}

// NewHandler creates a new HTTP handler for PWPusher
func NewHandler(embeddedFS fs.FS, encryptionKey string) (*PWPusher, error) {
	return NewPWPusher(embeddedFS, encryptionKey)
}
