package security

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// InputValidator provides input validation and sanitization methods
type InputValidator struct{}

// NewInputValidator creates a new input validator
func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

// SanitizeHTML escapes HTML characters to prevent XSS
func (v *InputValidator) SanitizeHTML(input string) string {
	return html.EscapeString(input)
}

// ValidateAndSanitizeText validates text input and removes dangerous content
func (v *InputValidator) ValidateAndSanitizeText(text string, maxLength int) (string, error) {
	// Check for empty input
	if strings.TrimSpace(text) == "" {
		return "", &ValidationError{Field: "text", Message: "Text cannot be empty"}
	}

	// Check length limits
	if len(text) > maxLength {
		return "", &ValidationError{Field: "text", Message: "Text exceeds maximum length"}
	}

	// Check for valid UTF-8
	if !utf8.ValidString(text) {
		return "", &ValidationError{Field: "text", Message: "Text contains invalid characters"}
	}

	// Remove null bytes and control characters (except normal whitespace)
	cleaned := regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`).ReplaceAllString(text, "")

	// Normalize line endings
	cleaned = strings.ReplaceAll(cleaned, "\r\n", "\n")
	cleaned = strings.ReplaceAll(cleaned, "\r", "\n")

	return cleaned, nil
}

// ValidatePassword validates password requirements
func (v *InputValidator) ValidatePassword(password string) error {
	if len(password) < 1 {
		return &ValidationError{Field: "password", Message: "Password cannot be empty"}
	}

	if len(password) > 1000 {
		return &ValidationError{Field: "password", Message: "Password too long"}
	}

	// Check for valid UTF-8
	if !utf8.ValidString(password) {
		return &ValidationError{Field: "password", Message: "Password contains invalid characters"}
	}

	return nil
}

// ValidateEmailHeaders validates email header input with enhanced detection and large file handling
func (v *InputValidator) ValidateEmailHeaders(headers string) (string, error) {
	if strings.TrimSpace(headers) == "" {
		return "", &ValidationError{Field: "headers", Message: "Email headers cannot be empty"}
	}

	// Check for valid UTF-8
	if !utf8.ValidString(headers) {
		return "", &ValidationError{Field: "headers", Message: "Headers contain invalid characters"}
	}

	// Extract only the header portion for large files
	processedHeaders := v.extractEmailHeadersOnly(headers)

	// Check if we have valid email headers
	if !v.containsValidEmailHeaders(processedHeaders) {
		return "", &ValidationError{Field: "headers", Message: "No valid email headers found. Please provide actual email headers."}
	}

	// After processing, check reasonable size limit
	if len(processedHeaders) > 200*1024 { // 200KB after processing
		return "", &ValidationError{Field: "headers", Message: "Email headers too large after processing"}
	}

	return processedHeaders, nil
}

// extractEmailHeadersOnly extracts only the email headers from potentially large files
func (v *InputValidator) extractEmailHeadersOnly(content string) string {
	var result strings.Builder
	lines := strings.Split(content, "\n")
	headerSection := true
	headerLines := 0
	maxHeaderLines := 1000

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Stop if we've processed too many header lines (safety limit)
		if headerLines >= maxHeaderLines {
			break
		}

		// Empty line typically separates headers from body
		if strings.TrimSpace(line) == "" {
			if headerSection && headerLines > 0 {
				// End of headers section
				break
			}
			continue
		}

		// MIME boundary indicates end of headers/start of body content
		if strings.HasPrefix(line, "--") && strings.Contains(line, "boundary") {
			break
		}

		// Skip obvious encoded content (base64-like long strings without spaces)
		if len(line) > 200 && !strings.Contains(line, " ") && !strings.Contains(line, ":") {
			continue
		}

		// Skip lines that look like encoded content
		if v.looksLikeEncodedContent(line) {
			continue
		}

		// Check if this looks like a header line
		if headerSection && (v.looksLikeEmailHeader(line) || v.isHeaderContinuation(line)) {
			result.WriteString(line)
			result.WriteString("\n")
			headerLines++
		} else if headerSection && !v.looksLikeEmailHeader(line) && !v.isHeaderContinuation(line) {
			// If we encounter a non-header line in header section, we might be done with headers
			if headerLines > 5 { // Only stop if we've seen some headers already
				break
			}
		}
	}

	return result.String()
}

// containsValidEmailHeaders checks if the content contains actual email headers
func (v *InputValidator) containsValidEmailHeaders(content string) bool {
	lines := strings.Split(content, "\n")
	headerCount := 0
	commonHeaders := []string{
		"received:", "from:", "to:", "subject:", "date:", "message-id:",
		"return-path:", "delivered-to:", "authentication-results:",
		"dkim-signature:", "content-type:", "mime-version:", "x-",
		"reply-to:", "cc:", "bcc:", "sender:", "list-id:",
	}

	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}

		// Check if this line contains a common email header
		for _, header := range commonHeaders {
			if strings.HasPrefix(line, header) {
				headerCount++
				break
			}
		}

		// Also check for basic header format
		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Additional validation for header format
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				// Header name should contain only valid characters
				if regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`).MatchString(headerName) {
					headerCount++
				}
			}
		}
	}

	// Need at least 3 valid headers to consider it email headers
	return headerCount >= 3
}

// looksLikeEmailHeader checks if a line looks like an email header
func (v *InputValidator) looksLikeEmailHeader(line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}

	// Header continuation lines start with space or tab
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return false // These are handled separately
	}

	// Must contain a colon
	if !strings.Contains(line, ":") {
		return false
	}

	// Split on first colon
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return false
	}

	headerName := strings.TrimSpace(parts[0])

	// Header name should not be empty and should contain only valid characters
	if headerName == "" {
		return false
	}

	// Valid header name pattern
	validHeaderName := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	return validHeaderName.MatchString(headerName)
}

// isHeaderContinuation checks if a line is a header continuation
func (v *InputValidator) isHeaderContinuation(line string) bool {
	return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
}

// looksLikeEncodedContent checks if a line looks like encoded content that should be skipped
func (v *InputValidator) looksLikeEncodedContent(line string) bool {
	line = strings.TrimSpace(line)

	// Very long lines without spaces are likely encoded
	if len(line) > 100 && !strings.Contains(line, " ") && !strings.Contains(line, ":") {
		return true
	}

	// Base64-like patterns (long strings of alphanumeric + / + =)
	if len(line) > 50 {
		base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
		if base64Pattern.MatchString(line) && !strings.Contains(line, ":") {
			// Count alphanumeric characters vs spaces
			alphanumeric := regexp.MustCompile(`[A-Za-z0-9+/=]`).FindAllString(line, -1)
			if float64(len(alphanumeric)) > float64(len(line))*0.8 { // More than 80% alphanumeric
				return true
			}
		}
	}

	return false
}

// ValidateDNSQuery validates DNS query input
func (v *InputValidator) ValidateDNSQuery(query string) (string, error) {
	query = strings.TrimSpace(query)

	if query == "" {
		return "", &ValidationError{Field: "query", Message: "DNS query cannot be empty"}
	}

	if len(query) > 253 { // Maximum domain name length
		return "", &ValidationError{Field: "query", Message: "DNS query too long"}
	}

	// Allow only valid DNS characters: letters, numbers, dots, hyphens, and colons (for IPv6)
	validDNS := regexp.MustCompile(`^[a-zA-Z0-9\.\-:]+$`)
	if !validDNS.MatchString(query) {
		return "", &ValidationError{Field: "query", Message: "DNS query contains invalid characters"}
	}

	return query, nil
}

// ValidateIntRange validates integer input within a range
func (v *InputValidator) ValidateIntRange(value, min, max int, fieldName string) error {
	if value < min || value > max {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("Value must be between %d and %d", min, max),
		}
	}
	return nil
}

// GetClientIP extracts the real client IP from request headers
func (v *InputValidator) GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}

	// Remove IPv6 brackets
	ip = strings.Trim(ip, "[]")

	return ip
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}
