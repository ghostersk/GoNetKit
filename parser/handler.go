package parser

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"headeranalyzer/security"
)

type Handler struct {
	templates *template.Template
	csrf      *security.CSRFManager
	validator *security.InputValidator
}

func NewHandler(embeddedFiles embed.FS) *Handler {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"splitString": func(s, delimiter string) []string {
			return strings.Split(s, delimiter)
		},
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"ge": func(a, b int) bool {
			return a >= b
		},
		"gt": func(a, b int) bool {
			return a > b
		},
		"eq": func(a, b interface{}) bool {
			return a == b
		},
		"index": func(slice []string, i int) string {
			if i >= 0 && i < len(slice) {
				return slice[i]
			}
			return ""
		},
		"len": func(v interface{}) int {
			switch s := v.(type) {
			case []string:
				return len(s)
			case map[string]string:
				return len(s)
			case string:
				return len(s)
			default:
				return 0
			}
		},
		"ne": func(a, b interface{}) bool {
			return a != b
		},
	}).ParseFS(embeddedFiles, "web/base.html", "web/headeranalyzer.html"))

	return &Handler{
		templates: tmpl,
		csrf:      security.NewCSRFManager(time.Hour),
		validator: security.NewInputValidator(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !h.csrf.ValidateToken(csrfToken) {
			http.Redirect(w, r, "/?error="+url.QueryEscape("Invalid security token. Please try again."), http.StatusSeeOther)
			return
		}

		// Get and validate headers input
		headers := r.FormValue("headers")
		log.Printf("DEBUG: Received headers input: %d characters", len(headers))

		validatedHeaders, err := h.validator.ValidateEmailHeaders(headers)
		if err != nil {
			log.Printf("DEBUG: Validation failed: %v", err)
			if security.IsValidationError(err) {
				http.Redirect(w, r, "/?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/?error="+url.QueryEscape("Invalid input provided"), http.StatusSeeOther)
			return
		}

		log.Printf("DEBUG: Headers validated successfully")
		report := Analyze(validatedHeaders)
		log.Printf("DEBUG: Analysis completed, From field: '%s'", report.From)
		// Create a wrapper struct to include current page info
		data := struct {
			*Report
			CurrentPage string
		}{
			Report:      report,
			CurrentPage: "home",
		}

		log.Printf("DEBUG: About to render template with data")
		err = h.templates.ExecuteTemplate(w, "headeranalyzer.html", data)
		if err != nil {
			log.Printf("ERROR: Template execution failed: %v", err)
			http.Error(w, "Template rendering failed", http.StatusInternalServerError)
			return
		}
		log.Printf("DEBUG: Template rendered successfully")
		return
	}

	// Generate CSRF token for GET requests
	csrfToken, err := h.csrf.GenerateToken()
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape("Security token generation failed"), http.StatusSeeOther)
		return
	}

	// For GET requests, create an empty report so template conditions work
	data := struct {
		*Report
		CurrentPage string
		CSRFToken   string
	}{
		Report:      &Report{}, // Empty report so .From will be empty string
		CurrentPage: "home",
		CSRFToken:   csrfToken,
	}
	h.templates.ExecuteTemplate(w, "headeranalyzer.html", data)
}
