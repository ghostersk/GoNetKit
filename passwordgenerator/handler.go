package passwordgenerator

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"headeranalyzer/security"
)

type Handler struct {
	templates *template.Template
	csrf      *security.CSRFManager
	validator *security.InputValidator
}

type PasswordConfig struct {
	Type            string
	Length          int
	IncludeUpper    bool
	IncludeLower    bool
	NumberCount     int
	SpecialChars    string
	MinSpecialChars int
	NoConsecutive   bool
	WordCount       int
	UseNumbers      bool
	UseSpecial      bool
	NumberPosition  string
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
	}).ParseFS(embeddedFiles, "web/base.html", "web/pwgenerator.html"))

	return &Handler{
		templates: tmpl,
		csrf:      security.NewCSRFManager(time.Hour),
		validator: security.NewInputValidator(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Generate CSRF token
	csrfToken, err := h.csrf.GenerateToken()
	if err != nil {
		http.Redirect(w, r, "/pwgenerator?error="+url.QueryEscape("Security token generation failed"), http.StatusSeeOther)
		return
	}

	// Parse URL parameters to set default values
	config := PasswordConfig{
		Type:            getStringParam(r, "type", "passphrase"),
		Length:          getIntParam(r, "length", 12),
		IncludeUpper:    getBoolParam(r, "includeUpper", true),
		IncludeLower:    getBoolParam(r, "includeLower", true),
		NumberCount:     getIntParam(r, "numberCount", 2),
		SpecialChars:    getStringParam(r, "specialChars", "!@#$%&*-_=+."),
		MinSpecialChars: getIntParam(r, "minSpecialChars", 3),
		NoConsecutive:   getBoolParam(r, "noConsecutive", true),
		WordCount:       getIntParam(r, "wordCount", 3),
		UseNumbers:      getBoolParam(r, "useNumbers", true),
		UseSpecial:      getBoolParam(r, "useSpecial", false),
		NumberPosition:  getStringParam(r, "numberPosition", "end"),
	}

	data := struct {
		CurrentPage string
		Config      PasswordConfig
		CSRFToken   string
	}{
		CurrentPage: "password",
		Config:      config,
		CSRFToken:   csrfToken,
	}
	h.templates.ExecuteTemplate(w, "pwgenerator.html", data)
}

// Helper functions to parse URL parameters
func getStringParam(r *http.Request, key, defaultValue string) string {
	if value := r.URL.Query().Get(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntParam(r *http.Request, key string, defaultValue int) int {
	if value := r.URL.Query().Get(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolParam(r *http.Request, key string, defaultValue bool) bool {
	if value := r.URL.Query().Get(key); value != "" {
		return value == "true" || value == "1" || value == "on"
	}
	return defaultValue
}
