package resolver

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gonetkit/security"
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
	}).ParseFS(embeddedFiles, "web/base.html", "web/dns.html"))

	return &Handler{
		templates: tmpl,
		csrf:      security.NewCSRFManager(time.Hour),
		validator: security.NewInputValidator(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Generate CSRF token for the page
	csrfToken, err := h.csrf.GenerateToken()
	if err != nil {
		http.Redirect(w, r, "/dns?error="+url.QueryEscape("Security token generation failed"), http.StatusSeeOther)
		return
	}

	data := struct {
		CurrentPage string
		CSRFToken   string
	}{
		CurrentPage: "dns",
		CSRFToken:   csrfToken,
	}
	h.templates.ExecuteTemplate(w, "dns.html", data)
}
