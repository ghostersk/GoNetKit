package resolver

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

type Handler struct {
	templates *template.Template
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
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := struct {
		CurrentPage string
	}{
		CurrentPage: "dns",
	}
	h.templates.ExecuteTemplate(w, "dns.html", data)
}
