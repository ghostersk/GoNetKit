package parser

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
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		headers := r.FormValue("headers")
		report := Analyze(headers)
		// Create a wrapper struct to include current page info
		data := struct {
			*Report
			CurrentPage string
		}{
			Report:      report,
			CurrentPage: "home",
		}
		h.templates.ExecuteTemplate(w, "headeranalyzer.html", data)
		return
	}
	// For GET requests, create an empty report so template conditions work
	data := struct {
		*Report
		CurrentPage string
	}{
		Report:      &Report{}, // Empty report so .From will be empty string
		CurrentPage: "home",
	}
	h.templates.ExecuteTemplate(w, "headeranalyzer.html", data)
}
