package landingpage

import (
	"html/template"
	"io/fs"
	"net/http"
)

type Handler struct {
	template *template.Template
}

func NewHandler(embeddedFS fs.FS) (*Handler, error) {
	tmpl, err := template.ParseFS(embeddedFS, "web/base.html", "web/landing_page.html")
	if err != nil {
		return nil, err
	}

	return &Handler{
		template: tmpl,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only handle root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		CurrentPage string
	}{
		CurrentPage: "home",
	}

	w.Header().Set("Content-Type", "text/html")
	if err := h.template.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
