package pwpusher

import (
	"net/http"
	"strings"
)

// RegisterRoutes registers all PWPusher routes with the given ServeMux
func (p *PWPusher) RegisterRoutes(mux *http.ServeMux) {
	// Main PWPusher page
	mux.HandleFunc("/pwpush", p.IndexHandler)

	// API endpoint for checking link status
	mux.HandleFunc("/pwpush/api/status/", p.StatusHandler)

	// PWPusher sub-routes (push viewing)
	mux.HandleFunc("/pwpush/", func(w http.ResponseWriter, r *http.Request) {
		// Extract push ID from URL path like /pwpush/abc123
		id := strings.TrimPrefix(r.URL.Path, "/pwpush/")
		if id != "" {
			// Redirect to view handler with proper ID
			r.URL.Path = "/pwview/" + id
			p.ViewHandler(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	// Direct view handler for clean URLs
	mux.HandleFunc("/pwview/", p.ViewHandler)
}

// RegisterRoutesWithDefault registers all PWPusher routes with the default ServeMux
func (p *PWPusher) RegisterRoutesWithDefault() {
	p.RegisterRoutes(http.DefaultServeMux)
}
