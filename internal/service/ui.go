package service

import (
	_ "embed"
	"net/http"
)

//go:embed web/manager.html
var managerHTML []byte

//go:embed web/manager.js
var managerJS []byte

//go:embed web/manager.css
var managerCSS []byte

func isManagerUIPath(path string) bool {
	return path == "/manager" || path == "/manager/" || path == "/manager/manager.js" || path == "/manager/manager.css"
}

func (s *Server) serveManagerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	body, contentType := managerHTML, "text/html; charset=utf-8"
	switch r.URL.Path {
	case "/manager/manager.js":
		body, contentType = managerJS, "text/javascript; charset=utf-8"
	case "/manager/manager.css":
		body, contentType = managerCSS, "text/css; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
