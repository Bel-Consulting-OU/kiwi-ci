package server

import (
	"io/fs"
	"net/http"

	web "github.com/Bel-Consulting-OU/kiwi-ci/internal/server/web"
)

// webCSP is the Content-Security-Policy applied to the dashboard and its
// assets: same-origin only, no inline scripts or styles, no framing, and a
// fixed document base URI.
const webCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"

// webAssets returns the embedded dashboard file tree.
func webAssets() fs.FS {
	sub, err := fs.Sub(web.Assets, ".")
	if err != nil {
		panic("kiwi server: embedded web assets: " + err.Error())
	}
	return sub
}

// ui serves the embedded dashboard at GET /.
func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	index, err := fs.ReadFile(webAssets(), "index.html")
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", webCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(index)
}

// static serves the embedded JS/CSS assets under /static/.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", webCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.FileServerFS(webAssets()).ServeHTTP(w, r)
}
