// Package web embeds the dependency-free Kiwi web dashboard assets
// (index.html, app.js, app.css, brand marks from the visual identity
// document). The server serves them through internal/server/ui.go under
// the strict CSP declared there.
package web

import "embed"

//go:embed index.html app.js app.css logo-mark.png logo-lockup-dark.png favicon.png
var Assets embed.FS
