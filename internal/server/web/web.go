// Package web embeds the dependency-free Kiwi web dashboard assets
// (index.html, app.js, app.css). The server serves them through
// internal/server/ui.go under the strict CSP declared there.
package web

import "embed"

//go:embed index.html app.js app.css
var Assets embed.FS
