// Package web embeds the single-page UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS serves index.html at "/".
var FS, _ = fs.Sub(files, "static")
