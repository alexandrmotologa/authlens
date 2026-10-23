package web

import "embed"

// DistFS contains the embedded production assets for the React 19 studio.
//
//go:embed all:dist
var DistFS embed.FS
