package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/alexandrmotologa/authlens/web"
	"github.com/gin-gonic/gin"
)

// RegisterStatic mounts embedded frontend single-page application assets.
func RegisterStatic(r *gin.Engine) {
	subFS, err := fs.Sub(web.DistFS, "dist")
	if err != nil {
		return
	}

	fileServer := http.FileServer(http.FS(subFS))

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Don't intercept API or OIDC endpoints with SPA HTML fallback
		if strings.HasPrefix(path, "/api") ||
			strings.HasPrefix(path, "/oauth") ||
			strings.HasPrefix(path, "/.well-known") ||
			path == "/userinfo" {
			c.JSON(http.StatusNotFound, gin.H{"error": "endpoint not found"})
			return
		}

		// Check if file exists in embedded FS
		trimmed := strings.TrimPrefix(path, "/")
		if trimmed != "" {
			if f, err := subFS.Open(trimmed); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}
		}

		// Fallback to index.html for client-side SPA routing
		indexBytes, err := fs.ReadFile(subFS, "index.html")
		if err != nil {
			c.String(http.StatusOK, "AuthLens Studio")
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
	})
}
