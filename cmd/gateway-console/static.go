package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/revokerclient"
)

func handlerFor(auditPath string, client *revokerclient.Client, uiDir string) http.Handler {
	api := newConsole(auditPath, client)
	if uiDir == "" {
		return api
	}
	return &uiHandler{api: api, root: uiDir}
}

func checkUIDir(dir string) error {
	if strings.ContainsAny(dir, "\r\n") {
		return errors.New("--ui must be a single line")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("--ui: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("--ui must be a directory, not a symlink")
	}
	return nil
}

type uiHandler struct {
	api  http.Handler
	root string
}

func (h *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		h.api.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	full, err := uiFile(h.root, r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	if ctype := uiContentType(full); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	http.ServeContent(w, r, filepath.Base(full), info.ModTime(), file)
}

func uiContentType(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	default:
		return ""
	}
}

func uiFile(root, urlPath string) (string, error) {
	if urlPath == "" || strings.ContainsAny(urlPath, "\x00\\") {
		return "", errors.New("path")
	}
	cleaned := path.Clean("/" + urlPath)
	if cleaned == "/" {
		cleaned = "/index.html"
	}
	rel := strings.TrimPrefix(cleaned, "/")
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		return "", errors.New("path")
	}
	base := path.Base(rel)
	if base == "." || base == "/" || strings.HasPrefix(base, ".") {
		return "", errors.New("path")
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".html", ".css", ".js", ".svg":
	default:
		return "", errors.New("type")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(rel))
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if fullAbs != rootAbs && !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", errors.New("escape")
	}
	info, err := os.Lstat(fullAbs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("file")
	}
	return fullAbs, nil
}
