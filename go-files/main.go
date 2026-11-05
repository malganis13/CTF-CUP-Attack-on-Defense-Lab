package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	teamID       = env("TEAM_ID", "blue")
	checkerToken = env("CHECKER_TOKEN", "CHANGE-ME-LOCAL-ONLY")
	patched      = envBool("PATCHED", false)
	dataRoot     = env("DATA_ROOT", "/data")
)

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.ToLower(os.Getenv(key))
	if value == "1" || value == "true" || value == "yes" || value == "on" {
		return true
	}
	if value == "0" || value == "false" || value == "no" || value == "off" {
		return false
	}
	return fallback
}

func jsonResponse(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func checkerAuthorized(r *http.Request) bool {
	provided := r.Header.Get("X-Checker-Token")
	return checkerToken != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(checkerToken)) == 1
}

func publicRoot() string { return filepath.Join(dataRoot, "public") }
func privateRoot() string { return filepath.Join(dataRoot, "private") }

func initStorage() error {
	if err := os.MkdirAll(publicRoot(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(privateRoot(), teamID), 0700); err != nil {
		return err
	}
	readme := filepath.Join(publicRoot(), "readme.txt")
	if _, err := os.Stat(readme); os.IsNotExist(err) {
		return os.WriteFile(readme, []byte("Go Files training service. Public sample file.\n"), 0644)
	}
	return nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]any{"status": "ok", "service": "go-files", "team": teamID, "patched": patched})
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || len(name) > 256 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	var target string
	if patched {
		// The resolved path must remain below publicRoot. Do not trust a URL path
		// or a filename merely because it came from a supposedly safe client.
		root, rootErr := filepath.EvalSymlinks(publicRoot())
		candidate, candidateErr := filepath.EvalSymlinks(filepath.Join(publicRoot(), filepath.FromSlash(name)))
		if rootErr != nil || candidateErr != nil {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "file not found"})
			return
		}
		relative, err := filepath.Rel(root, candidate)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
			jsonResponse(w, http.StatusForbidden, map[string]string{"error": "file is outside public directory"})
			return
		}
		target = candidate
	} else {
		// INTENTIONAL PATH TRAVERSAL: user input is joined without a containment check.
		target = filepath.Join(publicRoot(), filepath.FromSlash(name))
	}

	contents, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "file not found"})
		} else {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
		}
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"name": name, "contents": string(contents)})
}

func handleChecker(w http.ResponseWriter, r *http.Request) {
	if !checkerAuthorized(r) {
		jsonResponse(w, http.StatusForbidden, map[string]string{"error": "checker authentication required"})
		return
	}
	if r.URL.Path == "/_checker/putflag" && r.Method == http.MethodPost {
		var payload struct {
			FlagID string `json:"flag_id"`
			Flag   string `json:"flag"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&payload); err != nil || payload.FlagID == "" || payload.Flag == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "flag_id and flag required"})
			return
		}
		path := filepath.Join(privateRoot(), teamID, "flag.txt")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "flag storage failed"})
			return
		}
		if err := os.WriteFile(path, []byte(fmt.Sprintf("flag_id=%s;flag=%s", payload.FlagID, payload.Flag)), 0600); err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "flag storage failed"})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "stored"})
		return
	}
	if r.URL.Path == "/_checker/checkflag" && r.Method == http.MethodGet {
		contents, err := os.ReadFile(filepath.Join(privateRoot(), teamID, "flag.txt"))
		if err != nil {
			jsonResponse(w, http.StatusConflict, map[string]string{"error": "flag missing"})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"stored": string(contents)})
		return
	}
	jsonResponse(w, http.StatusNotFound, map[string]string{"error": "checker route not found"})
}

func router(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/health" && r.Method == http.MethodGet:
		handleHealth(w, r)
	case r.URL.Path == "/api/files/download" && r.Method == http.MethodGet:
		handleFile(w, r)
	case strings.HasPrefix(r.URL.Path, "/_checker/"):
		handleChecker(w, r)
	default:
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func main() {
	if err := initStorage(); err != nil {
		log.Fatal(err)
	}
	port := env("PORT", "8084")
	server := &http.Server{Addr: ":" + port, Handler: http.HandlerFunc(router)}
	log.Printf("starting go-files on :%s team=%s patched=%t data=%s", port, teamID, patched, dataRoot)
	log.Fatal(server.ListenAndServe())
}
