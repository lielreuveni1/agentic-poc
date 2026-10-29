// Package api exposes the scan flow over HTTP and serves the web UI.
package api

import (
	"encoding/json"
	"io/fs"
	"net/http"

	"ox_home_assignment/internal/pipeline"
	"ox_home_assignment/internal/scan"
	"ox_home_assignment/internal/scanners"
)

type API struct {
	store  *scan.Store
	runner *pipeline.Runner
	web    fs.FS
}

func New(store *scan.Store, runner *pipeline.Runner, web fs.FS) *API {
	return &API{store: store, runner: runner, web: web}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/scans", a.createScan)
	mux.HandleFunc("GET /api/scans", a.listScans)
	mux.HandleFunc("GET /api/scans/{id}", a.getScan)
	mux.HandleFunc("GET /api/scans/{id}/report", a.getReport)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("GET /", http.FileServerFS(a.web))
	return mux
}

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoURL string `json:"repo_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON: {\"repo_url\": \"...\"}")
		return
	}
	url, err := scanners.NormalizeRepoURL(req.RepoURL)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	sc := a.store.Create(url, pipeline.NewStages())
	a.runner.Start(sc.ID)
	w.Header().Set("Location", "/api/scans/"+sc.ID)
	writeJSON(w, http.StatusAccepted, sc)
}

func (a *API) listScans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.store.List())
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (a *API) getReport(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.store.Get(r.PathValue("id"))
	switch {
	case !ok:
		writeError(w, http.StatusNotFound, "scan not found")
	case sc.Report == nil:
		writeError(w, http.StatusConflict, "report not ready: scan is "+string(sc.Status))
	default:
		writeJSON(w, http.StatusOK, sc.Report)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
