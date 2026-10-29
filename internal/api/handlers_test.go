package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ox_home_assignment/internal/pipeline"
	"ox_home_assignment/internal/scan"
	"ox_home_assignment/web"
)

// newServer uses a 1ns scan timeout so background scans fail instantly instead of cloning from GitHub.
func newServer(t *testing.T) (*httptest.Server, *scan.Store) {
	store := scan.NewStore()
	runner := pipeline.New(store, nil, nil, "", 1, time.Nanosecond)
	srv := httptest.NewServer(New(store, runner, web.FS).Handler())
	t.Cleanup(srv.Close)
	return srv, store
}

func do(t *testing.T, method, url, body string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestCreateScan(t *testing.T) {
	srv, _ := newServer(t)

	code, hdr, body := do(t, "POST", srv.URL+"/api/scans", `{"repo_url":"github.com/OWASP/NodeGoat"}`)
	var sc scan.Scan
	json.Unmarshal([]byte(body), &sc)
	if code != http.StatusAccepted || sc.ID == "" || sc.RepoURL != "https://github.com/OWASP/NodeGoat" || hdr.Get("Location") != "/api/scans/"+sc.ID {
		t.Errorf("valid request: %d %v %s", code, hdr.Get("Location"), body)
	}

	if code, _, body := do(t, "POST", srv.URL+"/api/scans", `{"repo_url":"https://gitlab.com/a/b"}`); code != http.StatusUnprocessableEntity || !strings.Contains(body, "error") {
		t.Errorf("invalid URL: %d %s", code, body)
	}
	if code, _, _ := do(t, "POST", srv.URL+"/api/scans", `not json`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
}

func TestListAndGetScan(t *testing.T) {
	srv, store := newServer(t)
	sc := store.Create("https://github.com/o/r", pipeline.NewStages())

	code, _, body := do(t, "GET", srv.URL+"/api/scans", "")
	if code != http.StatusOK || !strings.Contains(body, sc.ID) {
		t.Errorf("list: %d %s", code, body)
	}
	if code, _, body := do(t, "GET", srv.URL+"/api/scans/"+sc.ID, ""); code != http.StatusOK || !strings.Contains(body, `"status":"queued"`) {
		t.Errorf("get: %d %s", code, body)
	}
	if code, _, _ := do(t, "GET", srv.URL+"/api/scans/nope", ""); code != http.StatusNotFound {
		t.Errorf("missing scan: %d", code)
	}
}

func TestGetReport(t *testing.T) {
	srv, store := newServer(t)
	sc := store.Create("https://github.com/o/r", pipeline.NewStages())

	if code, _, body := do(t, "GET", srv.URL+"/api/scans/"+sc.ID+"/report", ""); code != http.StatusConflict || !strings.Contains(body, "queued") {
		t.Errorf("not ready: %d %s", code, body)
	}
	store.Update(sc.ID, func(s *scan.Scan) { s.Status, s.Report = scan.StatusCompleted, &scan.Report{Headline: "All good"} })
	if code, _, body := do(t, "GET", srv.URL+"/api/scans/"+sc.ID+"/report", ""); code != http.StatusOK || !strings.Contains(body, "All good") {
		t.Errorf("ready: %d %s", code, body)
	}
	if code, _, _ := do(t, "GET", srv.URL+"/api/scans/nope/report", ""); code != http.StatusNotFound {
		t.Errorf("missing scan: %d", code)
	}
}

func TestHealthzAndUI(t *testing.T) {
	srv, _ := newServer(t)
	if code, _, body := do(t, "GET", srv.URL+"/healthz", ""); code != http.StatusOK || body != "ok" {
		t.Errorf("healthz: %d %q", code, body)
	}
	if code, hdr, body := do(t, "GET", srv.URL+"/", ""); code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") || !strings.Contains(body, "Repo Security Review") {
		t.Errorf("ui: %d %s", code, hdr.Get("Content-Type"))
	}
}

func TestWriteHelpers(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusTeapot, "nope")
	if w.Code != http.StatusTeapot || w.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(w.Body.String()) != `{"error":"nope"}` {
		t.Errorf("writeError: %d %q", w.Code, w.Body.String())
	}
}
