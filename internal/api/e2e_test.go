package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ox_home_assignment/internal/pipeline"
	"ox_home_assignment/internal/scan"
	"ox_home_assignment/internal/scanners"
	"ox_home_assignment/web"
)

// TestE2E scans a real, deliberately vulnerable repository through the HTTP API:
// GitHub clone, OSV.dev lookup, gitleaks and the rule-based review. It needs
// network access, so it only runs with E2E=1:
//
//	E2E=1 go test ./internal/api -run E2E -v
func TestE2E(t *testing.T) {
	if os.Getenv("E2E") == "" {
		t.Skip("set E2E=1 to run (needs network)")
	}
	secrets, err := scanners.NewSecretScanner()
	if err != nil {
		t.Fatal(err)
	}
	store := scan.NewStore()
	runner := pipeline.New(store, secrets, nil, os.Getenv("GITHUB_TOKEN"), 1, 5*time.Minute)
	srv := httptest.NewServer(New(store, runner, web.FS).Handler())
	defer srv.Close()

	code, _, body := do(t, "POST", srv.URL+"/api/scans", `{"repo_url":"https://github.com/OWASP/NodeGoat"}`)
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %s", code, body)
	}
	var sc scan.Scan
	json.Unmarshal([]byte(body), &sc)

	// Poll like the UI does, and check progress never goes backwards.
	lastProgress := 0
	deadline := time.Now().Add(5 * time.Minute)
	for sc.Status != scan.StatusCompleted && sc.Status != scan.StatusFailed {
		if time.Now().After(deadline) {
			t.Fatalf("scan did not finish; last state %+v", sc)
		}
		time.Sleep(time.Second)
		_, _, body = do(t, "GET", srv.URL+"/api/scans/"+sc.ID, "")
		sc = scan.Scan{}
		json.Unmarshal([]byte(body), &sc)
		if sc.Progress < lastProgress {
			t.Errorf("progress went backwards: %d -> %d", lastProgress, sc.Progress)
		}
		lastProgress = sc.Progress
	}
	if sc.Status != scan.StatusCompleted {
		t.Fatalf("scan failed: %s", sc.Error)
	}
	for _, st := range sc.Stages {
		if st.Status != scan.StageDone {
			t.Errorf("stage %s = %s (%s)", st.Name, st.Status, st.Detail)
		}
	}
	if sc.Commit == "" || sc.Progress != 100 {
		t.Errorf("commit=%q progress=%d", sc.Commit, sc.Progress)
	}

	// The report endpoint returns the same report.
	code, _, body = do(t, "GET", srv.URL+"/api/scans/"+sc.ID+"/report", "")
	var r scan.Report
	if err := json.Unmarshal([]byte(body), &r); code != http.StatusOK || err != nil {
		t.Fatalf("report: %d %v", code, err)
	}

	// NodeGoat is intentionally insecure: it must have vulnerable npm packages
	// and a committed private key, and the verdict must reflect that.
	if r.Stats.Packages < 100 || r.Stats.Vulnerabilities == 0 {
		t.Errorf("stats = %+v", r.Stats)
	}
	var depFound, keyFound bool
	for _, f := range r.Findings {
		if f.Kind == scan.KindDependency && f.Ecosystem == "npm" && f.FixedIn != "" {
			depFound = true
		}
		if f.Kind == scan.KindSecret && f.Severity == scan.Critical && f.Location == "artifacts/cert/server.key:1" {
			keyFound = true
		}
	}
	if !depFound || !keyFound {
		t.Errorf("expected an npm finding with a fix (%v) and the committed private key (%v)", depFound, keyFound)
	}
	if r.RiskLevel != scan.Critical || r.Headline == "" || len(r.NextActions) == 0 || r.ReviewedBy != "rules" {
		t.Errorf("verdict: level=%s headline=%q actions=%d by=%s", r.RiskLevel, r.Headline, len(r.NextActions), r.ReviewedBy)
	}
	if r.NextActions[0].Title != "Revoke and rotate the exposed credentials" {
		t.Errorf("first action = %q, want the credential rotation", r.NextActions[0].Title)
	}
	t.Logf("%s @ %s: %s (%d findings)", sc.RepoURL, sc.Commit[:7], r.Headline, len(r.Findings))
}
