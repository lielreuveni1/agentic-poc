package scanners

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
)

func TestNormalizeRepoURL(t *testing.T) {
	ok := map[string]string{
		"https://github.com/OWASP/NodeGoat":            "https://github.com/OWASP/NodeGoat",
		"github.com/OWASP/NodeGoat.git":                "https://github.com/OWASP/NodeGoat",
		"https://github.com/golang/go/tree/master/src": "https://github.com/golang/go",
		"git@github.com:owner/repo.git":                "https://github.com/owner/repo",
		"  http://www.github.com/a-b/c.d  ":            "https://github.com/a-b/c.d",
	}
	for in, want := range ok {
		if got, err := NormalizeRepoURL(in); err != nil || got != want {
			t.Errorf("NormalizeRepoURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "github.com/owner", "https://gitlab.com/a/b", "https://evil.com/github.com/a/b", "javascript:alert(1)"} {
		if _, err := NormalizeRepoURL(in); err == nil {
			t.Errorf("NormalizeRepoURL(%q) accepted an invalid URL", in)
		}
	}
}

func TestCloneFailureCleansUp(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // isolate from temp dirs made by other tests
	// Port 1 refuses connections, so this fails fast and offline.
	_, _, err := Clone(context.Background(), "http://127.0.0.1:1/owner/repo", "")
	if err == nil || !strings.Contains(err.Error(), "could not download repository") {
		t.Fatalf("err = %v", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("failed clone left %d temp dirs behind", len(left))
	}
}

func TestFriendlyCloneError(t *testing.T) {
	cases := map[error]string{
		transport.ErrAuthenticationRequired: "not found or private",
		transport.ErrRepositoryNotFound:     "not found or private",
		transport.ErrEmptyRemoteRepository:  "empty",
		context.DeadlineExceeded:            "timed out",
		errors.New("boom"):                  "could not download repository: boom",
	}
	for in, want := range cases {
		if got := friendlyCloneError(in).Error(); !strings.Contains(got, want) {
			t.Errorf("friendlyCloneError(%v) = %q, want it to contain %q", in, got, want)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	yes := []string{"test/a.js", "src/__tests__/x.js", "pkg/foo_test.go", "web/app.spec.ts", "testdata/key.pem", "examples/demo.py", "docs/setup.md", "spec/x.rb"}
	no := []string{"src/config.js", "cmd/main.go", "lib/contest.js", "README.md"}
	for _, p := range yes {
		if !isTestPath(p) {
			t.Errorf("isTestPath(%q) = false", p)
		}
	}
	for _, p := range no {
		if isTestPath(p) {
			t.Errorf("isTestPath(%q) = true", p)
		}
	}
}
