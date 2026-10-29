package scanners

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ox_home_assignment/internal/scan"
)

func TestSecretScanner(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	key := "ghp_" + "Zx8Kd2LmQ4pR7sT1vW3yA5bC9eF0gH6jN2kM" // split so this file itself doesn't look like a leak
	write("config/prod.js", "module.exports = { token: '"+key+"' };\n")
	write("test/fixtures/conf.js", "const token = '"+key+"';\n")
	write("src/clean.js", "const answer = 42;\n")

	s, err := NewSecretScanner()
	if err != nil {
		t.Fatal(err)
	}
	fs, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]scan.Severity{}
	for _, f := range fs {
		got[f.Location] = f.Severity
		if f.Kind != scan.KindSecret || !strings.HasPrefix(f.Title, "Exposed ") {
			t.Errorf("bad finding %+v", f)
		}
		if strings.Contains(f.Title+f.Description+f.Location, key) {
			t.Error("the secret value leaked into the finding")
		}
	}
	if len(got) != 2 || got["config/prod.js:1"] != scan.Critical || got["test/fixtures/conf.js:1"] != scan.Low {
		t.Fatalf("want prod=critical, test=low; got %v", got)
	}
}

func TestSecretScannerEmptyDir(t *testing.T) {
	s, err := NewSecretScanner()
	if err != nil {
		t.Fatal(err)
	}
	fs, err := s.Scan(context.Background(), t.TempDir())
	if err != nil || len(fs) != 0 {
		t.Errorf("empty dir: %v, %v", fs, err)
	}
}

func TestSecretTitle(t *testing.T) {
	cases := map[string]string{
		"aws-access-token":  "Exposed AWS access token",
		"generic-api-key":   "Exposed generic API key",
		"github-pat":        "Exposed Github PAT",
		"private-key":       "Exposed private key",
		"slack-webhook-url": "Exposed Slack webhook url",
	}
	for in, want := range cases {
		if got := secretTitle(in); got != want {
			t.Errorf("secretTitle(%q) = %q, want %q", in, got, want)
		}
	}
}
