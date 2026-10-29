package scanners

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"

	"ox_home_assignment/internal/scan"
)

// SecretScanner detects hard-coded credentials with gitleaks' default rule set.
type SecretScanner struct{ cfg config.Config }

// NewSecretScanner loads the gitleaks config once: loading it goes through a
// global viper instance, so it is not safe to do per scan.
func NewSecretScanner() (*SecretScanner, error) {
	logging.Logger = logging.Logger.Level(zerolog.Disabled)
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	return &SecretScanner{cfg: d.Config}, nil
}

// Scan runs gitleaks over the working tree. Secret values are not kept.
func (s *SecretScanner) Scan(ctx context.Context, dir string) ([]scan.Finding, error) {
	d := detect.NewDetectorContext(ctx, s.cfg)
	d.MaxTargetMegaBytes = 1
	found, err := d.DetectSource(ctx, &sources.Files{
		Config:      &d.Config,
		Path:        dir,
		Sema:        d.Sema,
		MaxFileSize: d.MaxTargetMegaBytes * 1_000_000,
	})
	if err != nil {
		return nil, err
	}
	var out []scan.Finding
	for _, f := range found {
		rel, _ := filepath.Rel(dir, f.File)
		inTest := isTestPath(rel)
		sev := scan.Critical // a working credential is usable by anyone who can read the repo
		if inTest {
			sev = scan.Low
		}
		out = append(out, scan.Finding{
			Kind:        scan.KindSecret,
			Severity:    sev,
			Title:       secretTitle(f.RuleID),
			Location:    fmt.Sprintf("%s:%d", rel, f.StartLine),
			TestPath:    inTest,
			Description: f.Description + " Anyone with read access to the repository (or its history) can use it.",
		})
	}
	return out, nil
}

// secretTitle turns a gitleaks rule ID ("aws-access-token") into "Exposed AWS access token".
func secretTitle(ruleID string) string {
	words := strings.Split(ruleID, "-")
	for i, w := range words {
		switch w {
		case "aws", "gcp", "api", "jwt", "pat", "npm", "ssh", "pgp", "rsa":
			words[i] = strings.ToUpper(w)
		case "github", "gitlab", "slack", "stripe", "twilio", "openai", "anthropic", "google", "azure":
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return "Exposed " + strings.Join(words, " ")
}
