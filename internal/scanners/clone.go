// Package scanners wraps the external scanning libraries (go-git, osv-scanner,
// gitleaks) and normalizes their output into scan.Finding.
package scanners

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

var repoRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/.*)?$`)

// NormalizeRepoURL accepts common GitHub URL shapes (with or without scheme,
// .git suffix, /tree/... paths, git@ form) and returns https://github.com/owner/repo.
func NormalizeRepoURL(raw string) (string, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "git@")
	m := repoRe.FindStringSubmatch(raw)
	if m == nil {
		return "", errors.New("enter a GitHub repository URL, e.g. https://github.com/owner/repo")
	}
	return fmt.Sprintf("https://github.com/%s/%s", m[1], m[2]), nil
}

// Clone shallow-clones the default branch into a new temp dir and returns the
// dir and HEAD commit. The .git directory is removed so scanners only see the
// working tree. The caller must os.RemoveAll the dir.
func Clone(ctx context.Context, repoURL, token string) (dir, commit string, err error) {
	dir, err = os.MkdirTemp("", "scan-*")
	if err != nil {
		return "", "", err
	}
	opts := &git.CloneOptions{URL: repoURL + ".git", Depth: 1, SingleBranch: true, Tags: git.NoTags}
	if token != "" {
		opts.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
	}
	repo, err := git.PlainCloneContext(ctx, dir, false, opts)
	if err != nil {
		os.RemoveAll(dir)
		return "", "", friendlyCloneError(err)
	}
	if head, err := repo.Head(); err == nil {
		commit = head.Hash().String()
	}
	_ = os.RemoveAll(filepath.Join(dir, ".git"))
	return dir, commit, nil
}

func friendlyCloneError(err error) error {
	switch {
	case errors.Is(err, transport.ErrAuthenticationRequired), errors.Is(err, transport.ErrRepositoryNotFound):
		return errors.New("repository not found or private (set GITHUB_TOKEN to scan private repositories)")
	case errors.Is(err, transport.ErrEmptyRemoteRepository):
		return errors.New("repository is empty")
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("timed out while downloading the repository")
	}
	return fmt.Errorf("could not download repository: %w", err)
}

// isTestPath reports whether a path looks like tests, fixtures, examples or docs:
// findings there are real but rarely shipped, so they are de-prioritized.
func isTestPath(p string) bool {
	p = "/" + strings.ToLower(filepath.ToSlash(p))
	for _, s := range []string{"/test", "/tests/", "/__tests__/", "/spec/", "/fixture", "/testdata/", "/example", "/sample", "/demo", "/docs/", "_test.", ".test.", ".spec."} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}
