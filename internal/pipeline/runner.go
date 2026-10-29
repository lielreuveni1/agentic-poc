// Package pipeline runs a scan end to end: clone → dependencies + secrets → review,
// reporting each stage's progress to the store.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"ox_home_assignment/internal/review"
	"ox_home_assignment/internal/scan"
	"ox_home_assignment/internal/scanners"
)

const (
	stageClone   = "clone"
	stageDeps    = "dependencies"
	stageSecrets = "secrets"
	stageReview  = "review"
)

// NewStages is the checklist a new scan starts with.
func NewStages() []scan.Stage {
	return []scan.Stage{
		{Name: stageClone, Label: "Downloading repository", Status: scan.StagePending},
		{Name: stageDeps, Label: "Checking dependencies for known vulnerabilities", Status: scan.StagePending},
		{Name: stageSecrets, Label: "Looking for exposed secrets", Status: scan.StagePending},
		{Name: stageReview, Label: "Prioritizing risks", Status: scan.StagePending},
	}
}

type Runner struct {
	Store       *scan.Store
	Secrets     *scanners.SecretScanner
	AI          *review.Claude // nil: rule-based review only
	GitHubToken string
	Timeout     time.Duration
	sem         chan struct{}
}

func New(store *scan.Store, secrets *scanners.SecretScanner, ai *review.Claude, token string, concurrency int, timeout time.Duration) *Runner {
	return &Runner{Store: store, Secrets: secrets, AI: ai, GitHubToken: token, Timeout: timeout, sem: make(chan struct{}, concurrency)}
}

// Start runs the scan in the background; scans beyond the concurrency limit wait in "queued".
func (r *Runner) Start(id string) {
	go func() {
		r.sem <- struct{}{}
		defer func() { <-r.sem }()
		r.run(id)
	}()
}

func (r *Runner) run(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	sc, _ := r.Store.Get(id)
	r.Store.Update(id, func(s *scan.Scan) {
		s.Status = scan.StatusRunning
	})

	// 1. Clone. The only stage whose failure fails the scan.
	r.stage(id, stageClone, scan.StageRunning, "")
	dir, commit, err := scanners.Clone(ctx, sc.RepoURL, r.GitHubToken)
	if err != nil {
		r.stage(id, stageClone, scan.StageFailed, err.Error())
		r.Store.Update(id, func(s *scan.Scan) { s.Status, s.Error = scan.StatusFailed, err.Error() })
		return
	}
	defer os.RemoveAll(dir)
	r.Store.Update(id, func(s *scan.Scan) { s.Commit = commit })
	r.stage(id, stageClone, scan.StageDone, shortSHA(commit))

	// 2+3. Dependencies (network-bound) and secrets (CPU-bound) are independent,
	// so they run in parallel. A failure in either degrades the report instead
	// of failing the scan.
	var (
		deps           scanners.DepResult
		secrets        []scan.Finding
		depErr, secErr error
		wg             sync.WaitGroup
	)
	r.stage(id, stageDeps, scan.StageRunning, "")
	r.stage(id, stageSecrets, scan.StageRunning, "")
	wg.Go(func() { deps, depErr = scanners.Dependencies(dir) })
	wg.Go(func() { secrets, secErr = r.Secrets.Scan(ctx, dir) })
	wg.Wait()

	var findings []scan.Finding
	var notes []string
	if depErr != nil {
		slog.Warn("dependency scan failed", "scan", id, "err", depErr)
		r.stage(id, stageDeps, scan.StageFailed, "dependency check unavailable")
		notes = append(notes, "The dependency check failed, so vulnerable packages are not included in this report.")
	} else {
		findings = append(findings, deps.Findings...)
		r.stage(id, stageDeps, scan.StageDone, fmt.Sprintf("%d packages checked, %d vulnerable", deps.Packages, deps.VulnerablePackages))
	}
	if secErr != nil {
		slog.Warn("secret scan failed", "scan", id, "err", secErr)
		r.stage(id, stageSecrets, scan.StageFailed, "secret scan unavailable")
		notes = append(notes, "The secret scan failed, so exposed credentials are not included in this report.")
	} else {
		findings = append(findings, secrets...)
		r.stage(id, stageSecrets, scan.StageDone, fmt.Sprintf("%d possible secrets", len(secrets)))
	}

	// 4. Review: rule-based baseline, then AI narrative on top when available.
	r.stage(id, stageReview, scan.StageRunning, "")
	report := review.Build(findings, deps.Packages, deps.VulnerablePackages)
	report.Notes = notes
	detail := "rule-based"
	if r.AI != nil {
		if err := r.AI.Review(ctx, sc.RepoURL, report); err != nil {
			slog.Warn("AI review failed, using rule-based review", "scan", id, "err", err)
			report.Notes = append(report.Notes, "AI review was unavailable, so this prioritization is rule-based.")
		} else if report.ReviewedBy != "rules" {
			detail = "AI-assisted"
		}
	}
	r.stage(id, stageReview, scan.StageDone, detail)
	r.Store.Update(id, func(s *scan.Scan) { s.Status, s.Report, s.Progress = scan.StatusCompleted, report, 100 })
}

// stage updates one stage and recomputes progress as the share of finished stages.
func (r *Runner) stage(id, name string, st scan.StageStatus, detail string) {
	r.Store.Update(id, func(s *scan.Scan) {
		finished := 0
		for i := range s.Stages {
			if s.Stages[i].Name == name {
				s.Stages[i].Status, s.Stages[i].Detail = st, detail
			}
			if s.Stages[i].Status == scan.StageDone || s.Stages[i].Status == scan.StageFailed {
				finished++
			}
		}
		s.Progress = finished * 100 / len(s.Stages)
	})
}

func shortSHA(c string) string {
	if len(c) > 7 {
		return "commit " + c[:7]
	}
	return c
}
