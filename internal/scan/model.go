// Package scan holds the domain model of a repository scan and its in-memory store.
package scan

import "time"

type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

type StageStatus string

const (
	StagePending StageStatus = "pending"
	StageRunning StageStatus = "running"
	StageDone    StageStatus = "done"
	StageFailed  StageStatus = "failed"
)

// Stage is one named step of the pipeline, shown to the user as a checklist item.
type Stage struct {
	Name   string      `json:"name"`
	Label  string      `json:"label"`
	Status StageStatus `json:"status"`
	Detail string      `json:"detail,omitempty"` // e.g. "412 packages, 9 vulnerable"
}

type Scan struct {
	ID        string    `json:"id"`
	RepoURL   string    `json:"repo_url"`
	Commit    string    `json:"commit,omitempty"`
	Status    Status    `json:"status"`
	Progress  int       `json:"progress"` // 0-100
	Stages    []Stage   `json:"stages"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Report    *Report   `json:"report,omitempty"`
}

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Unknown  Severity = "unknown"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

type Kind string

const (
	KindDependency Kind = "dependency"
	KindSecret     Kind = "secret"
)

// Finding is a normalized scanner result. Secret values are never stored.
type Finding struct {
	ID          string   `json:"id"` // short and stable within a report ("D3", "S1"), so the AI can reference it
	Kind        Kind     `json:"kind"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Location    string   `json:"location"` // manifest path, or file:line for secrets
	Package     string   `json:"package,omitempty"`
	Version     string   `json:"version,omitempty"`
	Ecosystem   string   `json:"ecosystem,omitempty"`
	FixedIn     string   `json:"fixed_in,omitempty"`
	Advisories  []string `json:"advisories,omitempty"` // advisory ID first, then aliases (CVE, GHSA)
	Dev         bool     `json:"dev,omitempty"`        // dev-only dependency
	TestPath    bool     `json:"test_path,omitempty"`  // found under test/example/fixture paths
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Report is what the user reads: a verdict, a few prioritized risks, an
// ordered to-do list, and the evidence behind them.
type Report struct {
	RiskLevel   Severity  `json:"risk_level"` // "unknown" means nothing found
	Headline    string    `json:"headline"`
	Summary     string    `json:"summary"`
	TopRisks    []Risk    `json:"top_risks"`
	NextActions []Action  `json:"next_actions"`
	Findings    []Finding `json:"findings"`
	Stats       Stats     `json:"stats"`
	ReviewedBy  string    `json:"reviewed_by"` // model ID, or "rules"
	Notes       []string  `json:"notes,omitempty"`
}

type Risk struct {
	Title      string   `json:"title"`
	Severity   Severity `json:"severity"`
	Why        string   `json:"why"`
	FindingIDs []string `json:"finding_ids"`
}

type Action struct {
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Effort     string   `json:"effort"` // quick | moderate | significant
	FindingIDs []string `json:"finding_ids"`
}

type Stats struct {
	Packages           int              `json:"packages"`
	VulnerablePackages int              `json:"vulnerable_packages"`
	Vulnerabilities    int              `json:"vulnerabilities"`
	Secrets            int              `json:"secrets"`
	BySeverity         map[Severity]int `json:"by_severity"`
}
