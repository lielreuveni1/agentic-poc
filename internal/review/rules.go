// Package review turns raw findings into a report a non-specialist can act on:
// a verdict, the few risks that matter, and an ordered to-do list.
package review

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"ox_home_assignment/internal/scan"
	"ox_home_assignment/internal/scanners"
)

// Build assigns finding IDs, sorts findings by priority, computes stats and the
// overall risk level, and fills in a rule-based narrative. It never fails, so a
// report always exists even if the AI reviewer is unavailable.
func Build(findings []scan.Finding, packages, vulnerablePackages int) *scan.Report {
	slices.SortStableFunc(findings, func(a, b scan.Finding) int {
		return cmp.Or(
			cmp.Compare(priority(b), priority(a)),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Package, b.Package),
		)
	})
	stats := scan.Stats{Packages: packages, VulnerablePackages: vulnerablePackages, BySeverity: map[scan.Severity]int{}}
	nd, ns := 0, 0
	for i := range findings {
		f := &findings[i]
		if f.Kind == scan.KindSecret {
			ns++
			f.ID = fmt.Sprintf("S%d", ns)
			stats.Secrets++
		} else {
			nd++
			f.ID = fmt.Sprintf("D%d", nd)
			stats.Vulnerabilities++
		}
		stats.BySeverity[f.Severity]++
	}
	r := &scan.Report{Findings: findings, Stats: stats, ReviewedBy: "rules", RiskLevel: riskLevel(findings)}
	ruleNarrative(r)
	return r
}

// priority is severity adjusted for context: secrets are directly usable,
// while dev-only and test-path findings rarely reach production.
func priority(f scan.Finding) int {
	p := f.Severity.Rank() * 10
	if f.Kind == scan.KindSecret && !f.TestPath {
		p += 5
	}
	if f.Dev || f.TestPath {
		p -= 15
	}
	return p
}

// riskLevel is the repo verdict: the severity of the most urgent finding.
func riskLevel(fs []scan.Finding) scan.Severity {
	if len(fs) == 0 {
		return scan.Unknown
	}
	// fs is sorted by priority, so the first finding drives the verdict; a
	// de-prioritized one (dev/test) can't push the repo above "medium".
	top := fs[0]
	if (top.Dev || top.TestPath) && top.Severity.Rank() > scan.Medium.Rank() {
		return scan.Medium
	}
	if top.Severity == scan.Unknown {
		return scan.Low
	}
	return top.Severity
}

// pkgGroup collects all advisories for one package (across the versions
// installed), since upgrading it fixes them together.
type pkgGroup struct {
	name, fixedIn string
	versions      []string
	worst         scan.Severity
	ids           []string
	dev           bool
}

// version lists the installed versions, e.g. "0.0.8, 1.2.5".
func (g *pkgGroup) version() string {
	return strings.Join(g.versions, ", ")
}

// groupByPackage merges dependency findings by package, keeping priority order.
func groupByPackage(fs []scan.Finding) []*pkgGroup {
	var out []*pkgGroup
	idx := map[string]*pkgGroup{}
	for _, f := range fs {
		if f.Kind != scan.KindDependency {
			continue
		}
		key := f.Ecosystem + "/" + f.Package
		g, ok := idx[key]
		if !ok {
			g = &pkgGroup{name: f.Package, worst: f.Severity, dev: true}
			idx[key] = g
			out = append(out, g) // fs is priority-sorted, so groups are too
		}
		g.ids = append(g.ids, f.ID)
		g.dev = g.dev && f.Dev // dev-only if every occurrence is dev-only
		if !slices.Contains(g.versions, f.Version) {
			g.versions = append(g.versions, f.Version)
		}
		if f.FixedIn != "" && (g.fixedIn == "" || scanners.CompareVersions(f.Ecosystem, f.FixedIn, g.fixedIn) > 0) {
			g.fixedIn = f.FixedIn
		}
	}
	return out
}

// ruleNarrative writes the headline, summary, top risks and to-do list without AI.
func ruleNarrative(r *scan.Report) {
	// One pass: split secrets by location, and count what the severity squares
	// show (shipped code) so the headline numbers match them.
	var secrets, testSecrets []string
	shippedVulns, noise := 0, 0
	for _, f := range r.Findings {
		switch {
		case f.Kind == scan.KindSecret && f.TestPath:
			testSecrets = append(testSecrets, f.ID)
		case f.Kind == scan.KindSecret:
			secrets = append(secrets, f.ID)
		case !f.Dev && !f.TestPath:
			shippedVulns++
		}
		if f.Dev || f.TestPath {
			noise++
		}
	}
	groups := groupByPackage(r.Findings)

	if len(r.Findings) == 0 {
		r.Headline = "No known vulnerable dependencies or exposed secrets found"
		r.Summary = fmt.Sprintf("We checked %d packages against the OSV vulnerability database and scanned every file for hard-coded credentials. Nothing needs action right now.", r.Stats.Packages)
		return
	}

	var parts []string
	if len(secrets) > 0 {
		parts = append(parts, plural(len(secrets), "exposed credential"))
	}
	if shippedVulns > 0 {
		parts = append(parts, plural(shippedVulns, "known vulnerability"))
	}
	if len(parts) == 0 {
		r.Headline = "No issues in shipped code"
	} else {
		r.Headline = titleCase(strings.Join(parts, " and ")) + " in shipped code" // the risk level is shown separately
	}
	r.Summary = "Start with the to-do list: it is ordered by urgency."
	if noise > 0 {
		r.Summary += fmt.Sprintf(" Another %s in dev tools or test files come last.", plural(noise, "finding"))
	}

	if len(secrets) > 0 {
		r.TopRisks = append(r.TopRisks, scan.Risk{
			Title:      plural(len(secrets), "hard-coded credential") + " in the code",
			Severity:   scan.Critical,
			Why:        "Anyone who can read the repository can use these credentials, and they stay in git history even after the file is changed.",
			FindingIDs: secrets,
		})
		r.NextActions = append(r.NextActions, scan.Action{
			Title:      "Revoke and rotate the exposed credentials",
			Detail:     "Rotate them at the provider, then load them from env vars or a secret manager. Deleting the line isn't enough: git history keeps it.",
			Effort:     "quick",
			FindingIDs: secrets,
		})
	}
	for _, g := range groups {
		if len(r.TopRisks) >= 5 {
			break
		}
		why := fmt.Sprintf("%s has %s; the worst is %s.", g.name, plural(len(g.ids), "known vulnerability"), g.worst)
		if g.dev {
			why += " It is a dev-only dependency, so it is unlikely to ship to production."
		}
		r.TopRisks = append(r.TopRisks, scan.Risk{
			Title:      fmt.Sprintf("Vulnerable %s (%s)", g.name, g.version()),
			Severity:   g.worst,
			Why:        why,
			FindingIDs: g.ids,
		})
	}
	for _, g := range groups {
		if len(r.NextActions) >= 6 {
			break
		}
		a := scan.Action{Effort: "quick", FindingIDs: g.ids}
		// Keep titles short: list several installed versions in the detail instead.
		from, installed := " "+g.versions[0], ""
		if len(g.versions) > 1 {
			from, installed = "", "Installed: "+g.version()+". "
		}
		if g.fixedIn != "" {
			a.Title = fmt.Sprintf("Upgrade %s%s → %s+", g.name, from, g.fixedIn)
			a.Detail = installed
		} else {
			a.Title = fmt.Sprintf("Replace or mitigate %s%s", g.name, from)
			a.Detail = installed + "No fix published yet. Check whether you use the affected code, or switch packages."
			a.Effort = "moderate"
		}
		if g.dev {
			a.Detail += "Dev-only dependency: not shipped to production."
		}
		a.Detail = strings.TrimSpace(a.Detail)
		r.NextActions = append(r.NextActions, a)
	}
	if len(testSecrets) > 0 {
		r.NextActions = append(r.NextActions, scan.Action{
			Title:      "Confirm the credentials in test files are fake",
			Detail:     "If any of them are real, rotate them like the others.",
			Effort:     "quick",
			FindingIDs: testSecrets,
		})
	}
}

// plural formats a count with a noun: plural(2, "finding") = "2 findings".
func plural(n int, s string) string {
	if n == 1 {
		return "1 " + s
	}
	switch {
	case strings.HasSuffix(s, "y") && !strings.HasSuffix(s, "ey"):
		s = s[:len(s)-1] + "ies"
	default:
		s += "s"
	}
	return fmt.Sprintf("%d %s", n, s)
}

// titleCase upper-cases the first letter.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
