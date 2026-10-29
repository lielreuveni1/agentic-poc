package scanners

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"ox_home_assignment/internal/scan"
)

func init() {
	// osv-scanner logs to stdout by default; keep the server log clean.
	osvscanner.SetLogger(slog.NewTextHandler(io.Discard, nil))
}

// DepResult is the outcome of the dependency scan.
type DepResult struct {
	Findings           []scan.Finding
	Packages           int
	VulnerablePackages int
}

// Dependencies finds known-vulnerable packages in every lockfile/manifest under
// dir using osv-scanner (OSV.dev database). One finding per advisory group.
func Dependencies(dir string) (DepResult, error) {
	res, err := osvscanner.DoScan(osvscanner.ScannerActions{
		DirectoryPaths:  []string{dir},
		Recursive:       true,
		ShowAllPackages: true, // so we can report how many packages were checked
	})
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(err, osvscanner.ErrNoPackagesFound) {
		return DepResult{}, err
	}

	var out DepResult
	seen := map[string]bool{}
	for _, src := range res.Results {
		loc, _ := filepath.Rel(dir, src.Source.Path)
		for _, pv := range src.Packages {
			out.Packages++
			if len(pv.Groups) == 0 {
				continue
			}
			out.VulnerablePackages++
			for _, g := range pv.Groups {
				key := pv.Package.Ecosystem + pv.Package.Name + pv.Package.Version + g.IDs[0]
				if seen[key] {
					continue
				}
				seen[key] = true
				out.Findings = append(out.Findings, depFinding(loc, pv, g))
			}
		}
	}
	return out, nil
}

func depFinding(loc string, pv models.PackageVulns, g models.GroupInfo) scan.Finding {
	pkg := pv.Package
	f := scan.Finding{
		Kind:       scan.KindDependency,
		Location:   loc,
		Package:    pkg.Name,
		Version:    pkg.Version,
		Ecosystem:  pkg.Ecosystem,
		Advisories: slices.Concat(g.IDs, slices.DeleteFunc(slices.Clone(g.Aliases), func(a string) bool { return slices.Contains(g.IDs, a) })),
		Dev:        slices.Contains(pv.DepGroups, "dev"),
		TestPath:   isTestPath(loc),
		Severity:   cvssSeverity(g.MaxSeverity),
	}
	for _, v := range pv.Vulnerabilities {
		if !slices.Contains(g.IDs, v.GetId()) {
			continue
		}
		if f.Title == "" {
			f.Title = v.GetSummary()
			f.Description = truncate(v.GetDetails(), 600)
		}
		if f.Severity == scan.Unknown {
			f.Severity = dbSeverity(v)
		}
		f.FixedIn = maxVersion(pkg.Ecosystem, f.FixedIn, fixedVersion(v, pkg.Ecosystem, pkg.Name, pkg.Version))
		for _, r := range v.GetReferences() {
			if r.GetType() == osvschema.Reference_ADVISORY && len(f.References) < 3 {
				f.References = append(f.References, r.GetUrl())
			}
		}
	}
	if f.Title == "" {
		f.Title = "Known vulnerability " + g.IDs[0]
	}
	// Summaries often end with "in <package>", which the UI already shows.
	f.Title = strings.TrimSuffix(f.Title, " in "+pkg.Name)
	return f
}

func cvssSeverity(score string) scan.Severity {
	s, err := strconv.ParseFloat(score, 64)
	switch {
	case err != nil || s <= 0:
		return scan.Unknown
	case s >= 9:
		return scan.Critical
	case s >= 7:
		return scan.High
	case s >= 4:
		return scan.Medium
	}
	return scan.Low
}

// dbSeverity reads GitHub's "database_specific.severity" label (e.g. "HIGH", "MODERATE").
func dbSeverity(v *osvschema.Vulnerability) scan.Severity {
	switch strings.ToLower(v.GetDatabaseSpecific().GetFields()["severity"].GetStringValue()) {
	case "critical":
		return scan.Critical
	case "high":
		return scan.High
	case "moderate", "medium":
		return scan.Medium
	case "low":
		return scan.Low
	}
	return scan.Unknown
}

// fixedVersion returns the lowest fixed version above the installed one.
func fixedVersion(v *osvschema.Vulnerability, ecosystem, name, current string) string {
	best := ""
	for _, a := range v.GetAffected() {
		if a.GetPackage().GetName() != name {
			continue
		}
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				fx := e.GetFixed()
				if fx == "" || CompareVersions(ecosystem, fx, current) <= 0 {
					continue
				}
				if best == "" || CompareVersions(ecosystem, fx, best) < 0 {
					best = fx
				}
			}
		}
	}
	return best
}

func maxVersion(ecosystem, a, b string) string {
	if a == "" || (b != "" && CompareVersions(ecosystem, b, a) > 0) {
		return b
	}
	return a
}

// CompareVersions orders two versions of a package using osv-scalibr's
// ecosystem-aware parser (npm semver, PyPI, Maven, Debian, ...). Versions it
// can't parse fall back to plain string order.
func CompareVersions(ecosystem, a, b string) int {
	if v, err := semantic.Parse(a, ecosystem); err == nil {
		if c, err := v.CompareStr(b); err == nil {
			return c
		}
	}
	return strings.Compare(a, b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
