package scanners

import (
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"

	"ox_home_assignment/internal/scan"
)

func vuln(id, pkg string, fixed ...string) *osvschema.Vulnerability {
	var events []*osvschema.Event
	for _, f := range fixed {
		events = append(events, &osvschema.Event{Introduced: "0"}, &osvschema.Event{Fixed: f})
	}
	return &osvschema.Vulnerability{
		Id:       id,
		Summary:  "Prototype Pollution in " + pkg,
		Details:  "details",
		Affected: []*osvschema.Affected{{Package: &osvschema.Package{Name: pkg}, Ranges: []*osvschema.Range{{Events: events}}}},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/web"},
			{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/advisory"},
		},
	}
}

func TestDependenciesEmptyDir(t *testing.T) {
	res, err := Dependencies(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Packages != 0 || len(res.Findings) != 0 {
		t.Errorf("empty dir produced %+v", res)
	}
}

func TestDepFinding(t *testing.T) {
	pv := models.PackageVulns{
		Package:         models.PackageInfo{Name: "minimist", Version: "1.2.0", Ecosystem: "npm"},
		DepGroups:       []string{"dev"},
		Vulnerabilities: []*osvschema.Vulnerability{vuln("GHSA-1", "minimist", "0.2.4", "1.2.6")},
	}
	g := models.GroupInfo{IDs: []string{"GHSA-1"}, Aliases: []string{"GHSA-1", "CVE-2021-1"}, MaxSeverity: "9.8"}
	f := depFinding("test/package-lock.json", pv, g)

	if f.Kind != scan.KindDependency || f.Severity != scan.Critical || f.Package != "minimist" || f.Version != "1.2.0" {
		t.Errorf("basic fields wrong: %+v", f)
	}
	if f.Title != "Prototype Pollution" {
		t.Errorf("title = %q, want the package name stripped", f.Title)
	}
	if f.FixedIn != "1.2.6" {
		t.Errorf("fixed_in = %q, want 1.2.6 (lowest fix above 1.2.0)", f.FixedIn)
	}
	if strings.Join(f.Advisories, ",") != "GHSA-1,CVE-2021-1" {
		t.Errorf("advisories = %v, want ID first and aliases deduplicated", f.Advisories)
	}
	if !f.Dev || !f.TestPath {
		t.Errorf("dev/test flags not set: %+v", f)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/advisory" {
		t.Errorf("references = %v, want advisory links only", f.References)
	}
}

func TestDepFindingFallbacks(t *testing.T) {
	v := vuln("GHSA-2", "x")
	v.Summary = ""
	v.DatabaseSpecific, _ = structpb.NewStruct(map[string]any{"severity": "MODERATE"})
	pv := models.PackageVulns{Package: models.PackageInfo{Name: "x", Version: "1.0"}, Vulnerabilities: []*osvschema.Vulnerability{v}}
	f := depFinding("go.mod", pv, models.GroupInfo{IDs: []string{"GHSA-2"}})
	if f.Severity != scan.Medium {
		t.Errorf("severity = %s, want medium from database_specific", f.Severity)
	}
	if f.Title != "Known vulnerability GHSA-2" {
		t.Errorf("title = %q", f.Title)
	}
}

func TestCvssSeverity(t *testing.T) {
	cases := map[string]scan.Severity{"9.8": scan.Critical, "9.0": scan.Critical, "7.5": scan.High, "4.0": scan.Medium, "3.9": scan.Low, "0": scan.Unknown, "": scan.Unknown, "n/a": scan.Unknown}
	for in, want := range cases {
		if got := cvssSeverity(in); got != want {
			t.Errorf("cvssSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestDbSeverity(t *testing.T) {
	cases := map[string]scan.Severity{"CRITICAL": scan.Critical, "HIGH": scan.High, "MODERATE": scan.Medium, "medium": scan.Medium, "LOW": scan.Low, "weird": scan.Unknown}
	for in, want := range cases {
		v := &osvschema.Vulnerability{}
		v.DatabaseSpecific, _ = structpb.NewStruct(map[string]any{"severity": in})
		if got := dbSeverity(v); got != want {
			t.Errorf("dbSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if dbSeverity(&osvschema.Vulnerability{}) != scan.Unknown {
		t.Error("missing database_specific should be unknown")
	}
}

func TestFixedVersion(t *testing.T) {
	v := vuln("A", "pkg", "0.2.4", "1.2.6", "2.0.1")
	cases := map[string]string{"0.0.8": "0.2.4", "1.2.0": "1.2.6", "1.9.0": "2.0.1", "3.0.0": ""}
	for current, want := range cases {
		if got := fixedVersion(v, "npm", "pkg", current); got != want {
			t.Errorf("fixedVersion(current=%s) = %q, want %q", current, got, want)
		}
	}
	if got := fixedVersion(v, "npm", "other-pkg", "0.0.1"); got != "" {
		t.Errorf("fixes for another package must be ignored, got %q", got)
	}
}

func TestMaxVersion(t *testing.T) {
	cases := [][3]string{{"", "1.0", "1.0"}, {"1.0", "", "1.0"}, {"1.2", "1.10", "1.10"}, {"2.0", "1.9", "2.0"}}
	for _, c := range cases {
		if got := maxVersion("npm", c[0], c[1]); got != c[2] {
			t.Errorf("maxVersion(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		eco, a, b string
		sign      int
	}{
		{"npm", "1.2.10", "1.2.9", 1},
		{"npm", "1.0.0", "1.0.0-rc.1", 1}, // a release is newer than its pre-release
		{"Go", "v2.0.0", "v1.9.9", 1},
		{"npm", "0.2.4", "1.2.6", -1},
		{"PyPI", "2.0.post1", "2.0", 1}, // PEP 440 post-release
		{"Maven", "1.0", "1.0.0", 0},
		{"unknown-eco", "b", "a", 1}, // unparseable: string order
	}
	for _, c := range cases {
		got := CompareVersions(c.eco, c.a, c.b)
		if (got > 0) != (c.sign > 0) || (got < 0) != (c.sign < 0) {
			t.Errorf("CompareVersions(%s, %q, %q) = %d, want sign %d", c.eco, c.a, c.b, got, c.sign)
		}
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("short strings must be unchanged")
	}
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
}
