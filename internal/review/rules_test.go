package review

import (
	"strings"
	"testing"

	"ox_home_assignment/internal/scan"
)

func findings() []scan.Finding {
	return []scan.Finding{
		{Kind: scan.KindDependency, Severity: scan.Critical, Package: "jest-util", Version: "1.0.0", Ecosystem: "npm", Dev: true, FixedIn: "1.0.5"},
		{Kind: scan.KindDependency, Severity: scan.Medium, Package: "lodash", Version: "4.17.15", Ecosystem: "npm", FixedIn: "4.17.19"},
		{Kind: scan.KindDependency, Severity: scan.High, Package: "lodash", Version: "4.17.15", Ecosystem: "npm", FixedIn: "4.17.21"},
		{Kind: scan.KindSecret, Severity: scan.Low, Location: "test/a.js:1", TestPath: true},
		{Kind: scan.KindSecret, Severity: scan.Critical, Location: "src/config.js:3"},
	}
}

func TestBuildPrioritizes(t *testing.T) {
	r := Build(findings(), 50, 2)

	// A live secret outranks a high CVE; a dev-only critical drops below both.
	order := []string{}
	for _, f := range r.Findings {
		order = append(order, f.ID+":"+f.Location+f.Package)
	}
	if r.Findings[0].Location != "src/config.js:3" || r.Findings[1].Package != "lodash" || r.Findings[1].Severity != scan.High {
		t.Fatalf("unexpected order %v", order)
	}
	if r.RiskLevel != scan.Critical {
		t.Errorf("risk level = %s, want critical (driven by the production secret)", r.RiskLevel)
	}
	if r.Stats.Secrets != 2 || r.Stats.Vulnerabilities != 3 {
		t.Errorf("stats = %+v", r.Stats)
	}

	// One upgrade action per package, targeting the highest fixed version.
	var lodash *scan.Action
	for i, a := range r.NextActions {
		if a.Title == "Upgrade lodash 4.17.15 → 4.17.21+" {
			lodash = &r.NextActions[i]
		}
	}
	if lodash == nil || len(lodash.FindingIDs) != 2 {
		t.Fatalf("missing grouped lodash upgrade; actions = %+v", r.NextActions)
	}
	if r.NextActions[0].Title != "Revoke and rotate the exposed credentials" {
		t.Errorf("first action = %q", r.NextActions[0].Title)
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build(nil, 10, 0)
	if r.RiskLevel != scan.Unknown || r.Headline == "" || len(r.NextActions) != 0 {
		t.Fatalf("unexpected empty report %+v", r)
	}
}

func TestHeadlineCountsShippedCode(t *testing.T) {
	r := Build(findings(), 50, 2)
	// 1 production secret, 2 shipped lodash advisories; the dev-only and test findings are excluded.
	if want := "1 exposed credential and 2 known vulnerabilities in shipped code"; r.Headline != want {
		t.Errorf("headline = %q, want %q", r.Headline, want)
	}
}

func TestMultiVersionActionTitle(t *testing.T) {
	r := Build([]scan.Finding{
		{Kind: scan.KindDependency, Severity: scan.High, Package: "minimist", Version: "0.0.8", Ecosystem: "npm", FixedIn: "0.2.4"},
		{Kind: scan.KindDependency, Severity: scan.High, Package: "minimist", Version: "1.2.5", Ecosystem: "npm", FixedIn: "1.2.6"},
	}, 2, 2)
	a := r.NextActions[0]
	if a.Title != "Upgrade minimist → 1.2.6+" || a.Detail != "Installed: 0.0.8, 1.2.5." {
		t.Errorf("action = %q / %q", a.Title, a.Detail)
	}
}

func TestPriority(t *testing.T) {
	base := scan.Finding{Kind: scan.KindDependency, Severity: scan.High}
	secret := scan.Finding{Kind: scan.KindSecret, Severity: scan.High}
	dev := base
	dev.Dev = true
	testSecret := secret
	testSecret.TestPath = true
	if !(priority(secret) > priority(base) && priority(base) > priority(dev)) {
		t.Errorf("want secret > dependency > dev; got %d, %d, %d", priority(secret), priority(base), priority(dev))
	}
	if priority(testSecret) >= priority(base) {
		t.Error("a secret in a test file must not get the secret bonus")
	}
	crit := scan.Finding{Kind: scan.KindDependency, Severity: scan.Critical}
	if priority(crit) <= priority(secret) {
		t.Error("a critical CVE should outrank a high secret")
	}
}

func TestRiskLevel(t *testing.T) {
	cases := []struct {
		name string
		top  scan.Finding
		want scan.Severity
	}{
		{"shipped critical", scan.Finding{Severity: scan.Critical}, scan.Critical},
		{"dev critical is capped", scan.Finding{Severity: scan.Critical, Dev: true}, scan.Medium},
		{"test high is capped", scan.Finding{Severity: scan.High, TestPath: true}, scan.Medium},
		{"dev low stays low", scan.Finding{Severity: scan.Low, Dev: true}, scan.Low},
		{"unrated becomes low", scan.Finding{Severity: scan.Unknown}, scan.Low},
	}
	for _, c := range cases {
		if got := riskLevel([]scan.Finding{c.top}); got != c.want {
			t.Errorf("%s: riskLevel = %s, want %s", c.name, got, c.want)
		}
	}
	if riskLevel(nil) != scan.Unknown {
		t.Error("no findings should be unknown (clean)")
	}
}

func TestGroupByPackage(t *testing.T) {
	fs := []scan.Finding{
		{ID: "D1", Kind: scan.KindDependency, Severity: scan.Critical, Ecosystem: "npm", Package: "minimist", Version: "0.0.8", FixedIn: "0.2.4", Dev: true},
		{ID: "S1", Kind: scan.KindSecret},
		{ID: "D2", Kind: scan.KindDependency, Severity: scan.High, Ecosystem: "npm", Package: "bson", Version: "1.0.9", FixedIn: "1.1.4"},
		{ID: "D3", Kind: scan.KindDependency, Severity: scan.High, Ecosystem: "npm", Package: "minimist", Version: "1.2.5", FixedIn: "1.2.6"},
		{ID: "D4", Kind: scan.KindDependency, Severity: scan.Low, Ecosystem: "npm", Package: "minimist", Version: "1.2.5"},
	}
	gs := groupByPackage(fs)
	if len(gs) != 2 || gs[0].name != "minimist" || gs[1].name != "bson" {
		t.Fatalf("groups = %+v, want minimist then bson (input order), secrets skipped", gs)
	}
	m := gs[0]
	if strings.Join(m.ids, ",") != "D1,D3,D4" || m.version() != "0.0.8, 1.2.5" || m.fixedIn != "1.2.6" || m.worst != scan.Critical {
		t.Errorf("minimist group = %+v", m)
	}
	if m.dev {
		t.Error("a package is dev-only only if every occurrence is dev")
	}
}

func TestRuleNarrativeNoFix(t *testing.T) {
	r := Build([]scan.Finding{{Kind: scan.KindDependency, Severity: scan.High, Package: "x", Version: "1.0", Ecosystem: "npm"}}, 1, 1)
	a := r.NextActions[0]
	if a.Title != "Replace or mitigate x 1.0" || a.Effort != "moderate" || !strings.Contains(a.Detail, "No fix published") {
		t.Errorf("action = %+v", a)
	}
}

func TestRuleNarrativeOnlyNoise(t *testing.T) {
	r := Build([]scan.Finding{{Kind: scan.KindSecret, Severity: scan.Low, TestPath: true}}, 0, 0)
	if r.Headline != "No issues in shipped code" || !strings.Contains(r.Summary, "Another 1 finding") {
		t.Errorf("headline=%q summary=%q", r.Headline, r.Summary)
	}
	if len(r.NextActions) != 1 || r.NextActions[0].Title != "Confirm the credentials in test files are fake" {
		t.Errorf("actions = %+v", r.NextActions)
	}
}

func TestPlural(t *testing.T) {
	cases := map[string]string{
		plural(1, "finding"):             "1 finding",
		plural(2, "finding"):             "2 findings",
		plural(3, "known vulnerability"): "3 known vulnerabilities",
		plural(2, "key"):                 "2 keys",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestTitleCase(t *testing.T) {
	if titleCase("critical risk") != "Critical risk" || titleCase("") != "" {
		t.Error("titleCase wrong")
	}
}
