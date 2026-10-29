package review

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"ox_home_assignment/internal/scan"
)

// fakeClaude serves canned Messages API responses and records the last request body.
func fakeClaude(t *testing.T, stopReason, text string) (*Claude, *atomic.Int32, *string) {
	t.Helper()
	calls, lastBody := &atomic.Int32{}, new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		*lastBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant", "model": "test-model",
			"stop_reason": stopReason,
			"content":     []map[string]any{{"type": "text", "text": text}},
			"usage":       map[string]any{"input_tokens": 1, "output_tokens": 1},
		})
	}))
	t.Cleanup(srv.Close)
	c := &Claude{client: anthropic.NewClient(option.WithBaseURL(srv.URL), option.WithAPIKey("test"), option.WithMaxRetries(0)), model: "test-model"}
	return c, calls, lastBody
}

const goodReview = `{"risk_level":"high","headline":"Rotate the key first","summary":"s",
 "top_risks":[{"title":"Key","severity":"critical","why":"w","finding_ids":["S1"]}],
 "next_actions":[{"title":"Rotate","detail":"d","effort":"quick","finding_ids":["S1","D99"]}]}`

func TestNewClaudeModel(t *testing.T) {
	if c := NewClaude("key", "claude-opus-5-5"); c.Model() != "claude-opus-5-5" {
		t.Errorf("Model() = %q", c.Model())
	}
}

func TestReviewAppliesAIOutput(t *testing.T) {
	c, calls, body := fakeClaude(t, "end_turn", goodReview)
	r := Build(findings(), 50, 2)
	if err := c.Review(context.Background(), "https://github.com/o/r", r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || r.Headline != "Rotate the key first" || r.ReviewedBy != "test-model" || r.RiskLevel != scan.High {
		t.Fatalf("report not updated: %+v", r)
	}
	if ids := r.NextActions[0].FindingIDs; len(ids) != 1 || ids[0] != "S1" {
		t.Errorf("invented ID kept: %v", ids)
	}
	for _, want := range []string{`"fallbacks":"default"`, `"json_schema"`, `src/config.js:3`} {
		if !strings.Contains(*body, want) {
			t.Errorf("request body missing %s", want)
		}
	}
}

func TestReviewErrorsKeepRules(t *testing.T) {
	cases := map[string][2]string{
		"refusal":  {"refusal", ""},
		"bad JSON": {"end_turn", "not json"},
	}
	for name, c := range cases {
		cl, _, _ := fakeClaude(t, c[0], c[1])
		r := Build(findings(), 50, 2)
		before := r.Headline
		if err := cl.Review(context.Background(), "u", r); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if r.Headline != before || r.ReviewedBy != "rules" {
			t.Errorf("%s: rule-based report was modified", name)
		}
	}
}

func TestReviewSkipsCleanRepo(t *testing.T) {
	c, calls, _ := fakeClaude(t, "end_turn", goodReview)
	if err := c.Review(context.Background(), "u", Build(nil, 3, 0)); err != nil || calls.Load() != 0 {
		t.Errorf("clean repo should not call the API (calls=%d, err=%v)", calls.Load(), err)
	}
}

func TestPromptFindings(t *testing.T) {
	secret := scan.Finding{ID: "S1", Kind: scan.KindSecret, Title: "Exposed key", Location: "a.js:1", Description: "SECRET-CONTEXT"}
	dep := scan.Finding{ID: "D1", Kind: scan.KindDependency, Package: "bson", Version: "1.0", Ecosystem: "npm", FixedIn: "1.1", Advisories: []string{"CVE-1"}, Dev: true, TestPath: true}
	out := promptFindings([]scan.Finding{secret, dep})
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SECRET-CONTEXT") {
		t.Error("descriptions must not be sent to the model")
	}
	if d := out[1]; d.Package != "bson@1.0" || d.FixedIn != "1.1" || !d.Dev || !d.TestPath || d.Advisories[0] != "CVE-1" {
		t.Errorf("dependency entry = %+v", d)
	}
	if !strings.Contains(string(b), `"id":"S1","kind":"secret","severity":"","title":"Exposed key","location":"a.js:1"}`) {
		t.Errorf("secret entry should have no package fields: %s", b)
	}

	many := make([]scan.Finding, 200)
	if got := len(promptFindings(many)); got != 150 {
		t.Errorf("prompt should be capped at 150 findings, got %d", got)
	}
}

func TestApplyDropsUnknownIDs(t *testing.T) {
	r := Build(findings(), 50, 2)
	apply(r, aiReview{
		RiskLevel: "critical",
		Headline:  "h",
		TopRisks: []aiRisk{
			{Title: "real", Severity: "high", FindingIDs: []string{"S1", "X9"}},
			{Title: "invented", Severity: "critical", FindingIDs: []string{"D99"}},
		},
		NextActions: []aiAction{{Title: "do it", FindingIDs: []string{"D1", "nope"}}},
	}, "claude-opus-5-5")

	if len(r.TopRisks) != 1 || r.TopRisks[0].Title != "real" || len(r.TopRisks[0].FindingIDs) != 1 {
		t.Errorf("top risks = %+v", r.TopRisks)
	}
	if got := r.NextActions[0].FindingIDs; len(got) != 1 || got[0] != "D1" {
		t.Errorf("action ids = %v", got)
	}
	if r.ReviewedBy != "claude-opus-5-5" || r.RiskLevel != scan.Critical {
		t.Errorf("reviewed_by=%s risk=%s", r.ReviewedBy, r.RiskLevel)
	}
}

func TestApplyKeepsRulesOnEmptyOutput(t *testing.T) {
	r := Build(findings(), 50, 2)
	before := r.Headline
	apply(r, aiReview{}, "m")
	if r.Headline != before || r.ReviewedBy != "rules" {
		t.Error("empty AI output replaced the rule-based narrative")
	}
}

func TestDevOnlyCriticalCapsVerdict(t *testing.T) {
	r := Build([]scan.Finding{
		{Kind: scan.KindDependency, Severity: scan.Critical, Package: "jest-util", Version: "1.0.0", Dev: true},
		{Kind: scan.KindDependency, Severity: scan.Low, Package: "left-pad", Version: "1.0.0"},
	}, 2, 2)
	if r.RiskLevel != scan.Medium {
		t.Errorf("risk level = %s, want medium (a dev-only critical must not drive it)", r.RiskLevel)
	}
}
