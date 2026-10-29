package scan

import "testing"

func TestSeverityRank(t *testing.T) {
	order := []Severity{Unknown, Low, Medium, High, Critical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%s.Rank() = %d, want > %s.Rank() = %d", order[i], order[i].Rank(), order[i-1], order[i-1].Rank())
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Error("unknown severity strings must rank 0")
	}
}
