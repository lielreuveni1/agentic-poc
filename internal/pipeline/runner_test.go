package pipeline

import (
	"strings"
	"testing"
	"time"

	"ox_home_assignment/internal/scan"
)

func TestNewStages(t *testing.T) {
	st := NewStages()
	want := []string{stageClone, stageDeps, stageSecrets, stageReview}
	if len(st) != len(want) {
		t.Fatalf("got %d stages", len(st))
	}
	for i, s := range st {
		if s.Name != want[i] || s.Status != scan.StagePending || s.Label == "" {
			t.Errorf("stage %d = %+v", i, s)
		}
	}
}

func TestStageUpdatesProgress(t *testing.T) {
	store := scan.NewStore()
	r := New(store, nil, nil, "", 1, time.Second)
	id := store.Create("u", NewStages()).ID

	r.stage(id, stageClone, scan.StageRunning, "")
	if sc, _ := store.Get(id); sc.Progress != 0 {
		t.Errorf("running stage counted as finished: %d", sc.Progress)
	}
	r.stage(id, stageClone, scan.StageDone, "commit abc")
	r.stage(id, stageDeps, scan.StageFailed, "unavailable")
	sc, _ := store.Get(id)
	if sc.Progress != 50 || sc.Stages[0].Detail != "commit abc" || sc.Stages[1].Status != scan.StageFailed {
		t.Errorf("after 2 of 4 stages: %+v", sc)
	}
}

func TestShortSHA(t *testing.T) {
	if got := shortSHA("c5cb68a1234567"); got != "commit c5cb68a" {
		t.Errorf("shortSHA = %q", got)
	}
	if got := shortSHA(""); got != "" {
		t.Errorf("empty commit = %q", got)
	}
}

func TestRunCloneFailureFailsScan(t *testing.T) {
	store := scan.NewStore()
	r := New(store, nil, nil, "", 1, 10*time.Second)
	id := store.Create("http://127.0.0.1:1/owner/repo", NewStages()).ID // refused: fast and offline

	r.run(id)
	sc, _ := store.Get(id)
	if sc.Status != scan.StatusFailed || !strings.Contains(sc.Error, "could not download repository") {
		t.Fatalf("scan = %+v", sc)
	}
	if sc.Stages[0].Status != scan.StageFailed || sc.Stages[1].Status != scan.StagePending || sc.Report != nil {
		t.Errorf("later stages must not run after a failed clone: %+v", sc.Stages)
	}
}

func TestStartWaitsForAFreeSlot(t *testing.T) {
	store := scan.NewStore()
	r := New(store, nil, nil, "", 1, 10*time.Second)
	id := store.Create("http://127.0.0.1:1/owner/repo", NewStages()).ID

	r.sem <- struct{}{} // occupy the only slot
	r.Start(id)
	time.Sleep(50 * time.Millisecond)
	if sc, _ := store.Get(id); sc.Status != scan.StatusQueued {
		t.Fatalf("status = %s, want queued while no slot is free", sc.Status)
	}
	<-r.sem // free it
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sc, _ := store.Get(id); sc.Status == scan.StatusFailed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan never ran after the slot was freed")
}
