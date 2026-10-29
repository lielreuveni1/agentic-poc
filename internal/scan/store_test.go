package scan

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"
)

func stages() []Stage { return []Stage{{Name: "a", Status: StagePending}} }

func TestCreateAndGet(t *testing.T) {
	s := NewStore()
	sc := s.Create("https://github.com/o/r", stages())
	if sc.ID == "" || sc.Status != StatusQueued || sc.RepoURL != "https://github.com/o/r" || sc.CreatedAt.IsZero() {
		t.Fatalf("unexpected new scan %+v", sc)
	}
	got, ok := s.Get(sc.ID)
	if !ok || got.ID != sc.ID {
		t.Fatalf("Get(%q) = %+v, %v", sc.ID, got, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Error("Get of a missing ID returned ok")
	}
	if other := s.Create("https://github.com/o/r", stages()); other.ID == sc.ID {
		t.Error("IDs are not unique")
	}
}

func TestGetReturnsCopy(t *testing.T) {
	s := NewStore()
	sc := s.Create("u", stages())
	got, _ := s.Get(sc.ID)
	got.Stages[0].Status = StageDone // must not leak into the store
	again, _ := s.Get(sc.ID)
	if again.Stages[0].Status != StagePending {
		t.Error("mutating a returned scan changed the stored one")
	}
}

func TestUpdate(t *testing.T) {
	s := NewStore()
	sc := s.Create("u", stages())
	time.Sleep(time.Millisecond)
	s.Update(sc.ID, func(x *Scan) { x.Status = StatusRunning })
	got, _ := s.Get(sc.ID)
	if got.Status != StatusRunning || !got.UpdatedAt.After(sc.UpdatedAt) {
		t.Errorf("update not applied: %+v", got)
	}
	s.Update("missing", func(*Scan) { t.Error("fn called for a missing scan") })
}

func TestListNewestFirstWithoutReports(t *testing.T) {
	s := NewStore()
	first := s.Create("first", stages())
	time.Sleep(time.Millisecond)
	second := s.Create("second", stages())
	s.Update(first.ID, func(x *Scan) { x.Report = &Report{Headline: "h"} })

	list := s.List()
	if len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
		t.Fatalf("wrong order: %+v", list)
	}
	if list[1].Report != nil {
		t.Error("List must not include reports")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore()
	sc := s.Create("u", stages())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.Update(sc.ID, func(x *Scan) { x.Progress++ }) }()
		go func() { defer wg.Done(); s.Get(sc.ID); s.List() }()
	}
	wg.Wait()
	if got, _ := s.Get(sc.ID); got.Progress != 50 {
		t.Errorf("progress = %d, want 50 (lost updates)", got.Progress)
	}
}

func TestEvictsOldestFinishedScans(t *testing.T) {
	s := NewStore()
	s.max = 2
	a := s.Create("a", stages())
	b := s.Create("b", stages())
	s.Update(b.ID, func(x *Scan) { x.Status = StatusCompleted })
	s.Update(a.ID, func(x *Scan) { x.Status = StatusRunning })

	c := s.Create("c", stages()) // over the limit: b is the oldest finished scan
	if _, ok := s.Get(b.ID); ok {
		t.Error("oldest finished scan was not evicted")
	}
	for _, id := range []string{a.ID, c.ID} {
		if _, ok := s.Get(id); !ok {
			t.Errorf("scan %s should be kept", id)
		}
	}
	if l := s.List(); len(l) != 2 || l[0].ID != c.ID || l[1].ID != a.ID {
		t.Errorf("list after eviction = %+v", l)
	}
}

func TestNeverEvictsUnfinishedScans(t *testing.T) {
	s := NewStore()
	s.max = 1
	a := s.Create("a", stages()) // queued
	b := s.Create("b", stages()) // queued
	if _, ok := s.Get(a.ID); !ok {
		t.Error("a queued scan was evicted")
	}
	if len(s.List()) != 2 {
		t.Error("in-flight scans may exceed the limit")
	}
	s.Update(a.ID, func(x *Scan) { x.Status = StatusFailed })
	s.Create("c", stages()) // now a is finished and can go
	if _, ok := s.Get(a.ID); ok {
		t.Error("finished scan was not evicted once over the limit")
	}
	if _, ok := s.Get(b.ID); !ok {
		t.Error("queued scan b was evicted")
	}
}

// fakeDB is an in-memory Persister.
type fakeDB struct {
	mu    sync.Mutex
	scans map[string]Scan
	saves int
}

func newFakeDB(scans ...Scan) *fakeDB {
	db := &fakeDB{scans: map[string]Scan{}}
	for _, sc := range scans {
		db.scans[sc.ID] = sc
	}
	return db
}

func (d *fakeDB) Save(_ context.Context, sc Scan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scans[sc.ID], d.saves = sc, d.saves+1
	return nil
}

func (d *fakeDB) Load(_ context.Context, id string) (Scan, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sc, ok := d.scans[id]
	return sc, ok, nil
}

func (d *fakeDB) Recent(_ context.Context, n int) ([]Scan, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Collect(maps.Values(d.scans))
	slices.SortFunc(out, func(a, b Scan) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out[:min(n, len(out))], nil
}

func TestPersistSavesEveryChange(t *testing.T) {
	db := newFakeDB()
	s := NewStore()
	if err := s.Persist(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	sc := s.Create("u", stages())
	s.Update(sc.ID, func(x *Scan) { x.Status = StatusCompleted })
	if got := db.scans[sc.ID]; got.Status != StatusCompleted || db.saves != 2 {
		t.Errorf("db has %+v after %d saves, want completed after 2", got, db.saves)
	}
}

func TestPersistLoadsScansAndMarksInterrupted(t *testing.T) {
	t0 := time.Now().UTC()
	done := Scan{ID: "done", Status: StatusCompleted, CreatedAt: t0, Report: &Report{Headline: "h"}}
	running := Scan{ID: "running", Status: StatusRunning, CreatedAt: t0.Add(time.Second),
		Stages: []Stage{{Name: "clone", Status: StageDone}, {Name: "deps", Status: StageRunning}}}
	db := newFakeDB(done, running)

	s := NewStore()
	if err := s.Persist(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if l := s.List(); len(l) != 2 || l[0].ID != "running" || l[1].ID != "done" {
		t.Fatalf("loaded list = %+v, want newest first", l)
	}
	if got, _ := s.Get("done"); got.Report == nil || got.Report.Headline != "h" {
		t.Error("completed report not restored")
	}
	got, _ := s.Get("running")
	if got.Status != StatusFailed || got.Error == "" || got.Stages[1].Status != StageFailed || got.Stages[0].Status != StageDone {
		t.Errorf("interrupted scan = %+v", got)
	}
	if db.scans["running"].Status != StatusFailed {
		t.Error("interrupted status was not saved back to the db")
	}
}

func TestGetFallsBackToDB(t *testing.T) {
	old := Scan{ID: "old", Status: StatusCompleted, CreatedAt: time.Now().UTC()}
	db := newFakeDB()
	s := NewStore()
	s.Persist(context.Background(), db)
	db.scans[old.ID] = old // saved but not in memory, e.g. evicted
	if got, ok := s.Get("old"); !ok || got.ID != "old" {
		t.Errorf("Get did not fall back to the db: %+v %v", got, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Error("missing scan reported as found")
	}
}
