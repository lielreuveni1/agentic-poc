package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"ox_home_assignment/internal/scan"
)

// Needs a real Postgres, so it only runs with TEST_DATABASE_URL set:
//
//	docker compose up -d
//	TEST_DATABASE_URL=postgres://scans:scans@localhost:5432/scans go test ./internal/pgstore
func open(t *testing.T) *DB {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run")
	}
	db, err := Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.pool.Exec(context.Background(), `DELETE FROM scans WHERE id LIKE 'test-%'`)
		db.Close()
	})
	return db
}

func TestSaveLoad(t *testing.T) {
	db, ctx := open(t), context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond) // Postgres stores microseconds
	sc := scan.Scan{ID: "test-1", RepoURL: "https://github.com/o/r", Status: scan.StatusCompleted, CreatedAt: now, UpdatedAt: now,
		Stages: []scan.Stage{{Name: "clone", Status: scan.StageDone}},
		Report: &scan.Report{Headline: "h", Findings: []scan.Finding{{ID: "D1", Package: "bson"}}}}
	if err := db.Save(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.Load(ctx, "test-1")
	if err != nil || !ok || got.RepoURL != sc.RepoURL || got.Report.Findings[0].Package != "bson" || !got.CreatedAt.Equal(now) {
		t.Fatalf("Load = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := db.Load(ctx, "test-missing"); ok || err != nil {
		t.Errorf("missing scan: ok=%v err=%v", ok, err)
	}
}

func TestSaveIgnoresOlderWrites(t *testing.T) {
	db, ctx := open(t), context.Background()
	now := time.Now().UTC()
	newer := scan.Scan{ID: "test-2", Status: scan.StatusCompleted, CreatedAt: now, UpdatedAt: now.Add(time.Second)}
	older := scan.Scan{ID: "test-2", Status: scan.StatusRunning, CreatedAt: now, UpdatedAt: now}
	db.Save(ctx, newer)
	db.Save(ctx, older) // arrives late
	if got, _, _ := db.Load(ctx, "test-2"); got.Status != scan.StatusCompleted {
		t.Errorf("status = %s, an older write rolled the scan back", got.Status)
	}
}

func TestRecent(t *testing.T) {
	db, ctx := open(t), context.Background()
	base := time.Now().UTC().Add(time.Hour) // newer than any other rows
	for i, id := range []string{"test-a", "test-b", "test-c"} {
		ts := base.Add(time.Duration(i) * time.Second)
		db.Save(ctx, scan.Scan{ID: id, Status: scan.StatusCompleted, CreatedAt: ts, UpdatedAt: ts})
	}
	got, err := db.Recent(ctx, 2)
	if err != nil || len(got) != 2 || got[0].ID != "test-c" || got[1].ID != "test-b" {
		t.Fatalf("Recent = %+v, %v; want test-c, test-b", got, err)
	}
}
