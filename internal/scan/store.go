package scan

import (
	"context"
	"crypto/rand"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// DefaultMaxScans bounds memory: beyond it, the oldest finished scans are
// evicted from memory (they stay in the database, if there is one).
const DefaultMaxScans = 500

// Persister saves scans durably (Postgres). It is optional: without one,
// scans live in memory only.
type Persister interface {
	Save(ctx context.Context, sc Scan) error
	Load(ctx context.Context, id string) (Scan, bool, error)
	Recent(ctx context.Context, n int) ([]Scan, error)
}

// Store is a concurrency-safe scan repository. Reads are served from memory;
// with a Persister, every change is also written to it. Callers always get
// copies, so a running pipeline never races with an HTTP handler.
type Store struct {
	mu    sync.RWMutex
	scans map[string]*Scan
	order []string // IDs in creation order, oldest first
	max   int
	db    Persister
}

func NewStore() *Store { return &Store{scans: map[string]*Scan{}, max: DefaultMaxScans} }

func (s *Store) Create(repoURL string, stages []Stage) Scan {
	now := time.Now().UTC()
	sc := &Scan{
		ID:        rand.Text(),
		RepoURL:   repoURL,
		Status:    StatusQueued,
		Stages:    stages,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	s.scans[sc.ID] = sc
	s.order = append(s.order, sc.ID)
	s.evict()
	c, db := sc.copy(), s.db
	s.mu.Unlock()
	save(db, c)
	return c
}

// Persist loads the most recent saved scans into memory and saves every later
// change to db. Scans that were queued or running when the server stopped will
// never finish, so they are marked failed.
func (s *Store) Persist(ctx context.Context, db Persister) error {
	saved, err := db.Recent(ctx, s.max)
	if err != nil {
		return err
	}
	var interrupted []Scan
	s.mu.Lock()
	for _, sc := range slices.Backward(saved) { // oldest first, like s.order
		if sc.Status == StatusQueued || sc.Status == StatusRunning {
			sc.Status, sc.Error, sc.UpdatedAt = StatusFailed, "interrupted by a server restart", time.Now().UTC()
			for i := range sc.Stages {
				if sc.Stages[i].Status == StageRunning {
					sc.Stages[i].Status = StageFailed
				}
			}
			interrupted = append(interrupted, sc)
		}
		s.scans[sc.ID] = &sc
		s.order = append(s.order, sc.ID)
	}
	s.db = db
	s.mu.Unlock()
	for _, sc := range interrupted {
		if err := db.Save(ctx, sc); err != nil {
			return err
		}
	}
	return nil
}

// save writes a scan to db, if there is one. A failed write is logged, not
// returned: the scan keeps running from memory.
func save(db Persister, sc Scan) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.Save(ctx, sc); err != nil {
		slog.Warn("saving scan failed", "scan", sc.ID, "err", err)
	}
}

// evict drops the oldest finished scans while the store is over its limit.
// Queued and running scans are never evicted, so the store can briefly exceed
// the limit if that many scans are in flight. Callers hold the write lock.
func (s *Store) evict() {
	for i := 0; len(s.scans) > s.max && i < len(s.order); {
		if st := s.scans[s.order[i]].Status; st == StatusCompleted || st == StatusFailed {
			delete(s.scans, s.order[i])
			s.order = slices.Delete(s.order, i, i+1)
			continue
		}
		i++
	}
}

// Get returns a scan from memory, or from db if it was evicted from memory.
func (s *Store) Get(id string) (Scan, bool) {
	s.mu.RLock()
	sc, ok := s.scans[id]
	var c Scan
	if ok {
		c = sc.copy()
	}
	db := s.db
	s.mu.RUnlock()
	if ok || db == nil {
		return c, ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, ok, err := db.Load(ctx, id)
	if err != nil {
		slog.Warn("loading scan failed", "scan", id, "err", err)
	}
	return c, ok
}

// List returns all scans newest first, without reports.
func (s *Store) List() []Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Scan, 0, len(s.order))
	for _, id := range slices.Backward(s.order) {
		c := s.scans[id].copy()
		c.Report = nil
		out = append(out, c)
	}
	return out
}

// Update applies fn to the stored scan under the write lock, then saves it.
func (s *Store) Update(id string, fn func(*Scan)) {
	s.mu.Lock()
	sc, ok := s.scans[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	fn(sc)
	sc.UpdatedAt = time.Now().UTC()
	c, db := sc.copy(), s.db
	s.mu.Unlock()
	save(db, c)
}

// copy clones the mutable parts; a Report is never modified after it is set.
func (sc *Scan) copy() Scan {
	c := *sc
	c.Stages = slices.Clone(sc.Stages)
	return c
}
