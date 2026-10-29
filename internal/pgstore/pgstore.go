// Package pgstore saves scans in Postgres so reports survive restarts. Each
// scan is one row with the full scan as JSONB; the in-memory scan.Store stays
// the fast path for reads and progress polling.
package pgstore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ox_home_assignment/internal/scan"
)

const schema = `CREATE TABLE IF NOT EXISTS scans (
	id         text PRIMARY KEY,
	repo_url   text NOT NULL,
	status     text NOT NULL,
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	data       jsonb NOT NULL
)`

type DB struct{ pool *pgxpool.Pool }

// Open connects to Postgres and creates the scans table if it doesn't exist.
func Open(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool: pool}, nil
}

func (d *DB) Close() { d.pool.Close() }

// Save inserts or replaces a scan. A write older than the stored row is
// ignored, so out-of-order saves can't roll a scan back.
func (d *DB) Save(ctx context.Context, sc scan.Scan) error {
	data, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx, `
		INSERT INTO scans (id, repo_url, status, created_at, updated_at, data)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE
			SET status = EXCLUDED.status, updated_at = EXCLUDED.updated_at, data = EXCLUDED.data
			WHERE scans.updated_at <= EXCLUDED.updated_at`,
		sc.ID, sc.RepoURL, string(sc.Status), sc.CreatedAt, sc.UpdatedAt, data)
	return err
}

// Load returns one scan; ok is false if it doesn't exist.
func (d *DB) Load(ctx context.Context, id string) (sc scan.Scan, ok bool, err error) {
	var data []byte
	err = d.pool.QueryRow(ctx, `SELECT data FROM scans WHERE id = $1`, id).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return scan.Scan{}, false, nil
	}
	if err != nil {
		return scan.Scan{}, false, err
	}
	return sc, true, json.Unmarshal(data, &sc)
}

// Recent returns the newest n scans, newest first.
func (d *DB) Recent(ctx context.Context, n int) ([]scan.Scan, error) {
	rows, err := d.pool.Query(ctx, `SELECT data FROM scans ORDER BY created_at DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	blobs, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		return nil, err
	}
	out := make([]scan.Scan, len(blobs))
	for i, b := range blobs {
		if err := json.Unmarshal(b, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}
