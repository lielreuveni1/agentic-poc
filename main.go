// Command ox_home_assignment runs the AI scan review service: a web UI and
// JSON API for scanning a GitHub repository and reviewing a prioritized report.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"ox_home_assignment/internal/api"
	"ox_home_assignment/internal/pgstore"
	"ox_home_assignment/internal/pipeline"
	"ox_home_assignment/internal/review"
	"ox_home_assignment/internal/scan"
	"ox_home_assignment/internal/scanners"
	"ox_home_assignment/web"
)

func main() {
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address")
	model := flag.String("model", envOr("ANTHROPIC_MODEL", "claude-opus-5-5"), "Claude model for the AI review")
	concurrency := flag.Int("concurrency", 4, "max concurrent scans")
	timeout := flag.Duration("timeout", 5*time.Minute, "per-scan timeout")
	flag.Parse()

	secrets, err := scanners.NewSecretScanner()
	if err != nil {
		slog.Error("loading gitleaks config", "err", err)
		os.Exit(1)
	}
	var ai *review.Claude
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		ai = review.NewClaude(key, *model)
		slog.Info("AI review enabled", "model", *model)
	} else {
		slog.Info("ANTHROPIC_API_KEY not set: using rule-based review")
	}

	store := scan.NewStore()
	if url := os.Getenv("DATABASE_URL"); url != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		db, err := pgstore.Open(ctx, url)
		if err == nil {
			err = store.Persist(ctx, db)
		}
		cancel()
		if err != nil {
			slog.Error("connecting to Postgres", "err", err)
			os.Exit(1)
		}
		defer db.Close()
		slog.Info("scans are saved in Postgres")
	} else {
		slog.Info("DATABASE_URL not set: scans are kept in memory only")
	}
	runner := pipeline.New(store, secrets, ai, os.Getenv("GITHUB_TOKEN"), *concurrency, *timeout)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.New(store, runner, web.FS).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("listening", "url", "http://localhost"+*addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
