// Package jobs implements the background worker pool that processes queued jobs.
package jobs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/analysis"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/discovery"
	"github.com/otnation/platform/internal/dns"
	"github.com/otnation/platform/internal/enrichment"
	"github.com/otnation/platform/internal/scanner"
	"github.com/otnation/platform/internal/shodan"
	"github.com/otnation/platform/internal/store"
)

// JobPayload is the canonical payload for all background jobs.
// Duplicated here to avoid an import cycle with the discovery package.
type JobPayload struct {
	RunID      uuid.UUID `json:"run_id"`
	IdentityID uuid.UUID `json:"identity_id"`
	AssetID    uuid.UUID `json:"asset_id,omitempty"`
	Value      string    `json:"value,omitempty"`
}

// Worker processes background jobs from the jobs table using multiple goroutines.
type Worker struct {
	store       *store.Store
	cfg         *config.Config
	concurrency int
}

// New creates a Worker backed by the given store and config.
func New(st *store.Store, cfg *config.Config, concurrency int) *Worker {
	return &Worker{
		store:       st,
		cfg:         cfg,
		concurrency: concurrency,
	}
}

// Start spawns concurrency goroutines that poll for and process pending jobs.
// It blocks until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	for i := 0; i < w.concurrency; i++ {
		go w.loop(ctx, i)
	}
	// Block until context is done.
	<-ctx.Done()
}

// loop is the per-goroutine job processing loop.
func (w *Worker) loop(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		job, err := w.store.ClaimNextJob(ctx)
		if err != nil {
			// No pending jobs — back off and retry.
			if isNoRows(err) {
				time.Sleep(2 * time.Second)
				continue
			}
			log.Error().Err(err).Int("worker", workerID).Msg("jobs: ClaimNextJob error")
			time.Sleep(2 * time.Second)
			continue
		}

		log.Info().
			Int("worker", workerID).
			Str("job_id", job.ID.String()).
			Str("type", job.Type).
			Int("attempt", job.Attempts).
			Msg("jobs: claimed job")

		var payload JobPayload
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			log.Error().Err(err).Str("job_id", job.ID.String()).Msg("jobs: failed to unmarshal payload")
			_ = w.store.FailJob(ctx, job.ID, "payload unmarshal error: "+err.Error())
			continue
		}

		jobErr := w.dispatch(ctx, job.Type, payload)
		if jobErr != nil {
			log.Error().Err(jobErr).
				Str("job_id", job.ID.String()).
				Str("type", job.Type).
				Msg("jobs: job failed")

			_ = w.store.FailJob(ctx, job.ID, jobErr.Error())

			// Requeue if retries remain.
			if job.Attempts < job.MaxAttempts {
				_ = w.store.RetryJob(ctx, job.ID)
			}
			continue
		}

		if err := w.store.CompleteJob(ctx, job.ID); err != nil {
			log.Error().Err(err).Str("job_id", job.ID.String()).Msg("jobs: CompleteJob error")
		}
	}
}

// dispatch routes a job to the appropriate handler by type.
func (w *Worker) dispatch(ctx context.Context, jobType string, payload JobPayload) error {
	switch jobType {
	case "discovery_run":
		return discovery.RunDiscovery(ctx, w.store, payload.RunID, payload.IdentityID)

	case "dns_resolve":
		return dns.Resolve(ctx, w.store, payload.AssetID, payload.IdentityID, payload.RunID)

	case "ip_enrich":
		return enrichment.EnrichIP(ctx, w.store, payload.AssetID, payload.IdentityID)

	case "scan":
		return scanner.ScanAsset(ctx, w.store, w.cfg, payload.AssetID, payload.IdentityID, payload.RunID)

	case "analyze":
		return analysis.AnalyzeAsset(ctx, w.store, payload.AssetID, payload.IdentityID)

	case "shodan_enrichment":
		if w.cfg.Shodan.APIKey == "" {
			log.Warn().Msg("jobs: shodan_enrichment skipped — no API key configured")
			return nil
		}
		return shodan.New(w.cfg.Shodan.APIKey).EnrichAsset(ctx, w.store, payload.AssetID, payload.IdentityID)

	default:
		log.Warn().Str("type", jobType).Msg("jobs: unknown job type, skipping")
		return nil
	}
}

// isNoRows returns true if err represents a "no rows" condition.
func isNoRows(err error) bool {
	return err != nil && (err == pgx.ErrNoRows || err.Error() == "store.ClaimNextJob scan: "+pgx.ErrNoRows.Error())
}
