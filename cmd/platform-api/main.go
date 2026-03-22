// Package main is the entry point for the SCADA platform REST API server.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/api"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/jobs"
	"github.com/otnation/platform/internal/store"
)

func main() {
	// Pretty console logger for development.
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Logger()

	// Determine config file path: CONFIG_FILE env var takes priority,
	// then the first CLI argument, then fall back to "config.yaml".
	cfgPath := os.Getenv("CONFIG_FILE")
	if cfgPath == "" && len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	var cfg config.Config
	if cfgPath != "" {
		var err error
		cfg, err = config.LoadFromFile(cfgPath)
		if err != nil {
			log.Fatal().Err(err).Str("path", cfgPath).Msg("failed to load config file")
		}
		log.Info().Str("path", cfgPath).Msg("loaded config file")
	} else {
		cfg = config.Defaults()
		log.Info().Msg("no config file specified — using defaults")
	}

	log.Info().Str("addr", cfg.Addr()).Msg("SCADA platform starting")

	// Root context, cancelled on shutdown signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL.
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.DSN)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse database DSN")
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create database pool")
	}
	defer pool.Close()

	// Verify connectivity.
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	if err := pool.Ping(pingCtx); err != nil {
		log.Warn().Err(err).Msg("database ping failed — continuing anyway")
	} else {
		log.Info().Msg("database connection established")
	}

	// Build store and router.
	st := store.New(pool)
	router := api.NewRouter(st, &cfg)

	// Start background worker pool.
	worker := jobs.New(st, &cfg, cfg.Scanner.Concurrency)
	go worker.Start(ctx)

	srv := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background.
	go func() {
		log.Info().Str("addr", cfg.Addr()).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for termination signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Info().Str("signal", sig.String()).Msg("shutdown signal received")

	// Graceful shutdown with a timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server forced to shutdown")
	} else {
		log.Info().Msg("HTTP server shut down cleanly")
	}
}
