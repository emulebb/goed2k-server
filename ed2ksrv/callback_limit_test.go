package ed2ksrv

import (
	"io"
	"log/slog"
	"testing"
)

func TestCallbackLimiterDisabledByDefault(t *testing.T) {
	server := newConnLimitTestServer(t, 0) // also leaves callback limiter unset
	if server.callbackLimiter != nil {
		t.Fatal("callbackLimiter should be nil by default")
	}
}

func TestCallbackLimiterEnabledRejectsBursts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdminListenAddress = ""
	cfg.CatalogPath = "../testdata/catalog.json"
	cfg.MaxCallbacksPerIPPerSecond = 2
	catalog, err := LoadCatalog(cfg.CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	server, err := NewServer(cfg, catalog, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if server.callbackLimiter == nil {
		t.Fatal("callbackLimiter should be set when MaxCallbacksPerIPPerSecond > 0")
	}
	allowed := 0
	for i := 0; i < 8; i++ {
		if server.callbackLimiter.allow("203.0.113.7") {
			allowed++
		}
	}
	if allowed == 0 || allowed > 2 {
		t.Fatalf("callback limiter allowed %d of 8, want 1..2", allowed)
	}
}
