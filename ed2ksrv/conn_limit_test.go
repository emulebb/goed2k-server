package ed2ksrv

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func newConnLimitTestServer(t *testing.T, connsPerSec int) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AdminListenAddress = ""
	cfg.CatalogPath = filepath.Join("..", "testdata", "catalog.json")
	cfg.MaxConnsPerIPPerSecond = connsPerSec
	catalog, err := LoadCatalog(cfg.CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	server, err := NewServer(cfg, catalog, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func TestConnLimiterDisabledByDefault(t *testing.T) {
	server := newConnLimitTestServer(t, 0)
	if server.connLimiter != nil {
		t.Fatal("connLimiter should be nil when MaxConnsPerIPPerSecond is 0")
	}
}

func TestConnLimiterEnabledAndRejectsBursts(t *testing.T) {
	server := newConnLimitTestServer(t, 3)
	if server.connLimiter == nil {
		t.Fatal("connLimiter should be set when MaxConnsPerIPPerSecond > 0")
	}
	allowed := 0
	for i := 0; i < 10; i++ {
		if server.connLimiter.allow("198.51.100.42") {
			allowed++
		}
	}
	if allowed == 0 || allowed > 3 {
		t.Fatalf("conn limiter allowed %d of 10 bursts, want 1..3", allowed)
	}
}
