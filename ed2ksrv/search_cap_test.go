package ed2ksrv

import (
	"testing"

	serverproto "github.com/monkeyWie/goed2k/protocol/server"
)

func TestCapSearchResults(t *testing.T) {
	results := make([]serverproto.SharedFileEntry, 50)
	if got := capSearchResults(results, 10); len(got) != 10 {
		t.Fatalf("cap 10 -> %d, want 10", len(got))
	}
	if got := capSearchResults(results, 0); len(got) != 50 {
		t.Fatalf("cap 0 (unlimited) -> %d, want 50", len(got))
	}
	if got := capSearchResults(results, 100); len(got) != 50 {
		t.Fatalf("cap above count -> %d, want 50", len(got))
	}
}
