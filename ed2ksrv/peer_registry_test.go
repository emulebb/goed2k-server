package ed2ksrv

import (
	"net"
	"testing"
)

func TestNewPeerRegistryParsesValidSkipsInvalid(t *testing.T) {
	r := newPeerRegistry([]string{"203.0.113.5:4661", "bad", "198.51.100.9:5000", "10.0.0.1:99999", "203.0.113.5:4661"})
	// Two valid, distinct peers ("bad" and the bad port skipped; duplicate ignored).
	if r.len() != 2 {
		t.Fatalf("len = %d, want 2", r.len())
	}
	if got := len(r.addrs()); got != 2 {
		t.Fatalf("addrs = %d, want 2", got)
	}
}

func TestPeerRegistryMarkSeenOnlyForKnownPeers(t *testing.T) {
	r := newPeerRegistry([]string{"203.0.113.5:4661"})
	known := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}
	unknown := &net.UDPAddr{IP: net.ParseIP("203.0.113.6"), Port: 4661}
	if !r.markSeen(known) {
		t.Fatal("known peer should be marked seen")
	}
	if r.markSeen(unknown) {
		t.Fatal("unknown source must not be accepted as a peer")
	}
	snap := r.snapshot()
	if len(snap) != 1 || snap[0].LastSeen.IsZero() {
		t.Fatalf("snapshot did not record last-seen: %+v", snap)
	}
}

func TestNilPeerRegistryIsSafe(t *testing.T) {
	var r *peerRegistry
	if r.len() != 0 || r.addrs() != nil || r.markSeen(&net.UDPAddr{}) || r.snapshot() != nil {
		t.Fatal("nil peerRegistry methods should be safe no-ops")
	}
}
