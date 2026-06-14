package ed2ksrv

import (
	"net"
	"testing"
)

func TestParseServerListBody(t *testing.T) {
	// count=2, then 203.0.113.5:4661 and 198.51.100.9:5000.
	body := []byte{
		2,
		203, 0, 113, 5, 0x35, 0x12, // 4661 LE
		198, 51, 100, 9, 0x88, 0x13, // 5000 LE
	}
	addrs := parseServerListBody(body)
	if len(addrs) != 2 {
		t.Fatalf("parsed %d addrs, want 2", len(addrs))
	}
	if addrs[0].String() != "203.0.113.5:4661" || addrs[1].String() != "198.51.100.9:5000" {
		t.Fatalf("parsed addrs wrong: %v %v", addrs[0], addrs[1])
	}
	if got := parseServerListBody([]byte{5, 1, 2}); got != nil && len(got) != 0 {
		t.Fatalf("truncated body should yield no complete entries, got %v", got)
	}
}

func TestPeerRegistryLearnsNewPeers(t *testing.T) {
	r := newPeerRegistry([]string{"203.0.113.5:4661"})
	added := r.add(&net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5000})
	if !added || r.len() != 2 {
		t.Fatalf("expected to learn a new peer; added=%v len=%d", added, r.len())
	}
	// Duplicate and invalid are rejected.
	if r.add(&net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4661}) {
		t.Fatal("duplicate peer should not be added")
	}
	if r.add(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5000}) {
		t.Fatal("non-IPv4 peer should not be added")
	}
}

func TestBuildAndParseUDPServerListRoundTrips(t *testing.T) {
	s := &Server{peers: newPeerRegistry([]string{"203.0.113.5:4661", "198.51.100.9:5000"})}
	reply := s.buildUDPServerListReply()
	if len(reply) < 2 || reply[0] != ed2kUDPHeader || reply[1] != udpOpServerListRes {
		t.Fatalf("bad reply header: % x", reply[:min(2, len(reply))])
	}
	addrs := parseServerListBody(reply[2:])
	if len(addrs) != 2 {
		t.Fatalf("round-trip parsed %d, want 2", len(addrs))
	}
}
