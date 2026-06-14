package ed2ksrv

import (
	"net"
	"testing"
)

func TestBuildServerListBodyEncodesSingleIPv4Entry(t *testing.T) {
	body := buildServerListBody(net.ParseIP("192.168.1.210"), 4751, nil)
	want := []byte{1, 192, 168, 1, 210, 0x8f, 0x12} // count=1, IP, port 4751 little-endian
	if len(body) != len(want) {
		t.Fatalf("body length = %d, want %d", len(body), len(want))
	}
	for i := range want {
		if body[i] != want[i] {
			t.Fatalf("body[%d] = 0x%02x, want 0x%02x (full %v)", i, body[i], want[i], body)
		}
	}
}

func TestBuildServerListBodyIncludesPeers(t *testing.T) {
	body := buildServerListBody(net.ParseIP("192.168.1.210"), 4751, []string{"203.0.113.5:4661", "bad", "198.51.100.9:5000"})
	if body[0] != 3 { // self + 2 valid peers ("bad" is skipped)
		t.Fatalf("count = %d, want 3 (body %v)", body[0], body)
	}
	if len(body) != 1+3*6 {
		t.Fatalf("body length = %d, want %d", len(body), 1+3*6)
	}
	// Second entry (first peer) is 203.0.113.5:4661.
	if body[7] != 203 || body[8] != 0 || body[9] != 113 || body[10] != 5 {
		t.Fatalf("peer IP wrong: %v", body[7:11])
	}
}

func TestBuildServerListBodyRejectsNonIPv4(t *testing.T) {
	if body := buildServerListBody(net.ParseIP("2001:db8::1"), 4751, nil); body != nil {
		t.Fatalf("expected nil body for IPv6 address, got %v", body)
	}
}
