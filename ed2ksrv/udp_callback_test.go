package ed2ksrv

import (
	"encoding/binary"
	"net"
	"testing"
)

func udpCallbackBody(ip string, port uint16, target int32) []byte {
	b := make([]byte, 10)
	copy(b[0:4], net.ParseIP(ip).To4())
	binary.LittleEndian.PutUint16(b[4:6], port)
	binary.LittleEndian.PutUint32(b[6:10], uint32(target))
	return b
}

func TestParseUDPCallback(t *testing.T) {
	if _, ok := parseUDPCallback([]byte{1, 2, 3}); ok {
		t.Fatal("short body should not parse")
	}
	cb, ok := parseUDPCallback(udpCallbackBody("192.0.2.5", 4662, 0x00ABCDEF))
	if !ok {
		t.Fatal("valid body failed to parse")
	}
	if cb.requesterPort != 4662 || cb.targetID != 0x00ABCDEF {
		t.Fatalf("parsed fields wrong: %+v", cb)
	}
}

func TestHandleUDPCallbackRejectsSpoofedSourceIP(t *testing.T) {
	server := newConnLimitTestServer(t, 0)
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5000}
	// Body claims a different requester IP than the datagram source.
	if server.handleUDPCallback(addr, udpCallbackBody("192.0.2.5", 4662, 1234)) {
		t.Fatal("spoofed-source callback should be rejected (false)")
	}
}

func TestHandleUDPCallbackUnknownTargetIsIgnored(t *testing.T) {
	server := newConnLimitTestServer(t, 0)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 5000}
	// Matching source IP, but no connected client with that LowID.
	if !server.handleUDPCallback(addr, udpCallbackBody("192.0.2.5", 4662, 999999)) {
		t.Fatal("unknown-target callback should be accepted-and-ignored (true)")
	}
}
