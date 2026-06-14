package ed2ksrv

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/monkeyWie/goed2k/protocol"
	serverproto "github.com/monkeyWie/goed2k/protocol/server"
)

// udpTestServer starts a server (with the given catalog files) on an X_LOCAL_IP
// bound TCP listener plus its derived UDP port, returning a client UDP socket
// already targeted at the server's UDP endpoint.
func udpTestServer(t *testing.T, files []FileRecord) (*Server, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AdminListenAddress = ""
	cfg.StorageBackend = storageBackendJSON
	cfg.CatalogPath = "catalog.json"
	cfg.ServerUDP = true

	catalog, err := NewCatalog(cfg.CatalogPath, files)
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	server, err := NewServer(cfg, catalog, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	host := localUDPTestHost()
	listener := listenTCPWithAvailableUDPOffset(t, host, cfg.UDPPortOffset)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { shutdownServer(t, server) })

	tcpAddr := listener.Addr().(*net.TCPAddr)
	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port+4)))
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host), Port: 0})
	if err != nil {
		t.Fatalf("listen udp client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client, udpAddr
}

// readUDPReply sends req once and waits briefly for a datagram, retrying until
// the deadline so the async search worker has time to answer.
func readUDPReply(t *testing.T, client *net.UDPConn, target *net.UDPAddr, req []byte) []byte {
	t.Helper()
	resp := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	first := true
	for time.Now().Before(deadline) {
		if first {
			if _, err := client.WriteToUDP(req, target); err != nil {
				t.Fatalf("write udp: %v", err)
			}
			first = false
		}
		_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, err := client.ReadFromUDP(resp)
		if err == nil {
			return resp[:n]
		}
		first = true // resend on timeout
	}
	return nil
}

func TestUDPSearchReturnsMatchingFiles(t *testing.T) {
	ubuntu := FileRecord{
		Hash:     protocol.MustHashFromString("00112233445566778899AABBCCDDEEFF"),
		Name:     "ubuntu-24.04-desktop-amd64.iso",
		FileType: "Iso",
		Size:     6144000000,
		Sources:  9,
	}
	server, client, target := udpTestServer(t, []FileRecord{ubuntu})

	// Build the search body with the shared encoder (same bytes a TCP client
	// emits), then frame it as OP_GLOBSEARCHREQ2.
	body := &bytes.Buffer{}
	if err := (&serverproto.SearchRequest{Query: "ubuntu"}).Put(body); err != nil {
		t.Fatalf("encode search: %v", err)
	}
	req := append([]byte{ed2kUDPHeader, udpOpGlobSearchReq2}, body.Bytes()...)

	reply := readUDPReply(t, client, target, req)
	if reply == nil {
		t.Fatal("no UDP search reply received")
	}
	entries := parseUDPSearchResults(t, reply)
	if len(entries) == 0 {
		t.Fatal("expected at least one search result entry")
	}
	if entries[0].Hash.String() != ubuntu.Hash.String() {
		t.Fatalf("unexpected result hash: got %s want %s", entries[0].Hash, ubuntu.Hash)
	}

	stats := server.StatsSnapshot()
	if stats.UDPSearchRequests == 0 {
		t.Fatal("UDPSearchRequests counter not incremented")
	}
}

// parseUDPSearchResults decodes back-to-back [0xE3 0x99 SharedFileEntry] blocks.
func parseUDPSearchResults(t *testing.T, datagram []byte) []serverproto.SharedFileEntry {
	t.Helper()
	reader := bytes.NewReader(datagram)
	var out []serverproto.SharedFileEntry
	for reader.Len() >= 2 {
		proto, _ := reader.ReadByte()
		op, _ := reader.ReadByte()
		if proto != ed2kUDPHeader || op != udpOpGlobSearchRes {
			t.Fatalf("unexpected block header proto=0x%02x op=0x%02x", proto, op)
		}
		var entry serverproto.SharedFileEntry
		if err := entry.Get(reader); err != nil {
			t.Fatalf("decode search entry: %v", err)
		}
		out = append(out, entry)
	}
	return out
}

func TestUDPGetSourcesReturnsEndpoints(t *testing.T) {
	hash := protocol.MustHashFromString("AABBCCDDEEFF00112233445566778899")
	file := FileRecord{
		Hash:      hash,
		Name:      "demo-payload.bin",
		Size:      1048576,
		Endpoints: []SourceEntry{{Host: "203.0.113.10", Port: 4662}},
	}
	_, client, target := udpTestServer(t, []FileRecord{file})

	req := append([]byte{ed2kUDPHeader, udpOpGlobGetSources}, hash.Bytes()...)
	reply := readUDPReply(t, client, target, req)
	if reply == nil {
		t.Fatal("no UDP sources reply received")
	}
	if len(reply) < 2 || reply[0] != ed2kUDPHeader || reply[1] != udpOpGlobFoundSources {
		t.Fatalf("unexpected sources reply header: % x", reply[:min(2, len(reply))])
	}
	var found serverproto.FoundFileSources
	if err := found.Get(bytes.NewReader(reply[2:])); err != nil {
		t.Fatalf("decode found sources: %v", err)
	}
	if found.Hash.String() != hash.String() {
		t.Fatalf("sources hash mismatch: got %s want %s", found.Hash, hash)
	}
	if len(found.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(found.Sources))
	}
}

func TestUDPMalformedRequestsAreCountedNotFatal(t *testing.T) {
	server, client, target := udpTestServer(t, nil)

	// Truncated GETSOURCES (no full hash) and an unsupported opcode.
	_, _ = client.WriteToUDP([]byte{ed2kUDPHeader, udpOpGlobGetSources, 0x01, 0x02}, target)
	_, _ = client.WriteToUDP([]byte{ed2kUDPHeader, 0x7f}, target)
	// Give the server a moment to process.
	time.Sleep(150 * time.Millisecond)

	stats := server.StatsSnapshot()
	if stats.UDPMalformed == 0 {
		t.Fatal("expected UDPMalformed to be incremented")
	}
}

func TestUDPLimiterRejectsBursts(t *testing.T) {
	limiter := newUDPLimiter(3)
	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.allow("198.51.100.7") {
			allowed++
		}
	}
	if allowed > 3 {
		t.Fatalf("limiter allowed %d packets, want <= 3", allowed)
	}
	if allowed == 0 {
		t.Fatal("limiter rejected every packet")
	}
}
