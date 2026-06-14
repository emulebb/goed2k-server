package ed2ksrv

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"net"
	"testing"

	"github.com/monkeyWie/goed2k/protocol"
)

func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func TestInflatePackedFrameRoundTrip(t *testing.T) {
	original := bytes.Repeat([]byte("ubuntu-search-payload"), 50)
	out, err := inflatePackedFrame(zlibCompress(t, original))
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatal("inflated payload does not match original")
	}
}

func TestInflatePackedFrameRejectsGarbage(t *testing.T) {
	if _, err := inflatePackedFrame([]byte{0x00, 0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error for non-zlib data")
	}
}

func TestMaybePackFrameCompressesLargeFramesAndRoundTrips(t *testing.T) {
	// Build a plain ED2K frame with a large, compressible body.
	body := bytes.Repeat([]byte("search-result-entry"), 64)
	raw := make([]byte, protocol.PacketHeaderSize+len(body))
	raw[0] = protocol.EdonkeyHeader
	binary.LittleEndian.PutUint32(raw[1:5], uint32(len(body)+1))
	raw[5] = 0x33 // OP_SEARCHRESULT
	copy(raw[protocol.PacketHeaderSize:], body)

	wire := maybePackFrame(raw)
	if wire[0] != protocol.PackedProt {
		t.Fatalf("frame was not packed: proto=0x%02x", wire[0])
	}
	if len(wire) >= len(raw) {
		t.Fatalf("packed frame not smaller: %d >= %d", len(wire), len(raw))
	}
	if wire[5] != 0x33 {
		t.Fatalf("opcode not preserved: 0x%02x", wire[5])
	}
	inflated, err := inflatePackedFrame(wire[protocol.PacketHeaderSize:])
	if err != nil {
		t.Fatalf("inflate packed wire: %v", err)
	}
	if !bytes.Equal(inflated, body) {
		t.Fatal("round-trip body mismatch")
	}
}

func TestMaybePackFrameLeavesSmallFramesUnchanged(t *testing.T) {
	raw := make([]byte, protocol.PacketHeaderSize+8)
	raw[0] = protocol.EdonkeyHeader
	raw[5] = 0x34
	if got := maybePackFrame(raw); &got[0] != &raw[0] {
		t.Fatal("small frame should be returned unchanged (same backing array)")
	}
}

func TestReadFrameInflatesPackedProtocol(t *testing.T) {
	// A search body that the recursive parser accepts (single keyword term).
	term := []byte("ubuntu")
	searchBody := append([]byte{0x01, byte(len(term)), 0x00}, term...)
	compressed := zlibCompress(t, searchBody)

	var header protocol.PacketHeader
	header.ResetWithKey(protocol.PK(protocol.PackedProt, opSearchRequest), int32(len(compressed)+1))
	var frame bytes.Buffer
	if err := header.Put(&frame); err != nil {
		t.Fatalf("header put: %v", err)
	}
	frame.Write(compressed)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(frame.Bytes())
	}()

	gotHeader, body, _, err := readFrame(server)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if gotHeader.Protocol != protocol.EdonkeyHeader {
		t.Fatalf("protocol = 0x%02x, want EdonkeyHeader after inflate", gotHeader.Protocol)
	}
	if gotHeader.Packet != opSearchRequest {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", gotHeader.Packet, opSearchRequest)
	}
	if !bytes.Equal(body, searchBody) {
		t.Fatalf("inflated body mismatch: got % x want % x", body, searchBody)
	}

	// And the inflated body parses as a valid search request.
	if _, err := ParseSearchRequest(body); err != nil {
		t.Fatalf("parse inflated search: %v", err)
	}
}
