package ed2ksrv

import (
	"encoding/binary"
	"testing"
)

func TestBuildServerDescResEncodesNameAndDescription(t *testing.T) {
	s := &Server{cfg: Config{ServerName: "goed2k-live", ServerDescription: "parity server"}}
	out := s.buildServerDescRes()

	if len(out) < 2 || out[0] != ed2kUDPHeader || out[1] != udpOpServerDescRes {
		t.Fatalf("bad header: % x", out[:min(2, len(out))])
	}
	body := out[2:]
	nameLen := int(binary.LittleEndian.Uint16(body[0:2]))
	name := string(body[2 : 2+nameLen])
	if name != "goed2k-live" {
		t.Fatalf("name = %q, want goed2k-live", name)
	}
	rest := body[2+nameLen:]
	descLen := int(binary.LittleEndian.Uint16(rest[0:2]))
	desc := string(rest[2 : 2+descLen])
	if desc != "parity server" {
		t.Fatalf("desc = %q, want 'parity server'", desc)
	}
	if 2+nameLen+2+descLen != len(body) {
		t.Fatalf("trailing bytes: bodyLen=%d consumed=%d", len(body), 2+nameLen+2+descLen)
	}
}
