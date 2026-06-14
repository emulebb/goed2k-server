package ed2ksrv

import "testing"

func TestIsHTTPMethodStart(t *testing.T) {
	for _, b := range []byte("GPHODTC") { // first bytes of GET/POST/HEAD/OPTIONS/DELETE/TRACE/CONNECT
		if !isHTTPMethodStart(b) {
			t.Fatalf("0x%02x (%c) should be detected as an HTTP method start", b, b)
		}
	}
	// ED2K protocol bytes and other values must not be treated as HTTP.
	for _, b := range []byte{0xE3, 0xD4, 0xC5, 0x01, 'X', 'A'} {
		if isHTTPMethodStart(b) {
			t.Fatalf("0x%02x should NOT be treated as an HTTP method start", b)
		}
	}
}
