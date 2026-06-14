package ed2ksrv

import "testing"

func TestOrderAndCapSourcesPutsHighIDFirst(t *testing.T) {
	var highID2 uint32 = 0xD2A801D2 // HighID whose int32 form is negative
	low1 := foundSourceEntry{ClientID: 1234}        // LowID (< 0x1000000)
	high1 := foundSourceEntry{ClientID: 0x0A0B0C0D} // HighID
	low2 := foundSourceEntry{ClientID: 5678}        // LowID
	high2 := foundSourceEntry{ClientID: int32(highID2)}

	out := orderAndCapSources([]foundSourceEntry{low1, high1, low2, high2}, 255)

	if len(out) != 4 {
		t.Fatalf("len = %d, want 4", len(out))
	}
	for i := 0; i < 2; i++ {
		if uint32(out[i].ClientID) < 0x1000000 {
			t.Fatalf("position %d is a LowID, expected HighID first: %v", i, out)
		}
	}
	// Stable order preserved within each class.
	if out[0].ClientID != high1.ClientID || out[1].ClientID != high2.ClientID {
		t.Fatalf("HighID order not stable: %v", out)
	}
	if out[2].ClientID != low1.ClientID || out[3].ClientID != low2.ClientID {
		t.Fatalf("LowID order not stable: %v", out)
	}
}

func TestOrderAndCapSourcesDeduplicates(t *testing.T) {
	dup := foundSourceEntry{ClientID: 0x0A0B0C0D, Port: 4662}
	other := foundSourceEntry{ClientID: 0x0A0B0C0D, Port: 4663} // same ID, different port
	out := orderAndCapSources([]foundSourceEntry{dup, dup, other, dup}, 255)
	if len(out) != 2 {
		t.Fatalf("dedup -> len %d, want 2 (%v)", len(out), out)
	}
}

func TestOrderAndCapSourcesCaps(t *testing.T) {
	sources := make([]foundSourceEntry, 300)
	for i := range sources {
		sources[i] = foundSourceEntry{ClientID: int32(0x01000000 + i)}
	}
	if got := orderAndCapSources(sources, 10); len(got) != 10 {
		t.Fatalf("cap 10 -> len %d", len(got))
	}
	if got := orderAndCapSources(sources, 0); len(got) != 255 {
		t.Fatalf("cap 0 should fall back to 255, got %d", len(got))
	}
}
