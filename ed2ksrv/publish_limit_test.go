package ed2ksrv

import "testing"

func TestCapOfferedRecordsEnforcesLimit(t *testing.T) {
	records := make([]FileRecord, 5)
	for i := range records {
		records[i].Name = string(rune('a' + i))
	}
	if got := capOfferedRecords(records, 2); len(got) != 2 {
		t.Fatalf("cap 2 -> len %d, want 2", len(got))
	}
	if got := capOfferedRecords(records, 0); len(got) != 5 {
		t.Fatalf("cap 0 (disabled) -> len %d, want 5", len(got))
	}
	if got := capOfferedRecords(records, 10); len(got) != 5 {
		t.Fatalf("cap above count -> len %d, want 5", len(got))
	}
}
