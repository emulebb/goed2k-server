package ed2ksrv

import (
	"fmt"
	"sort"
	"testing"

	"github.com/monkeyWie/goed2k/protocol"
)

// bruteForceSearch matches the pre-index full-scan semantics for cross-checking.
func bruteForceSearch(files []FileRecord, query SearchQuery) []string {
	var out []string
	for _, r := range files {
		if matchesRecord(r, query) {
			out = append(out, r.Hash.String())
		}
	}
	sort.Strings(out)
	return out
}

func indexedSearchHashes(t *testing.T, cat *Catalog, query SearchQuery) []string {
	t.Helper()
	entries := cat.Search(query)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Hash.String())
	}
	sort.Strings(out)
	return out
}

func TestSearchIndexMatchesFullScan(t *testing.T) {
	names := []string{
		"ubuntu-24.04-desktop-amd64.iso",
		"ubuntu-22.04-server-amd64.iso",
		"archlinux-2026.03.01-x86_64.iso",
		"demo-track.flac",
		"holiday-photos-2026.zip",
		"ubuntustudio-24.04.iso",
		"random-archive.tar.gz",
	}
	files := make([]FileRecord, len(names))
	for i, n := range names {
		files[i] = FileRecord{
			Hash: protocol.MustHashFromString(fmt.Sprintf("%032X", i+1)),
			Name: n, Size: int64(1000 + i),
		}
	}
	cat, err := NewCatalog("catalog.json", files)
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}

	// Queries include full tokens, partial substrings, and a non-match — all must
	// agree between the trigram-indexed path and the brute-force scan.
	for _, kw := range []string{"ubuntu", "buntu", "iso", "arch", "flac", "studio", "xyznope", "ar"} {
		query, err := ParseSearchRequest(append([]byte{0x01, byte(len(kw)), 0x00}, []byte(kw)...))
		if err != nil {
			t.Fatalf("parse %q: %v", kw, err)
		}
		want := bruteForceSearch(files, query)
		got := indexedSearchHashes(t, cat, query)
		if fmt.Sprint(want) != fmt.Sprint(got) {
			t.Fatalf("keyword %q: indexed=%v scan=%v", kw, got, want)
		}
	}
}
