package ed2ksrv

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/monkeyWie/goed2k/protocol"
	serverproto "github.com/monkeyWie/goed2k/protocol/server"
)

// Catalog is the concurrent in-memory search index used by the server.
type Catalog struct {
	path  string
	store catalogStore

	mu       sync.RWMutex
	files    []FileRecord
	byHash   map[string]FileRecord
	triIndex map[string][]int // lowercase name trigram -> sorted file indices
}

// FileRecord describes a searchable file and the peers that can serve it.
type FileRecord struct {
	Hash            protocol.Hash `json:"hash"`
	Name            string        `json:"name"`
	Size            int64         `json:"size"`
	FileType        string        `json:"file_type"`
	Extension       string        `json:"extension"`
	MediaCodec      string        `json:"media_codec"`
	MediaLength     int           `json:"media_length"`
	MediaBitrate    int           `json:"media_bitrate"`
	Sources         int           `json:"sources"`
	CompleteSources int           `json:"complete_sources"`
	Endpoints       []SourceEntry `json:"endpoints"`
}

// SourceEntry is a static peer endpoint returned by OP_GETSOURCES.
type SourceEntry struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	ObfuscationOptions uint8  `json:"obfuscation_options,omitempty"`
	UserHash           string `json:"user_hash,omitempty"`
}

type catalogDisk struct {
	Files []FileRecord `json:"files"`
}

// LoadCatalog reads the JSON catalog file from disk.
func LoadCatalog(path string) (*Catalog, error) {
	store := &jsonCatalogStore{path: path}
	files, err := store.Load()
	if err != nil {
		return nil, err
	}
	catalog := &Catalog{path: path, store: store}
	if err := catalog.ReplaceAll(files); err != nil {
		return nil, err
	}
	return catalog, nil
}

// LoadCatalogFromConfig reads the configured catalog backend into memory.
func LoadCatalogFromConfig(cfg Config) (*Catalog, error) {
	store, err := newCatalogStore(cfg)
	if err != nil {
		return nil, err
	}
	files, err := store.Load()
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	catalog := &Catalog{path: cfg.CatalogPath, store: store}
	if err := catalog.ReplaceAll(files); err != nil {
		_ = store.Close()
		return nil, err
	}
	return catalog, nil
}

// NewCatalog creates a runtime catalog from an in-memory record list.
func NewCatalog(path string, files []FileRecord) (*Catalog, error) {
	catalog := &Catalog{path: path, store: &jsonCatalogStore{path: path}}
	if err := catalog.ReplaceAll(files); err != nil {
		return nil, err
	}
	return catalog, nil
}

// Path returns the backing JSON file used for persistence.
func (c *Catalog) Path() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.path
}

// StoreDescription returns a human-readable description of the active backend.
func (c *Catalog) StoreDescription() string {
	if c == nil || c.store == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.Description()
}

// Count returns the number of indexed files.
func (c *Catalog) Count() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.files)
}

// Snapshot returns a copy of the catalog contents for admin APIs.
func (c *Catalog) Snapshot() []FileRecord {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneFiles(c.files)
}

// Get returns a single file record by hash.
func (c *Catalog) Get(hash protocol.Hash) (FileRecord, bool) {
	if c == nil {
		return FileRecord{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	record, ok := c.byHash[hash.String()]
	if !ok {
		return FileRecord{}, false
	}
	record.Endpoints = append([]SourceEntry(nil), record.Endpoints...)
	return record, true
}

// Search applies the decoded ED2K search filters against the catalog. When the
// query has a required keyword it uses the trigram index to narrow candidates
// before the full predicate runs; otherwise it scans all files. Results are
// identical to a full scan (the index only produces a superset of candidates).
func (c *Catalog) Search(query SearchQuery) []serverproto.SharedFileEntry {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	candidates := c.searchCandidatesLocked(query)
	if candidates == nil { // full scan
		results := make([]serverproto.SharedFileEntry, 0, len(c.files))
		for _, record := range c.files {
			if matchesRecord(record, query) {
				results = append(results, makeSharedFileEntry(record))
			}
		}
		return results
	}
	results := make([]serverproto.SharedFileEntry, 0, len(candidates))
	for _, idx := range candidates {
		if matchesRecord(c.files[idx], query) {
			results = append(results, makeSharedFileEntry(c.files[idx]))
		}
	}
	return results
}

// searchCandidatesLocked returns a sorted superset of file indices that can match
// query, using the trigram index, or nil to signal "scan all files". Caller holds
// c.mu (read). Safe: a file whose name contains a required keyword as a substring
// contains all of that keyword's trigrams, so it is always in the intersection.
func (c *Catalog) searchCandidatesLocked(query SearchQuery) []int {
	if !query.summarized || len(c.triIndex) == 0 {
		return nil
	}
	key := ""
	for _, kw := range query.Keywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if len(k) >= 3 && len(k) > len(key) {
			key = k
		}
	}
	if key == "" {
		return nil // no keyword long enough to index on; scan
	}
	grams := uniqueTrigrams(key)
	counts := make(map[int]int, 16)
	for _, g := range grams {
		postings, ok := c.triIndex[g]
		if !ok {
			return []int{} // a required trigram is absent -> no file can match
		}
		for _, idx := range postings {
			counts[idx]++
		}
	}
	candidates := make([]int, 0, len(counts))
	for idx, n := range counts {
		if n == len(grams) {
			candidates = append(candidates, idx)
		}
	}
	sort.Ints(candidates)
	return candidates
}

// rebuildSearchIndexLocked rebuilds the trigram index from c.files. Caller holds c.mu (write).
func (c *Catalog) rebuildSearchIndexLocked() {
	index := make(map[string][]int, len(c.files))
	for idx := range c.files {
		for _, g := range uniqueTrigrams(strings.ToLower(c.files[idx].Name)) {
			index[g] = append(index[g], idx)
		}
	}
	c.triIndex = index
}

// uniqueTrigrams returns the distinct 3-byte substrings of s (already lowercased
// by callers). Matching is byte-substring, consistent with keywordMatchesRecord.
func uniqueTrigrams(s string) []string {
	if len(s) < 3 {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s)-2)
	for i := 0; i+3 <= len(s); i++ {
		g := s[i : i+3]
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// Sources returns all configured peer endpoints for the given file hash.
func (c *Catalog) Sources(hash protocol.Hash) []protocol.Endpoint {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	record, ok := c.byHash[hash.String()]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	out := make([]protocol.Endpoint, 0, len(record.Endpoints))
	for _, source := range record.Endpoints {
		endpoint, err := protocol.EndpointFromString(source.Host, source.Port)
		if err != nil {
			continue
		}
		out = append(out, endpoint)
	}
	return out
}

// Upsert inserts or replaces a file record at runtime.
func (c *Catalog) Upsert(record FileRecord) error {
	if c == nil {
		return fmt.Errorf("catalog is nil")
	}
	normalized, err := normalizeFileRecord(record)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byHash == nil {
		c.byHash = make(map[string]FileRecord)
	}
	key := normalized.Hash.String()
	if _, ok := c.byHash[key]; ok {
		for idx := range c.files {
			if c.files[idx].Hash.Equal(normalized.Hash) {
				c.files[idx] = normalized
				break
			}
		}
	} else {
		c.files = append(c.files, normalized)
	}
	c.byHash[key] = normalized
	c.rebuildSearchIndexLocked()
	return nil
}

// Delete removes a file record by ED2K hash.
func (c *Catalog) Delete(hash protocol.Hash) bool {
	if c == nil {
		return false
	}
	key := hash.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byHash[key]; !ok {
		return false
	}
	delete(c.byHash, key)
	for idx := range c.files {
		if c.files[idx].Hash.Equal(hash) {
			c.files = append(c.files[:idx], c.files[idx+1:]...)
			break
		}
	}
	c.rebuildSearchIndexLocked()
	return true
}

// ReplaceAll resets the catalog contents using the provided records.
func (c *Catalog) ReplaceAll(files []FileRecord) error {
	if c == nil {
		return fmt.Errorf("catalog is nil")
	}
	normalized := make([]FileRecord, 0, len(files))
	byHash := make(map[string]FileRecord, len(files))
	for idx, file := range files {
		record, err := normalizeFileRecord(file)
		if err != nil {
			return fmt.Errorf("files[%d]: %w", idx, err)
		}
		normalized = append(normalized, record)
		byHash[record.Hash.String()] = record
	}
	c.mu.Lock()
	c.files = normalized
	c.byHash = byHash
	c.rebuildSearchIndexLocked()
	c.mu.Unlock()
	return nil
}

// Save persists the current catalog back to its JSON file.
func (c *Catalog) Save() error {
	if c == nil {
		return fmt.Errorf("catalog is nil")
	}
	c.mu.RLock()
	store := c.store
	files := cloneFiles(c.files)
	c.mu.RUnlock()
	if store == nil {
		return fmt.Errorf("catalog store is nil")
	}
	return store.Save(files)
}

// Close releases the underlying persistence backend.
func (c *Catalog) Close() error {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.Close()
}

func normalizeFileRecord(record FileRecord) (FileRecord, error) {
	if record.Hash.IsZero() {
		return FileRecord{}, fmt.Errorf("hash is required")
	}
	record.Name = strings.TrimSpace(record.Name)
	if record.Name == "" {
		return FileRecord{}, fmt.Errorf("name is required")
	}
	if record.Size <= 0 {
		return FileRecord{}, fmt.Errorf("size must be positive")
	}
	for idx, source := range record.Endpoints {
		if _, err := protocol.EndpointFromString(source.Host, source.Port); err != nil {
			return FileRecord{}, fmt.Errorf("endpoints[%d] invalid: %w", idx, err)
		}
	}
	if record.Sources <= 0 {
		record.Sources = len(record.Endpoints)
	}
	if record.CompleteSources <= 0 {
		record.CompleteSources = record.Sources
	}
	if record.FileType != "" {
		record.FileType = strings.TrimSpace(record.FileType)
	}
	if record.Extension != "" {
		record.Extension = strings.TrimSpace(record.Extension)
	}
	if record.MediaCodec != "" {
		record.MediaCodec = strings.TrimSpace(record.MediaCodec)
	}
	return record, nil
}

func cloneFiles(files []FileRecord) []FileRecord {
	out := make([]FileRecord, len(files))
	for idx, file := range files {
		out[idx] = file
		out[idx].Endpoints = append([]SourceEntry(nil), file.Endpoints...)
	}
	return out
}

func matchesRecord(record FileRecord, query SearchQuery) bool {
	return query.match(record)
}

func makeSharedFileEntry(record FileRecord) serverproto.SharedFileEntry {
	entry := serverproto.SharedFileEntry{
		Hash: record.Hash,
		Tags: protocol.TagList{
			protocol.NewStringTag(protocol.FTFilename, record.Name),
			protocol.NewUInt32Tag(protocol.FTFileSize, uint32(record.Size)),
			protocol.NewUInt32Tag(protocol.FTSources, uint32(record.Sources)),
			protocol.NewUInt32Tag(protocol.FTCompleteSources, uint32(record.CompleteSources)),
		},
	}
	if record.Size > 0xffffffff {
		entry.Tags = append(entry.Tags, protocol.NewUInt32Tag(protocol.FTFileSizeHi, uint32(uint64(record.Size)>>32)))
	}
	if record.FileType != "" {
		entry.Tags = append(entry.Tags, protocol.NewStringTag(protocol.FTFileType, record.FileType))
	}
	if record.Extension != "" {
		entry.Tags = append(entry.Tags, protocol.NewStringTag(protocol.FTFileFormat, record.Extension))
	}
	if record.MediaCodec != "" {
		entry.Tags = append(entry.Tags, protocol.NewStringTag(protocol.FTMediaCodec, record.MediaCodec))
	}
	if record.MediaLength > 0 {
		entry.Tags = append(entry.Tags, protocol.NewUInt32Tag(protocol.FTMediaLength, uint32(record.MediaLength)))
	}
	if record.MediaBitrate > 0 {
		entry.Tags = append(entry.Tags, protocol.NewUInt32Tag(protocol.FTMediaBitrate, uint32(record.MediaBitrate)))
	}
	if len(record.Endpoints) > 0 {
		if endpoint, err := protocol.EndpointFromString(record.Endpoints[0].Host, record.Endpoints[0].Port); err == nil {
			entry.ClientID = endpoint.IP()
			entry.Port = uint16(endpoint.Port())
		}
	}
	return entry
}
