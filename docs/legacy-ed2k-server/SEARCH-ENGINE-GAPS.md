# Search Engine Gaps

## Current Go Behavior

The Go server parses recursive-prefix ED2K search expressions, supports boolean operators, supports important numeric and string tags, and evaluates queries by scanning the static catalog plus dynamic files. Pagination is implemented through `SearchMore`.

Important current files:

- `ed2ksrv/protocol.go`: search expression parser.
- `ed2ksrv/server.go`: search dispatch, result collection, and pagination.
- `ed2ksrv/catalog.go`: static catalog.

## LegacyED2KServer Behavior

LegacyED2KServer treated search as an indexed planning problem, not only as packet parsing. It:

- Parsed recursive boolean search nodes with string terms, tagged string terms, 32-bit numeric terms, and 64-bit numeric terms.
- Supported boolean operators including AND, OR, ANDNOT, XOR, and NOTAND.
- Recognized file metadata such as type, extension, codec, length, bitrate, size bounds, source counts, and complete source counts.
- Extracted a mandatory or preferred keyword when possible.
- Optimized the search tree before execution.
- Used keyword indexes to avoid scanning every known file for common requests.
- Had separate TCP and UDP search execution paths.
- Applied request throttles and returned empty result packets for some rejected or unproductive searches.
- Tracked result counts, fake or suspicious results, and timing.
- Varied result packing based on client capability, including compressed replies for clients that support them.

## Gaps

1. Search execution is scan-based and will not scale with large catalogs.
2. Query planning is minimal.
3. Keyword extraction does not drive index selection.
4. Result caps are not separated by TCP, UDP, search-more, and policy.
5. Result packing does not account for zlib-capable clients.
6. Fake or suspicious result policy is not modeled.
7. Query observability lacks before/after optimization traces.

## Proposed Go Design

### Search AST

Keep the current parser shape, but normalize all parsed requests into a stable AST:

```go
type SearchNode interface {
    Match(FileRecord) bool
    Estimate(*SearchIndex) SearchEstimate
}

type TermNode struct {
    Field SearchField
    Op    SearchCompareOp
    Value SearchValue
}

type BoolNode struct {
    Op          SearchBoolOp
    Left, Right SearchNode
}
```

The AST should preserve the original packet semantics while giving the planner a typed view of the query.

### Indexes

Build and maintain:

- Keyword index: normalized token to file IDs.
- Extension index: extension to file IDs.
- Type index: audio, video, archive, image, document, program, collection.
- Hash index: ED2K hash to file ID.
- Size buckets: coarse range index for fast size filters.
- Optional media indexes: codec, bitrate, duration.

Dynamic user offers should update these indexes incrementally.

### Planner

Create a planner that:

1. Extracts the most selective positive term.
2. Uses the smallest candidate set as the base.
3. Applies remaining filters in-memory.
4. Short-circuits impossible branches.
5. Refuses or degrades very broad negative-only searches.

Planner output:

```go
type SearchPlan struct {
    BaseIndex     string
    CandidateIDs  []FileID
    Residual      SearchNode
    EstimatedCost int
    Broad         bool
}
```

### Result Policy

Separate limits:

- `max_tcp_search_results`
- `max_udp_search_results`
- `max_search_more_results`
- `max_search_cpu_millis`
- `max_broad_searches_per_client`

Search-more should use a server-side cursor or stable query token, not only a simple offset, so concurrent catalog updates do not create duplicates or skipped rows.

### Response Packing

If the client advertises zlib support and the result set is large enough, responses should be eligible for compressed packed frames. Compression should be bounded by the same frame limits defined for TCP.

## Security Requirements

- Reject malformed recursive trees without recursion overflow.
- Add a maximum AST depth and maximum term count.
- Treat broad searches as expensive even if they are syntactically valid.
- Do not allow search-more to become an unbounded cursor leak.
- Normalize strings once and avoid repeated allocation in hot loops.

## Tests

- Boolean operators match existing protocol semantics.
- Tagged string, uint32, and uint64 search terms parse and evaluate correctly.
- Broad negative-only search is throttled.
- Indexed and scan search return the same files for golden cases.
- Dynamic offer add/remove updates indexes.
- Search-more remains stable after unrelated catalog updates.
- UDP and TCP search limits differ as configured.