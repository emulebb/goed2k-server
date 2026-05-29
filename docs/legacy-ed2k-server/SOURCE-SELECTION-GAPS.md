# Source Selection Gaps

## Current Go Behavior

The Go server answers source requests by finding all known endpoints for a file hash and returning up to the protocol cap. It has separate paths for regular and obfuscated source replies, but source choice is simple and mostly stateless.

Important current files:

- `ed2ksrv/server.go`: `handleGetSources`, `sourcesAll`, and source reply builders.
- `ed2ksrv/offerfiles.go`: dynamic file ownership data.
- `ed2ksrv/catalog.go`: static catalog source data.

## LegacyED2KServer Behavior

LegacyED2KServer used source selection as a policy engine. It:

- Distinguished TCP source replies, UDP source replies, and obfuscated source replies.
- Used different "smart source" policies for normal TCP, alternate TCP behavior, UDP, alternate UDP behavior, and obfuscated UDP.
- Avoided repeatedly serving the same sources to the same requester too quickly.
- Considered source freshness, user availability, high ID versus low ID status, ports, client capability, and obfuscation settings.
- Tracked source history so a requester could rotate through available sources across repeated requests.
- Applied delay and queue pressure rules.
- Omitted sources that were not useful for the requester.
- Had separate packet construction for legacy and newer source request forms.

## Gaps

1. Source choice is not personalized per requester.
2. There is no source history or rotation.
3. Stale or disconnected dynamic sources can be returned if state changes race with lookup.
4. Low ID and high ID compatibility rules are incomplete.
5. Obfuscation capability is only partially represented in source replies.
6. UDP source batching is not implemented.
7. Source reply policy is not configurable.

## Proposed Go Design

### Source Model

Use a richer source record:

```go
type SourceRecord struct {
    ClientID       uint32
    UserHash       [16]byte
    IP             netip.Addr
    TCPPort        uint16
    UDPPort        uint16
    ObfuscationPort uint16
    HighID         bool
    SupportsObfuscation bool
    LastSeen       time.Time
    LastOffered    time.Time
    FileHash       [16]byte
}
```

### Request Context

Selection should receive requester context:

```go
type SourceRequestContext struct {
    RequesterID        uint32
    RequesterIP        netip.Addr
    RequesterHighID    bool
    WantsObfuscated    bool
    Transport          SourceTransport
    MaxSources         int
    Now                time.Time
}
```

### Selector

Implement:

```go
type SourceSelector interface {
    SelectSources(ctx SourceRequestContext, hash [16]byte) ([]SourceRecord, SourceSelectionStats)
}
```

Selection order:

1. Load candidate sources by hash.
2. Drop requester self-source unless protocol requires it.
3. Drop disconnected or stale dynamic sources.
4. Drop sources incompatible with requested transport or obfuscation mode.
5. Prefer high ID sources when requester is low ID.
6. Rotate using per-requester source history.
7. Apply configured max source count.
8. Record served source IDs into source history.

### Source History

Maintain a bounded per-client, per-file ring:

```go
type SourceHistoryKey struct {
    RequesterID uint32
    FileHash    [16]byte
}
```

This prevents repeated answers from returning the same first N sources for popular files.

### Configuration

```json
{
  "sources": {
    "max_tcp_sources": 255,
    "max_udp_sources": 255,
    "dynamic_source_ttl_seconds": 900,
    "source_rotation_window_seconds": 1800,
    "prefer_high_id_sources": true,
    "allow_self_source": false,
    "require_obfuscated_source_for_obfuscated_request": false
  }
}
```

## Security Requirements

- Validate request payload length before reading each file hash.
- Reject source requests that carry impossible hash counts.
- Bound UDP source response size before appending a source.
- Never include private/internal static sources unless explicitly configured.
- Do not leak user hashes in reply variants that do not require them.

## Tests

- Repeated requests rotate sources.
- Self-source is excluded by default.
- Stale dynamic source is not returned.
- Low ID requester receives useful high ID sources first.
- Obfuscated source request prefers obfuscation-capable endpoints.
- Source history is bounded.
- UDP source response builder never exceeds configured datagram size.