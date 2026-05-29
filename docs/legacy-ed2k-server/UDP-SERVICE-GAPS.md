# UDP Service Gaps

## Current Go Behavior

The Go server currently implements UDP global server status request and response. Other UDP ED2K operations are intentionally not implemented yet.

Important current file:

- `ed2ksrv/server_udp.go`

## LegacyED2KServer Behavior

LegacyED2KServer treated UDP as a parallel service with its own dispatcher, queues, limits, and port layout. It handled:

- Global server status requests and replies.
- UDP ping replies.
- UDP search requests in multiple opcode variants.
- UDP source lookup requests in legacy and newer forms.
- UDP server-list replies.
- UDP callback requests.
- Extended server pings.
- Obfuscated UDP port variants.
- Dedicated UDP search worker queues.
- Datagram-size-aware response flushing.

UDP was not just a stateless status endpoint. It was a high-volume search and source lookup path with separate abuse controls.

## Gaps

1. UDP search is missing.
2. UDP source lookup is missing.
3. UDP callback request handling is missing.
4. UDP server-list response is missing.
5. UDP ping and extended ping behavior are incomplete.
6. UDP queue pressure and worker isolation are not modeled.
7. Obfuscated UDP port behavior is not specified.
8. Datagram size management is missing outside status replies.

## Proposed Go Design

### Dispatcher

Create a UDP dispatcher with strict packet validation:

```go
type UDPDispatcher struct {
    SearchQueue chan UDPSearchJob
    Sources     SourceSelector
    Searcher    SearchService
    Peers       ServerListService
    Limiter     UDPLimiter
}
```

Dispatch should be table-driven by protocol and opcode, with unsupported opcodes counted and ignored.

### Search Queue

UDP search should enqueue work instead of running expensive queries directly on the read loop:

```go
type UDPSearchJob struct {
    Addr      netip.AddrPort
    PacketID  uint64
    Query     SearchNode
    Received  time.Time
}
```

Queue behavior:

- Drop when queue is full.
- Apply per-IP rate limits before enqueue.
- Apply maximum AST depth and broad-search policy before enqueue.
- Return no response for malformed or dropped requests unless compatibility requires an empty answer.

### Source Lookup

UDP source lookup should support both known request forms:

- Single or multiple file hashes, depending on opcode.
- Legacy and newer response packet layouts.
- Obfuscated response variant when requested and enabled.

Response builder rules:

- Keep datagrams below `max_udp_payload_bytes`.
- Flush the current datagram before adding an item that would exceed the limit.
- Never split a single source record across datagrams.
- Validate that the request has enough remaining bytes before reading a 16-byte hash.

### Server List and Ping

Server-list responses should use the shared server peer store described in [Server List and Peering Gaps](SERVER-LIST-AND-PEERING-GAPS.md). UDP ping replies should expose the same counters as TCP status where the protocol allows it.

### Configuration

```json
{
  "udp": {
    "enabled": true,
    "status_enabled": true,
    "search_enabled": true,
    "sources_enabled": true,
    "server_list_enabled": false,
    "callback_enabled": true,
    "max_payload_bytes": 1300,
    "search_workers": 4,
    "search_queue_size": 1024,
    "per_ip_packets_per_second": 20
  }
}
```

## Security Requirements

- Validate full payload length before every fixed-size read.
- Add malformed packet counters by opcode.
- Bound queue memory and worker count.
- Treat UDP sender address as unauthenticated.
- Avoid reflection amplification: replies should have a configurable maximum response-to-request byte ratio.
- Default server-list over UDP to disabled until peering policy is configured.

## Tests

- UDP status remains backward compatible.
- UDP search request returns the same logical results as TCP within UDP limits.
- UDP source request with multiple hashes returns bounded datagrams.
- Short source request is ignored without panic.
- Queue-full behavior drops and counts jobs.
- Per-IP limiter rejects bursts.
- Unsupported opcodes are counted and ignored.