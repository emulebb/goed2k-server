# Server List and Peering Gaps

## Current Go Behavior

The Go server accepts the server-list request opcode, but the current handler only sends normal status/message behavior and does not return a real server list. The server is mostly standalone.

Important current file:

- `ed2ksrv/server.go`: `handleGetServerList`

## LegacyED2KServer Behavior

LegacyED2KServer maintained a peer server table and used it for client-facing and server-facing behavior:

- Loaded server entries from a `server.met` style file.
- Added and updated server records learned from peers.
- Returned server lists over TCP.
- Returned server lists over UDP.
- Pinged peer servers and updated liveness/stat fields.
- Saved server state back to disk.
- Asked peer servers for name, description, user count, file count, and limits.
- Removed or deprioritized stale entries.
- Bounded the number of returned servers.

## Gaps

1. No peer server store exists.
2. TCP server-list replies are not implemented.
3. UDP server-list replies are not implemented.
4. Peer ping and stat refresh are missing.
5. `server.met` import/export is missing.
6. Peering policy is not configurable.
7. There is no stale-peer lifecycle.

## Proposed Go Design

### Peer Store

```go
type PeerServer struct {
    IP          netip.Addr
    TCPPort     uint16
    UDPPort     uint16
    Name        string
    Description string
    Users       uint32
    Files       uint32
    SoftLimit   uint32
    HardLimit   uint32
    LastSeen    time.Time
    LastPing    time.Time
    Failures    int
}
```

Store implementations:

- In-memory for tests.
- JSON file for simple runtime.
- Optional SQL table for deployments already using database storage.

### TCP Server-List Reply

`handleGetServerList` should:

1. Check whether server-list replies are enabled.
2. Select live peers from the store.
3. Cap the count.
4. Encode using ED2K server-list packet format.
5. Optionally include this server if configured.

### UDP Server-List Reply

UDP server-list response should share peer selection logic with TCP and apply a stricter datagram size cap.

### Peer Refresh

Run a background worker:

1. Periodically ping peers.
2. Parse status replies.
3. Update liveness and counters.
4. Increase failure count on timeout.
5. Retire peers after configured failure threshold.

### Configuration

```json
{
  "peering": {
    "enabled": false,
    "server_list_replies": false,
    "include_self": false,
    "peer_store_path": "server-peers.json",
    "max_tcp_servers_returned": 50,
    "max_udp_servers_returned": 20,
    "ping_interval_seconds": 300,
    "retire_after_failures": 5
  }
}
```

Default peering should be disabled. Returning arbitrary server lists changes network behavior and can expose the server to reflection and reputation issues.

## Security Requirements

- Do not accept unlimited peer entries from untrusted input.
- Validate IP and port values before storing.
- Avoid returning private or loopback peers unless explicitly configured.
- Bound response size for both TCP and UDP.
- Add allowlist/denylist support for peering sources.

## Tests

- `server.met` import parses valid entries and rejects malformed entries.
- TCP server-list request returns capped live peers.
- UDP server-list reply respects datagram size.
- Stale peer is retired after failures.
- Private peer is filtered by default.
- Disabled peering returns no list and preserves current behavior.