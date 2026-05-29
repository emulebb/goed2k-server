# Callback and LowID Gaps

## Current Go Behavior

The Go server assigns IDs, tracks connected clients, and supports callback requests by finding the target client in memory and sending callback packets. The implementation is useful for local compatibility, but the LowID model is intentionally basic.

Important current files:

- `ed2ksrv/server.go`: login, ID assignment, callback handling.
- `ed2ksrv/id_change_extended.go`: extended ID change helpers.
- `ed2ksrv/obfuscate.go`: protocol obfuscation support.

## LegacyED2KServer Behavior

LegacyED2KServer treated LowID clients as a first-class population:

- Assigned LowID values from an internal sequence and hash table.
- Tracked LowID client identity separately from high ID address identity.
- Supported callback requests from high ID clients to LowID clients.
- Sent different callback packet shapes depending on target and requester capability.
- Included extended callback information when protocol obfuscation or extended fields were relevant.
- Supported UDP callback request handling.
- Had callback cryptographic connection support for specific connection modes.
- Applied callback rate limits and policy checks.
- Warned or rejected clients based on invalid ports, old versions, or disallowed network ranges.

## Gaps

1. LowID assignment and lifecycle policy is incomplete.
2. Callback request permissions are minimal.
3. Extended callback fields are only partially modeled.
4. UDP callback request handling is missing.
5. Callback rate limiting is not separated from general packet handling.
6. Client reachability tests and forced LowID policy are not specified.

## Proposed Go Design

### Client Identity

Represent ID type explicitly:

```go
type ClientIDKind int

const (
    ClientHighID ClientIDKind = iota
    ClientLowID
)

type ClientIdentity struct {
    ID       uint32
    Kind     ClientIDKind
    UserHash [16]byte
    IP       netip.Addr
    TCPPort  uint16
    UDPPort  uint16
}
```

### LowID Allocator

Use a bounded allocator:

```go
type LowIDAllocator interface {
    Allocate(userHash [16]byte) (uint32, error)
    Release(id uint32)
    Lookup(id uint32) (*ClientIdentity, bool)
}
```

LowID should be released on disconnect and after session cleanup. The allocator should avoid immediate reuse where possible to reduce stale callback races.

### Callback Service

```go
type CallbackService struct {
    Clients ClientRegistry
    Limiter CallbackLimiter
    Policy  CallbackPolicy
}
```

Request handling:

1. Validate requester is logged in.
2. Validate target ID exists and is LowID where required.
3. Apply per-requester and per-target limits.
4. Select callback packet variant based on capabilities.
5. Send success notification to target or failure to requester.
6. Count callback success, target-missing, denied, and send-failed outcomes.

### Extended Callback Fields

When supported and enabled, include:

- Requester client ID.
- Requester IP and TCP port.
- Obfuscation support flag.
- Obfuscation port when known.
- User hash if required by the packet variant.

### UDP Callback

UDP callback requests should share the same `CallbackService` and policy. UDP should only be a transport adapter, not a separate callback implementation.

## Security Requirements

- Do not let unauthenticated UDP senders trigger unbounded callback traffic.
- Rate-limit by requester IP, requester client ID, and target ID.
- Reject callbacks to nonexistent or disconnected targets silently or with configured failure packets.
- Avoid leaking private source addresses in extended callback packets.
- Keep LowID lookup synchronized with disconnect cleanup.

## Tests

- LowID allocation is unique while clients are connected.
- LowID is released on disconnect.
- Callback to connected LowID target succeeds.
- Callback to missing target sends failure or drops according to policy.
- Rate limiter blocks callback floods.
- UDP callback path uses the same policy as TCP.
- Extended callback packet contains the expected fields for capable clients.