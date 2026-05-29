# Abuse Control Gaps

## Current Go Behavior

The Go server has basic limits and connection handling, but many protocol decisions are still permissive. That is reasonable for a small compatibility server, but broader protocol support needs stronger abuse controls.

Important current files:

- `ed2ksrv/config.go`
- `ed2ksrv/server.go`
- `ed2ksrv/admin.go`

## LegacyED2KServer Behavior

LegacyED2KServer contained a broad policy layer:

- Per-IP credit buckets and blackout periods.
- Client blacklisting.
- IP and network filters.
- Bad client and bad module detection.
- Null-publish blacklisting.
- Share count limits.
- Zlib-only and obfuscation-only admission policy.
- Warnings for old clients, random ports, fake files, and invalid behavior.
- Queue pressure limits for UDP and TCP worker queues.
- Separate counters for bad packets, bad searches, overlong packets, zlib errors, and filtered clients.

## Gaps

1. No general reputation model exists.
2. IP rate limiting is incomplete.
3. Blacklist and filter loaders are missing.
4. Policy actions are not standardized.
5. UDP queue and amplification limits are missing.
6. Client warnings are not modeled as first-class actions.
7. Admin API does not expose enough abuse state.

## Proposed Go Design

### Policy Actions

Use a common action model:

```go
type PolicyAction int

const (
    ActionAllow PolicyAction = iota
    ActionWarn
    ActionThrottle
    ActionReject
    ActionDisconnect
    ActionBlacklist
)
```

Each subsystem returns policy decisions instead of directly closing sessions.

### Reputation

```go
type ClientReputation struct {
    IP              netip.Addr
    UserHash        [16]byte
    BadPackets      int
    BadSearches     int
    NullPublishes   int
    ZlibErrors      int
    CallbackDenied  int
    BlacklistedUntil time.Time
}
```

Reputation keys should include IP, user hash when known, and client ID after login.

### Rate Limiting

Implement token buckets for:

- TCP new connections per IP.
- TCP requests per session.
- Search requests per client.
- Source requests per client.
- Callback requests per requester and target.
- UDP packets per IP.
- UDP response bytes per IP.

### Filters

Support:

- CIDR denylist.
- CIDR allowlist bypass for local testing.
- User-hash blacklist.
- Optional client-mod blacklist if client software tags are parsed.

Filter reload should be atomic and observable through the admin API.

### Warnings

Warnings should be structured:

```go
type ClientWarning struct {
    Code    string
    Message string
    Action  PolicyAction
}
```

The server can send protocol messages for user-visible warnings where compatible, and still record a machine-readable event.

### Admin and Metrics

Expose:

- Current blacklisted IPs.
- Recent policy decisions.
- Per-opcode reject counts.
- UDP drops by reason.
- Top rate-limited addresses.
- Filter version and reload timestamp.

## Security Requirements

- Default deny for malformed packets, not for unknown optional metadata.
- Never allow warning text to include unescaped user-provided strings.
- Make all queues bounded.
- Avoid reflection amplification on UDP.
- Ensure filter reload cannot leave a nil policy pointer.

## Tests

- Per-IP search burst is throttled.
- Blacklisted client cannot log in.
- CIDR denylist blocks before login.
- Allowlist bypass works only for configured ranges.
- Null publish increments reputation and triggers configured action.
- UDP amplification ratio limit drops excessive replies.
- Admin endpoint reports policy counters.