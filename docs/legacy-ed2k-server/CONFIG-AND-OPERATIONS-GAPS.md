# Configuration and Operations Gaps

## Current Go Behavior

The Go server has JSON configuration, a sample config file, runtime stats, health checks, and an HTTP admin API. It is easy to run locally and suitable for iterative development.

Important current files:

- `ed2ksrv/config.go`
- `config.example.json`
- `ed2ksrv/admin.go`
- `ed2ksrv/admin_ui.go`

## LegacyED2KServer Behavior

LegacyED2KServer exposed many operational controls:

- Server identity, description, and operator messages.
- TCP, UDP, obfuscated, and auxiliary port settings.
- Worker counts and queue sizing.
- Max users, max clients, max file limits, and buffer limits.
- Search, HTTP, debug, and status logging.
- Runtime views for users, clients, debug state, and statistics.
- Periodic user/file/stat counters.
- IP filter loading.
- Peer server file loading and saving.
- Feature gates for zlib, obfuscation, warnings, and old client handling.

## Gaps

1. Config is flat compared with the behavior we need to add.
2. Runtime metrics do not cover all protocol queues and policy decisions.
3. Logging categories are not granular enough for deep protocol debugging.
4. Admin API does not expose planned search/source/policy internals.
5. Config reload behavior is not specified.
6. There is no documented compatibility matrix for enabled protocol features.

## Proposed Go Design

### Config Layout

Move toward grouped config while preserving backward compatibility through migration:

```json
{
  "identity": {
    "server_name": "goed2k-server",
    "server_description": "ED2K server",
    "message": "Welcome"
  },
  "listeners": {
    "tcp": ":4661",
    "udp_enabled": true,
    "udp_port_offset": 4,
    "obfuscation_enabled": true,
    "aux": []
  },
  "limits": {
    "max_users_advertised": 500000,
    "soft_files_limit": 5000,
    "hard_files_limit": 200000
  },
  "protocol": {},
  "search": {},
  "sources": {},
  "publish": {},
  "udp": {},
  "peering": {},
  "abuse": {},
  "admin": {}
}
```

Existing top-level fields should continue to load and be translated into the grouped model.

### Metrics

Add counters and gauges for:

- TCP sessions by phase.
- Frames by opcode and protocol.
- Packed frame decode successes/failures.
- Search requests, broad-search rejects, result counts, and planner cost.
- Source requests, selected source counts, and rotation hits.
- UDP packets by opcode, drops by reason, queue depth, and reply bytes.
- Publish accepted/rejected files and conflicts.
- Callback success/failure/denied counts.
- Abuse policy decisions.

### Logging

Use structured logs with categories:

- `tcp`
- `udp`
- `search`
- `sources`
- `publish`
- `callback`
- `peering`
- `abuse`
- `storage`

Debug logs should be opt-in by category to avoid flooding production logs.

### Admin API

Expose read-only endpoints first:

- `/api/runtime/protocol`
- `/api/runtime/search`
- `/api/runtime/sources`
- `/api/runtime/udp`
- `/api/runtime/abuse`
- `/api/runtime/peers`

Mutating endpoints should require explicit token auth and should be avoided until the state model is stable.

### Config Reload

Classify config fields:

- Reloadable: messages, warnings, limits, rate limits, filters, logging levels.
- Restart required: listener addresses, storage backend, schema-affecting options.
- Unsafe to reload initially: peering mode and obfuscation port layout.

The reload path should validate a complete config before swapping it into runtime services.

## Security Requirements

- Redact admin tokens and database DSNs in logs and admin responses.
- Validate config before starting listeners.
- Expose admin API only on explicitly configured addresses.
- Keep debug protocol dumps disabled by default.
- Avoid logging full user-provided filenames at high volume unless debug logging is enabled.

## Tests

- Old flat config loads into grouped config.
- Invalid grouped config fails before listeners start.
- Reloadable policy changes affect new requests.
- Restart-required fields are reported as not reloadable.
- Admin runtime endpoints redact secrets.
- Metrics increment on representative TCP, UDP, search, source, publish, and callback paths.