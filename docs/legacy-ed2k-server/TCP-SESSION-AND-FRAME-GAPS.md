# TCP Session and Frame Gaps

## Current Go Behavior

The Go server accepts TCP sessions, decodes regular ED2K frames, handles the main client opcodes, and supports TCP protocol obfuscation. The current frame path is intentionally small: it reads one frame, dispatches by opcode, and replies with direct packet writes.

Important current files:

- `ed2ksrv/server.go`: TCP session loop, opcode dispatch, login, offers, search, sources, callbacks.
- `ed2ksrv/obfuscate.go`: server-side TCP obfuscation handshake.
- `ed2ksrv/protocol.go`: search and protocol helpers.

## LegacyED2KServer Behavior

LegacyED2KServer had a wider TCP session model:

- Accepted plain ED2K frames and compressed packed frames.
- Performed server-side Diffie-Hellman and RC4 setup before normal packet parsing on obfuscated ports.
- Rejected HTTP probes with an HTTP response instead of treating them as malformed ED2K frames.
- Tracked malformed frame length, zlib errors, and "zlib required" policy violations separately.
- Allowed policy to require zlib-capable clients.
- Routed large compressed offer-file payloads through the same publish path after decompression.
- Maintained per-client request counters for search, source lookup, callback, bad request, and disconnect decisions.
- Had auxiliary listeners and alternate ports for related server functions.

The important design point is that frame decoding was not just a byte reader. It was part of admission control, client capability enforcement, observability, and packet accounting.

## Gaps

1. Packed-frame support is missing.
2. Decompressed output limits are not modeled as a first-class safety setting.
3. HTTP probe handling is not explicit.
4. Capability gates such as "zlib required" are not represented in config.
5. The session state machine does not distinguish pre-login, obfuscation, logged-in, and closing policy states deeply enough.
6. TCP packet counters exist only indirectly through runtime stats.
7. Auxiliary listener behavior is not specified.

## Proposed Go Design

### Frame Reader

Introduce a `FrameReader` that returns:

```go
type FrameKind int

const (
    FrameED2K FrameKind = iota
    FramePacked
    FrameHTTPProbe
)

type Frame struct {
    Kind       FrameKind
    Protocol   byte
    Opcode     byte
    Payload    []byte
    PackedSize int
}
```

The reader should enforce:

- Maximum encoded frame size.
- Maximum decoded frame size.
- Maximum compression ratio.
- Strict little-endian length parsing.
- No partial opcode reads.
- No frame allocation before checking configured limits.

### Session State

Represent session state explicitly:

```go
type SessionPhase int

const (
    PhaseConnected SessionPhase = iota
    PhaseObfuscating
    PhaseAwaitingLogin
    PhaseLoggedIn
    PhaseClosing
)
```

The dispatcher should reject state-invalid opcodes. For example, offer-files before login should not update dynamic share state.

### Zlib Policy

Add configuration:

```json
{
  "protocol": {
    "zlib": {
      "accept_packed_frames": true,
      "require_client_support": false,
      "max_decoded_frame_bytes": 1048576,
      "max_compression_ratio": 64
    }
  }
}
```

If packed support is disabled, the server should close or reject packed frames consistently. If zlib is required and the client did not advertise support, the server should send the configured rejection message and close.

### HTTP Probe Handling

Detect `GET `, `POST `, `HEAD `, and `OPTIONS ` at the start of a TCP stream. Reply with a minimal 404 or 400 response, increment an HTTP-probe counter, and close. This avoids noisy ED2K parse errors in logs.

### Auxiliary Listeners

Model auxiliary listeners as explicit server components with their own listen address, purpose, and handler. Do not overload the primary ED2K listener with unrelated behavior.

## Security Requirements

- Never decompress without an output cap.
- Never trust compressed size as a proxy for decoded size.
- Keep obfuscation handshake timeouts short.
- Treat packed offer-files as untrusted input to the same parser as plain offer-files.
- Fuzz frame parsing with random protocol bytes, short buffers, oversized lengths, and invalid compressed streams.

## Tests

- Plain frame dispatch still works for all existing TCP tests.
- Packed search request decodes and dispatches.
- Packed offer-files request decodes and updates dynamic files.
- Oversized packed frame is rejected before large allocation.
- Invalid zlib stream increments a zlib-error metric and closes.
- HTTP probe receives HTTP response and no ED2K handler runs.
- Obfuscated login still works with the new reader.