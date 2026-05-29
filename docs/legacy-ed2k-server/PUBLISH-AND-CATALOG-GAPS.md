# Publish and Catalog Gaps

## Current Go Behavior

The Go server accepts `OP_OFFERFILES` and updates dynamic shared files for a connected client. It also supports a static shared catalog backed by JSON, MySQL, or PostgreSQL. The current design is practical, but it treats publish as a relatively direct replacement/update operation.

Important current files:

- `ed2ksrv/offerfiles.go`
- `ed2ksrv/catalog.go`
- `ed2ksrv/db_store.go`
- `ed2ksrv/server.go`

## LegacyED2KServer Behavior

LegacyED2KServer had a full publish pipeline:

- Parsed file offers with strict tag handling and string length caps.
- Enforced hard and soft share limits.
- Detected null or suspicious publish behavior and could blacklist clients.
- Stored or updated file nodes in global indexes.
- Retired file ownership when clients disconnected or republished.
- Detected duplicate hashes with conflicting sizes.
- Maintained keyword, metadata, and source relationships for search and source lookup.
- Applied fake-file and suspicious-file policy.
- Logged publish events and warning reasons.
- Sent warning messages for policy violations when configured.

## Gaps

1. Publish policy is not separated from packet parsing.
2. Soft and hard limits are not enforced with LegacyED2KServer-level detail.
3. Null-publish and suspicious publish behavior are not tracked.
4. Duplicate hash with conflicting metadata has no explicit policy.
5. Dynamic publish updates do not feed a complete search index.
6. Fake or suspicious file classification is not represented.
7. Publish audit data is minimal.

## Proposed Go Design

### Publish Manager

Introduce a publish manager between packet parsing and catalog/index mutation:

```go
type PublishManager struct {
    Files      FileRepository
    Index      SearchIndex
    Sources    SourceRepository
    Policy     PublishPolicy
    Reputation ClientReputation
}

type PublishRequest struct {
    ClientID uint32
    UserHash [16]byte
    Files    []OfferedFile
    Received time.Time
}
```

The manager returns a structured result:

```go
type PublishResult struct {
    AcceptedFiles int
    RejectedFiles int
    Warnings      []PublishWarning
    Blacklist     bool
}
```

### Policy

```json
{
  "publish": {
    "soft_file_limit_per_client": 5000,
    "hard_file_limit_per_client": 200000,
    "max_offer_files_per_packet": 10000,
    "max_filename_bytes": 512,
    "allow_hash_size_conflict": false,
    "blacklist_null_publish": true,
    "warn_on_suspicious_file": true
  }
}
```

### File Identity

Use ED2K hash as the primary identity, but treat size as a required invariant:

```go
type FileIdentity struct {
    Hash [16]byte
    Size uint64
}
```

If the same hash appears with conflicting sizes, the default action should be reject the new record, increment a conflict metric, and optionally mark the client suspicious.

### Index Updates

Publish changes should update:

- Hash to file record.
- File to source ownership.
- Keyword index.
- Type and extension indexes.
- Optional media metadata indexes.

All index mutations should be atomic from the perspective of search. Use copy-on-write snapshots or a single locked mutation path.

### Disconnect and Republish

On disconnect:

1. Remove client ownership from dynamic files.
2. Remove file records that have no static record and no dynamic owners.
3. Update all affected indexes.

On republish:

1. Compare old and new ownership sets.
2. Add new files.
3. Remove files no longer offered.
4. Keep unchanged ownership timestamps fresh.

## Security Requirements

- Enforce maximum files per packet before allocating per-file structures.
- Cap all string tag lengths.
- Normalize filenames once.
- Reject malformed tags without partial index mutation.
- Protect index mutation with transaction-like semantics.

## Tests

- Publish within limits adds dynamic files and source ownership.
- Republish removes files no longer offered.
- Disconnect removes dynamic ownership.
- Null publish triggers configured policy.
- Hash-size conflict is rejected.
- Over-limit publish is rejected or truncated according to policy.
- Search index updates after publish and disconnect.