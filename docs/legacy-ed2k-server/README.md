# LegacyED2KServer Gap Design Index

This directory documents behavior observed in LegacyED2KServer and maps it to gaps in the current Go implementation. The intent is not to clone unsafe implementation details. The intent is to capture wire behavior, policy knobs, queueing semantics, and operational surfaces that are useful when building a fuller ED2K server.

## Scope

The current Go fork already implements the core TCP path: login, status, message, ID change, file offers, search, search-more, source lookup, callback notification, TCP protocol obfuscation, static catalog storage, dynamic user state, an admin API, and UDP global server status replies.

The remaining parity gaps are mostly around protocol breadth, policy fidelity, indexing, abuse controls, and operational behavior. Each document below defines:

- What the current Go fork does today.
- What LegacyED2KServer did at the protocol or operational level.
- The proposed Go design.
- Validation and security requirements.

## Gap Documents

- [TCP Session and Frame Gaps](TCP-SESSION-AND-FRAME-GAPS.md)
- [Search Engine Gaps](SEARCH-ENGINE-GAPS.md)
- [Source Selection Gaps](SOURCE-SELECTION-GAPS.md)
- [UDP Service Gaps](UDP-SERVICE-GAPS.md)
- [Publish and Catalog Gaps](PUBLISH-AND-CATALOG-GAPS.md)
- [Callback and LowID Gaps](CALLBACK-AND-LOWID-GAPS.md)
- [Server List and Peering Gaps](SERVER-LIST-AND-PEERING-GAPS.md)
- [Abuse Control Gaps](ABUSE-CONTROL-GAPS.md)
- [Configuration and Operations Gaps](CONFIG-AND-OPERATIONS-GAPS.md)

## Implementation Principles

1. Preserve ED2K/eMule wire compatibility where clients rely on it.
2. Keep policy choices configurable and observable.
3. Prefer typed parsers and bounded buffers over byte slicing shortcuts.
4. Do not reproduce memory-safety bugs from legacy C behavior.
5. Add focused protocol tests before widening behavior.
6. Keep optional server-to-server and aggressive policy features disabled by default until they are proven safe.

## Suggested Order

1. TCP frame/zlib support, because it affects many request paths.
2. UDP search and UDP source lookup, because clients expect these for server-list and source refresh behavior.
3. Source selection policy, because simple source dumping does not match large-network behavior.
4. Publish/catalog indexing, because search and source selection need stronger metadata.
5. Abuse control and operations, because broader protocol support increases exposure.