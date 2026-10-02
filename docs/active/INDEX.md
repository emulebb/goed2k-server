# goed2k-server Harness Baseline

> **Lifecycle: harness-only.** goed2k-server is the fixed deterministic local
> eD2K server used by eMuleBB tests. It has no product roadmap, promotion trigger,
> or feature-evolution program.

Purpose: a deterministic local ED2K server used by eMuleBB/emulebb-rust live E2E
and protocol-parity scenarios. The checklist below records the baseline that was
assembled for those scenarios; it is provenance, not a forward backlog.

## Recorded Lugdunum-parity baseline

Done (live-validated where noted):

- [x] F1 — UDP search (0x90/0x92/0x98 → 0x99) + UDP source lookup (0x9a/0x94 → 0x9b)
- [x] F2 — `OP_GETSERVERLIST → OP_SERVERLIST` (live: aMule)
- [x] F3 — UDP server description `OP_SERVER_DESC_REQ` (0xa2) → `OP_SERVER_DESC_RES` (0xa3)
- [x] F4 — Packed/zlib TCP frame receive (decompression-bomb guarded)
- [x] F5 — Packed/zlib TCP frame send (live: emulebb-main)
- [x] F6 — Source-selection policy (HighID-first ordering, cap, dedupe)
- [x] F7 — Per-IP TCP connection rate limiter (opt-in)
- [x] F8 — Publish-limit enforcement (max offered files per client)
- [x] F9 — UDP callback `OP_GLOBCALLBACKREQUEST` (0x9c) with anti-spoof
- [x] F11 — Callback rate limiting (TCP + UDP)
- [x] F12 — Server-list peering (static `peer_servers`)
- [x] F13 — Substring-preserving trigram search index
- [x] F14 — Active server-to-server peering (GLOBSERVSTATREQ/RES)
- [x] F15 — Deeper peer-list exchange (`OP_SERVER_LIST_REQ/RES`, learn peers)
- [x] F16-18 — UDP server-list variant 0xa4; TCP total search-result cap; HTTP-probe reject

Parked observations (not scheduled work):

- [ ] Finish session-phase enforcement (`handleGetSources`/`handleCallback` pre-login guard)
- [ ] Send-side standalone packing polish
- [ ] Further abuse-control / publish-conflict hardening

Historical inputs are retained in `docs/legacy-ed2k-server/`. Kad stays out of
goed2k scope.