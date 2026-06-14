# goed2k-server Active Backlog — Lab Index

> **Tier: Lab.** goed2k-server is a **lab/service** product in the BB suite, not a
> shipped client. By operator decision (2026-06-14) it **stays lab for now**: no
> build/test CI gate and no org-board itemization yet. This index is a lightweight
> tracking record of the Lugdunum-parity program; promote to full
> `docs/active/items` + the eMuleBB Suite board only when goed2k leaves lab tier.

Purpose: a deterministic local ED2K server used by eMuleBB/emulebb-rust live E2E
and protocol-parity scenarios. Active goal: feature-by-feature parity with
**Lugdunum eserver 17.15**, validated with live clients + the Python campaigns.

## ID Taxonomy (when promoted)

Item IDs would use the product prefix `GOED2K-<CLASS>-<NNN>` (classes `BUG`,
`FEAT`, `REF`, `CI`). Until promotion, the parity features below are tracked as a
checklist, not as individual item files.

## Lugdunum-parity checklist

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

Next (suggested order, uncommitted working-tree may exist):

- [ ] Finish session-phase enforcement (`handleGetSources`/`handleCallback` pre-login guard)
- [ ] Send-side standalone packing polish
- [ ] Further abuse-control / publish-conflict hardening

Authoritative inputs and the live test loop are recorded in the project memory
note `goed2k-lugdunum-parity-loop` and in `docs/legacy-ed2k-server/`. KAD stays
out of goed2k scope.