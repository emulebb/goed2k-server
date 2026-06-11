# Rules

- Read `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first; it is authoritative for workspace-wide rules.
- Start from
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\AGENT-CHECKLIST.md`
  for the repeatable operating path.

Everything below is this repo's local deltas only:

- Use `README.md` as the canonical ED2K server docs home.
- Use eMule workspace planning and progress docs as the active backlog for
  eMuleBB integration work.
- Target full stock eMule `v0.72a` ED2K parity, including deprecated legacy
  compatibility behavior. The only standing protocol exception is defunct ED2K
  PeerCache support.
- This repo is the active local ED2K server used by eMuleBB live E2E and parity
  scenarios.
- Keep the checkout at `EMULEBB_WORKSPACE_ROOT\repos\goed2k-server`; resolve it
  through the generated workspace manifest instead of adding a separate ED2K
  server path environment variable.
- Keep the fork rebased on `chenjia404/goed2k-server` before behavior work, then
  apply eMuleBB integration deltas as small local commits.
- Resolve the eMule harness only through `EMULEBB_WORKSPACE_ROOT`.
- Before finishing Go changes, run:
  - `go test ./...`
  - `go build -o $env:EMULEBB_WORKSPACE_ROOT\workspaces\workspace\state\tools\goed2k-server\goed2k-server.exe .\cmd\goed2k-server`
- Do not add shell wrapper launchers.