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
- This repo is the fixed local ED2K server used by eMuleBB live E2E and parity
  scenarios. It is harness infrastructure, not an evolving product or parity
  program. Make behavior changes only when required by a maintained harness
  scenario or a defect that prevents deterministic testing.
- Keep the checkout at `EMULEBB_WORKSPACE_ROOT\repos\goed2k-server`; resolve it
  through the generated workspace manifest instead of adding a separate ED2K
  server path environment variable.
- Do not perform routine upstream evolution. If a required harness fix needs
  upstream comparison, review `chenjia404/goed2k-server` deliberately and keep
  the local change narrowly scoped.
- Resolve the eMule harness only through `EMULEBB_WORKSPACE_ROOT`.
- Before finishing Go changes, run:
  - `go test ./...`
  - `go build -o $env:EMULEBB_WORKSPACE_OUTPUT_ROOT\tools\goed2k-server\goed2k-server.exe .\cmd\goed2k-server`
- Do not add shell wrapper launchers.