# ED2K Server Repo Rules

- Follow the shared workspace policy in
  `%EMULE_WORKSPACE_ROOT%\repos\eMule-tooling\docs\WORKSPACE-POLICY.md`.
- Use `README.md` as the canonical ED2K server docs home.
- Use eMule workspace planning and progress docs as the active backlog for
  eMule BB integration work.
- Target full stock eMule `v0.72a` ED2K parity, including deprecated legacy
  compatibility behavior. The only standing protocol exception is defunct
  ED2K PeerCache support.
- This repo is the active local ED2K server used by eMule BB live E2E and
  parity scenarios.
- Keep the checkout at `%EMULE_WORKSPACE_ROOT%\repos\goed2k-server`;
  resolve it through the generated workspace manifest instead of adding a
  separate ED2K server path environment variable.
- Keep the fork rebased on `chenjia404/goed2k-server` before behavior work,
  then apply eMule BB integration deltas as small local commits.
- Resolve the eMule harness only through `%EMULE_WORKSPACE_ROOT%`.
- Before finishing Go changes, run:
  - `go test ./...`
  - `go build -o %EMULE_WORKSPACE_ROOT%\workspaces\workspace\state\tools\goed2k-server\goed2k-server.exe .\cmd\goed2k-server`
- Keep tracked text files normalized to UTF-8 with LF endings; the workspace
  line-ending guard is enforced from tooling.
- Do not add shell wrapper launchers.
