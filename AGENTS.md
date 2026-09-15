# Mewra Dependency Guard

## Product scope

This extension contributes diff-scoped dependency-security checks to Mewra PreFlight. It is not a dashboard, a CI replacement, or a general source scanner.

## Architecture rules

- Keep VS Code APIs in `src/extension/` only.
- `src/core/` must depend only on the local structural PreFlight contract in `src/shared/preflight-api.ts`.
- Scan only supported changed lockfiles for vulnerabilities. Never expand a diff-scoped scan into a workspace scan.
- Keep the dependency-source transport check limited to added lines in changed dependency manifests and lockfiles.
- Use fixed argument arrays for every command. Never invoke a shell.
- Docker mode must keep the workspace mount read-only and must not use host networking, privileged mode, or the Docker socket.
- Missing tools return `not-configured`; malformed scanner output or execution errors return `warning`.

## Quality gate

```bash
pnpm validate
```
