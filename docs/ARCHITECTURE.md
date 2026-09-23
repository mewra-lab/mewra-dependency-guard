# Architecture

Mewra Dependency Guard is a companion extension, not a PreFlight pack. It activates after VS Code startup, activates `mewra.mewra-preflight`, verifies API version 1, and registers two `CheckRunner`s:

```text
mewra-dependency-guard:security-scan
dependency-guard:unsafe-source
```

The extension layer owns VS Code APIs and configuration. The core layer is independent of VS Code and uses a local structural representation of the PreFlight API.

```text
VS Code configuration
        |
extension.ts -- registers check --> Mewra PreFlight API
        |
security-scan.ts -- selects changed lockfiles --> scanner-command.ts
        |                                           |
        +------------ parse JSON results <----------+

extension.ts -- explicit full-scan command --> lockfiles.ts discovery
        |                                      scanner-context.ts
        +------------------------- fixed command context ------------+
```

Only changed supported lockfiles can enter the vulnerability scan path. Each file must be a regular non-symlink file resolving inside the workspace before command construction. The source guard only inspects added patch lines in changed dependency files. Commands are fixed argument arrays; no shell command is formed. Scanner and Docker executables resolve only from trusted user or system locations, never the opened workspace.

**Run Full Dependency Scan** is intentionally outside the PreFlight pipeline.
It is invoked from the Command Palette, targets the active workspace folder (or
requires a selection in a multi-root window), and uses the same OSV/Trivy
parser and command construction. Discovery skips symlinked, generated, and
dependency directories and refuses more than 32 supported lockfiles rather
than silently performing a partial audit. `scanner-context.ts` accepts only the
three fixed executable names (`osv-scanner`, `trivy`, `docker`) from trusted
user/system locations and executes fixed argument arrays with a timeout. The
command writes results to its own output channel; it does not change PreFlight
dashboard status or PR/MR gating.

Docker mode is explicitly selected. It uses pinned image digests, a read-only workspace mount, a temporary `/tmp`, dropped capabilities, and `no-new-privileges`. It does not use privileged containers, the Docker socket, or host networking. Trivy's database is cached in the Docker-managed `mewra-dependency-guard-trivy-cache` volume, never the workspace.

The `securityScanScope` setting also supports an explicit `workspace` mode for
teams that want the contributed check itself to run on every PreFlight action,
including an empty diff. In that mode the runner calls the same bounded
discovery and scanner pipeline; the default remains `diff`. Host-level
`.mewra-preflight.json` and `.preflightignore` controls remain visible and
auditable after findings are produced.

The security check contributes a host-resolved scope action. When the default
diff-scoped check has no matching lockfile, PreFlight shows **Configure scan
scope** on the skipped row. Saving a scope reruns the PreFlight pipeline so the
new setting is visible immediately. The Webview sends only the check ID; the
host resolves and validates the registered VS Code command before executing it.
