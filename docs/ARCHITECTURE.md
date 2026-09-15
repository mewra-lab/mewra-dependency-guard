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
```

Only changed supported lockfiles can enter the vulnerability scan path. Each file must be a regular non-symlink file resolving inside the workspace before command construction. The source guard only inspects added patch lines in changed dependency files. Commands are fixed argument arrays; no shell command is formed. Scanner and Docker executables resolve only from trusted user or system locations, never the opened workspace.

Docker mode is explicitly selected. It uses pinned image digests, a read-only workspace mount, a temporary `/tmp`, dropped capabilities, and `no-new-privileges`. It does not use privileged containers, the Docker socket, or host networking. Trivy's database is cached in the Docker-managed `mewra-dependency-guard-trivy-cache` volume, never the workspace.
