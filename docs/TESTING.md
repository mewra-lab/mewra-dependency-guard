# Testing

Run the complete local quality gate:

```bash
pnpm install --frozen-lockfile
pnpm validate
```

Unit tests cover the boundary between the PreFlight check contract and scanner execution:

- only supported changed lockfiles are scanned;
- symlinked lockfiles are rejected;
- local and Docker command construction stays lockfile-scoped;
- Docker command arguments retain the hardening controls;
- OSV and Trivy vulnerabilities, plus insecure added dependency sources, fail the check;
- malformed or schema-invalid output and partial scanner availability produce warnings instead of a false pass.
- full-scan discovery skips symbolic links and generated/dependency directories,
  has a deterministic bounded scope, and reuses the same scanner result
  normalization as the diff check.

For a manual Docker smoke test, select `mewraDependencyGuard.scannerMode: "docker"`, change a supported lockfile, and run PreFlight. The extension may pull the pinned scanner images and Trivy database on first use. To exercise the explicit audit path, run **Mewra Dependency Guard: Run Full Dependency Scan** from the Command Palette; it must show results in the **Mewra Dependency Guard** output channel without changing the PreFlight dashboard.
