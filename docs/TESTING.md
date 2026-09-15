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

For a manual Docker smoke test, select `mewraDependencyGuard.scannerMode: "docker"`, change a supported lockfile, and run PreFlight. The extension may pull the pinned scanner images and Trivy database on first use.
