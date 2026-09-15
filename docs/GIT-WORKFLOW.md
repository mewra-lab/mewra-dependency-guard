# Git workflow

Work from a short-lived branch and open a pull request against `main`.

Before requesting review, run:

```bash
pnpm validate
```

Merge only after CI passes. Releases are created from an annotated SemVer tag on `main`; the release workflow verifies that the tag and `package.json` version match, packages a VSIX, publishes its SHA-256 checksum, and creates or updates the GitHub Release.
