import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { resolveWorkspaceFile } from "../../src/core/lockfiles.js";
import { buildSecurityScanCheck } from "../../src/core/security-scan.js";
import { dependencyUnsafeSourceCheck } from "../../src/core/unsafe-source.js";
import type { PreFlightContext } from "../../src/shared/preflight-api.js";

let workspaceRoot = "";

beforeAll(async () => {
  workspaceRoot = await mkdtemp(join(tmpdir(), "mewra-dependency-guard-"));
  await Promise.all([
    writeFile(join(workspaceRoot, "package-lock.json"), "{}"),
    writeFile(join(workspaceRoot, "pnpm-lock.yaml"), "lockfileVersion: '9.0'"),
  ]);
});

afterAll(async () => {
  await rm(workspaceRoot, { recursive: true, force: true });
});

function context(
  runCommand: PreFlightContext["runCommand"],
  resolveTrustedTool: NonNullable<PreFlightContext["resolveTrustedTool"]>,
  root = workspaceRoot,
): PreFlightContext {
  return {
    workspaceRoot: root,
    resolveTool: async () => {
      throw new Error(
        "Security scanners must not use the workspace tool resolver.",
      );
    },
    resolveTrustedTool,
    runCommand,
  };
}

describe("security scan", () => {
  it("does not expose the scanner check as a package-manager install", () => {
    const check = buildSecurityScanCheck({ mode: "local" });

    expect(check.installable).toBe(false);
    expect(check.setupCommand).toBe("mewra-dependency-guard.configureScanner");
  });

  it("scans only changed supported lockfiles with trusted tools", async () => {
    const check = buildSecurityScanCheck({ mode: "local" });
    const commands: Array<{ command: string; args: string[] }> = [];
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [
          { path: "package-lock.json", status: "modified" },
          { path: "src/app.ts", status: "modified" },
        ],
        rawPatch: "",
      },
      context(
        async (command, args) => {
          commands.push({ command, args });
          return {
            stdout: command.endsWith("osv-scanner")
              ? '{"results":[]}'
              : '{"Results":[]}',
            stderr: "",
            code: 0,
          };
        },
        async (name) => `/trusted/${name}`,
      ),
    );

    expect(result.status).toBe("pass");
    expect(commands).toHaveLength(2);
    const scannedPath = await resolveWorkspaceFile(
      workspaceRoot,
      "package-lock.json",
    );
    expect(commands.map(({ args }) => args.at(-1))).toEqual([
      scannedPath,
      scannedPath,
    ]);
  });

  it("warns instead of passing when a scanner emits malformed JSON", async () => {
    const check = buildSecurityScanCheck({ mode: "local" });
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "pnpm-lock.yaml", status: "modified" }],
        rawPatch: "",
      },
      context(
        async () => ({
          stdout: "not scanner json",
          stderr: "",
          code: 0,
        }),
        async (name) => `/trusted/${name}`,
      ),
    );

    expect(result.status).toBe("warning");
    expect(result.message).toContain("could not complete");
  });

  it("warns when scanner JSON does not match its expected schema", async () => {
    const check = buildSecurityScanCheck({ mode: "local" });
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "pnpm-lock.yaml", status: "modified" }],
        rawPatch: "",
      },
      context(
        async () => ({ stdout: "{}", stderr: "", code: 0 }),
        async (name) => `/trusted/${name}`,
      ),
    );

    expect(result.status).toBe("warning");
  });

  it("fails with actionable OSV and Trivy vulnerability findings", async () => {
    const check = buildSecurityScanCheck({ mode: "local" });
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "package-lock.json", status: "modified" }],
        rawPatch: "",
      },
      context(
        async (command) => ({
          stdout: command.endsWith("osv-scanner")
            ? '{"results":[{"packages":[{"package":{"name":"example","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-test","database_specific":{"severity":"HIGH"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}]}]}]}'
            : '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-test","PkgName":"example-two","InstalledVersion":"2.0.0","Severity":"HIGH","FixedVersion":"2.1.0","PrimaryURL":"https://example.test/CVE-test","CVSS":{"nvd":{"V3Score":8.1}}}]}]}',
          stderr: "",
          code: 0,
        }),
        async (name) => `/trusted/${name}`,
      ),
    );

    expect(result).toMatchObject({
      status: "fail",
      findings: [
        {
          file: "package-lock.json",
          message: "GHSA-test affects example@1.0.0.",
          rule: "osv:GHSA-test",
          metadata: {
            scanner: "OSV",
            packageName: "example",
            installedVersion: "1.0.0",
            severity: "HIGH",
            fixedVersion: "1.2.0",
            cvss: "9.8",
          },
        },
        {
          file: "package-lock.json",
          message: "CVE-test affects example-two@2.0.0.",
          rule: "trivy:CVE-test",
          metadata: {
            scanner: "Trivy",
            packageName: "example-two",
            installedVersion: "2.0.0",
            severity: "HIGH",
            fixedVersion: "2.1.0",
            cvss: "8.1",
          },
        },
      ],
    });
  });

  it("uses a hardened, read-only Docker invocation only when explicitly selected", async () => {
    const check = buildSecurityScanCheck({ mode: "docker" });
    const commands: Array<{ command: string; args: string[] }> = [];
    await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "pnpm-lock.yaml", status: "modified" }],
        rawPatch: "",
      },
      context(
        async (command, args) => {
          commands.push({ command, args });
          return {
            stdout: args.includes("fs") ? '{"Results":[]}' : '{"results":[]}',
            stderr: "",
            code: 0,
          };
        },
        async (name) => (name === "docker" ? "/trusted/docker" : null),
      ),
    );

    expect(commands).toHaveLength(2);
    for (const { command, args } of commands) {
      expect(command).toBe("/trusted/docker");
      expect(args).toEqual(
        expect.arrayContaining([
          "run",
          "--rm",
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          `type=bind,source=${workspaceRoot},target=/workspace,readonly`,
          "/workspace/pnpm-lock.yaml",
        ]),
      );
      if (args.includes("fs")) {
        expect(args).toEqual(
          expect.arrayContaining([
            "type=volume,source=mewra-dependency-guard-trivy-cache,target=/cache",
            "--cache-dir",
            "/cache",
          ]),
        );
      }
      expect(args).not.toContain("--privileged");
      expect(args).not.toContain("--network");
    }
  });

  it("warns instead of attempting an unsafe Docker mount", async () => {
    const check = buildSecurityScanCheck({ mode: "docker" });
    let called = false;
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "pnpm-lock.yaml", status: "modified" }],
        rawPatch: "",
      },
      context(
        async () => {
          called = true;
          return { stdout: "", stderr: "", code: 0 };
        },
        async () => "/trusted/docker",
        `${workspaceRoot},unsafe`,
      ),
    );

    expect(result.status).toBe("warning");
    expect(called).toBe(false);
  });

  it("warns when only one local scanner is available and finds no vulnerabilities", async () => {
    const check = buildSecurityScanCheck({ mode: "local" });
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "package-lock.json", status: "modified" }],
        rawPatch: "",
      },
      context(
        async () => ({
          stdout: '{"results":[]}',
          stderr: "",
          code: 0,
        }),
        async (name) =>
          name === "osv-scanner" ? "/trusted/osv-scanner" : null,
      ),
    );

    expect(result.status).toBe("warning");
    expect(result.message).toContain("Only one scanner");
  });

  it("rejects changed lockfiles that are symbolic links", async () => {
    const target = join(workspaceRoot, "outside-lockfile");
    const link = join(workspaceRoot, "Cargo.lock");
    await writeFile(target, "outside");
    await symlink(target, link);

    await expect(
      resolveWorkspaceFile(workspaceRoot, "Cargo.lock"),
    ).resolves.toBeNull();
  });

  it("warns when one changed lockfile cannot be safely scanned", async () => {
    const target = join(workspaceRoot, "outside-gemfile");
    const link = join(workspaceRoot, "Gemfile.lock");
    await writeFile(target, "outside");
    await symlink(target, link);

    const check = buildSecurityScanCheck({ mode: "local" });
    const result = await check.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [
          { path: "package-lock.json", status: "modified" },
          { path: "Gemfile.lock", status: "modified" },
        ],
        rawPatch: "",
      },
      context(
        async (command) => ({
          stdout: command.endsWith("osv-scanner")
            ? '{"results":[]}'
            : '{"Results":[]}',
          stderr: "",
          code: 0,
        }),
        async (name) => `/trusted/${name}`,
      ),
    );

    expect(result.status).toBe("warning");
    expect(result.message).toContain("could not be safely scanned");
  });

  it("keeps the insecure dependency-source protection from PreFlight v0.3", async () => {
    const result = await dependencyUnsafeSourceCheck.run(
      {
        baseBranch: "main",
        headBranch: "feat/security",
        changedFiles: [{ path: "package.json", status: "modified" }],
        rawPatch:
          'diff --git a/package.json b/package.json\n+++ b/package.json\n@@ -1 +1 @@\n+"left-pad": "http://example.test/left-pad.tgz"',
      },
      context(
        async () => ({ stdout: "", stderr: "", code: 0 }),
        async () => null,
      ),
    );

    expect(result).toMatchObject({
      status: "fail",
      findings: [
        expect.objectContaining({ rule: "dependency-guard:unsafe-source" }),
      ],
    });
  });
});
