import type {
  CheckFinding,
  CheckResult,
  CheckRunner,
  GitDiff,
  PreFlightContext,
} from "../shared/preflight-api.js";
import {
  changedLockfiles,
  discoverSupportedLockfiles,
  dockerWorkspacePath,
  resolveWorkspaceFile,
} from "./lockfiles.js";
import {
  buildScannerCommands,
  type ScannerMode,
  type ScannerName,
} from "./scanner-command.js";
import { parseCvssVector } from "./cvss.js";

export type SecurityScanOptions = {
  mode: ScannerMode;
  scope?: SecurityScanScope;
};

export type SecurityScanScope = "diff" | "workspace";

type ScannerOutput = {
  scanner: ScannerName;
  file: string;
  stdout: string;
  stderr: string;
  code: number;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asText(value: unknown, fallback = "unknown"): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function trivyCvssScore(
  vulnerability: Record<string, unknown>,
): string | undefined {
  const cvss = asRecord(vulnerability.CVSS);
  if (!cvss) return undefined;
  const scores = Object.values(cvss)
    .map(asRecord)
    .flatMap((source) => [source?.V3Score, source?.V2Score])
    .filter((score): score is number => typeof score === "number");
  const highest = Math.max(...scores);
  return Number.isFinite(highest) ? highest.toFixed(1) : undefined;
}

function osvFixedVersion(
  vulnerability: Record<string, unknown>,
): string | undefined {
  for (const affected of asArray(vulnerability.affected)) {
    for (const range of asArray(asRecord(affected)?.ranges)) {
      for (const event of asArray(asRecord(range)?.events)) {
        const fixed = optionalText(asRecord(event)?.fixed);
        if (fixed) return fixed;
      }
    }
  }
  return undefined;
}

function osvCvssScore(
  vulnerability: Record<string, unknown>,
): string | undefined {
  const scores = asArray(vulnerability.severity)
    .map(asRecord)
    .filter((severity) => severity?.type?.toString().startsWith("CVSS"))
    .map((severity) => optionalText(severity?.score))
    .flatMap((score) => {
      if (!score) return [];
      const parsed = parseCvssVector(score) ?? Number.parseFloat(score);
      return Number.isFinite(parsed) ? [parsed] : [];
    });
  const highest = Math.max(...scores);
  return Number.isFinite(highest) ? highest.toFixed(1) : undefined;
}

function osvSeverity(vulnerability: Record<string, unknown>): string {
  const databaseSeverity = optionalText(
    asRecord(vulnerability.database_specific)?.severity,
  )?.toUpperCase();
  if (databaseSeverity === "MODERATE") return "MEDIUM";
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(databaseSeverity ?? "")) {
    return databaseSeverity!;
  }
  const cvss = osvCvssScore(vulnerability);
  if (!cvss) return "UNKNOWN";
  const score = Number.parseFloat(cvss);
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function parseOsvFindings(file: string, stdout: string): CheckFinding[] | null {
  const parsed = asRecord(JSON.parse(stdout));
  if (!parsed || !Array.isArray(parsed.results)) return null;
  return parsed.results.flatMap((result) => {
    const resultRecord = asRecord(result);
    return asArray(resultRecord?.packages).flatMap((entry) => {
      const packageRecord = asRecord(entry);
      const packageInfo = asRecord(packageRecord?.package);
      const packageName = asText(packageInfo?.name);
      const packageVersion = asText(packageInfo?.version);
      return asArray(packageRecord?.vulnerabilities).map((vulnerability) => {
        const vulnerabilityRecord = asRecord(vulnerability) ?? {};
        const id = asText(vulnerabilityRecord.id);
        const fixedVersion = osvFixedVersion(vulnerabilityRecord);
        const cvss = osvCvssScore(vulnerabilityRecord);
        return {
          file,
          line: 0,
          message: `${id} affects ${packageName}@${packageVersion}.`,
          rule: `osv:${id}`,
          metadata: {
            scanner: "OSV",
            packageName,
            installedVersion: packageVersion,
            severity: osvSeverity(vulnerabilityRecord),
            ...(fixedVersion ? { fixedVersion } : {}),
            ...(cvss ? { cvss } : {}),
            advisoryUrl: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
          },
        };
      });
    });
  });
}

function parseTrivyFindings(
  file: string,
  stdout: string,
): CheckFinding[] | null {
  const parsed = asRecord(JSON.parse(stdout));
  if (!parsed || !Array.isArray(parsed.Results)) return null;
  return parsed.Results.flatMap((result) => {
    const resultRecord = asRecord(result);
    return asArray(resultRecord?.Vulnerabilities).map((vulnerability) => {
      const vulnerabilityRecord = asRecord(vulnerability) ?? {};
      const id = asText(vulnerabilityRecord.VulnerabilityID);
      const packageName = asText(vulnerabilityRecord.PkgName);
      const packageVersion = asText(vulnerabilityRecord.InstalledVersion);
      const severity = optionalText(vulnerabilityRecord.Severity);
      const fixedVersion = optionalText(vulnerabilityRecord.FixedVersion);
      const advisoryUrl = optionalText(vulnerabilityRecord.PrimaryURL);
      const cvss = trivyCvssScore(vulnerabilityRecord);
      return {
        file,
        line: 0,
        message: `${id} affects ${packageName}@${packageVersion}.`,
        rule: `trivy:${id}`,
        metadata: {
          scanner: "Trivy",
          packageName,
          installedVersion: packageVersion,
          ...(severity ? { severity } : {}),
          ...(fixedVersion ? { fixedVersion } : {}),
          ...(cvss ? { cvss } : {}),
          ...(advisoryUrl ? { advisoryUrl } : {}),
        },
      };
    });
  });
}

function parseFindings(output: ScannerOutput): CheckFinding[] | null {
  if (!output.stdout.trim()) return null;
  try {
    return output.scanner === "osv"
      ? parseOsvFindings(output.file, output.stdout)
      : parseTrivyFindings(output.file, output.stdout);
  } catch {
    return null;
  }
}

function dedupeFindings(findings: CheckFinding[]): CheckFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.file}:${finding.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function scanLockfile(
  file: string,
  context: PreFlightContext,
  mode: ScannerMode,
): Promise<{
  outputs: ScannerOutput[];
  configured: boolean;
  partial: boolean;
  unscannable: boolean;
}> {
  const localPath = await resolveWorkspaceFile(context.workspaceRoot, file);
  const containerPath = dockerWorkspacePath(file);
  if (!localPath || !containerPath) {
    return {
      outputs: [],
      configured: false,
      partial: false,
      unscannable: true,
    };
  }

  const commands = await buildScannerCommands(
    context,
    mode,
    localPath,
    containerPath,
  );
  if (commands.length === 0) {
    return {
      outputs: [],
      configured: false,
      partial: false,
      unscannable: false,
    };
  }

  const outputs = await Promise.all(
    commands.map(async (scanner) => {
      const result = await context.runCommand(
        scanner.command,
        scanner.args,
        context.workspaceRoot,
        120_000,
      );
      return { ...scanner, file, ...result };
    }),
  );
  return {
    outputs,
    configured: true,
    partial: commands.length === 1,
    unscannable: false,
  };
}

async function scanLockfiles(
  files: string[],
  context: PreFlightContext,
  mode: ScannerMode,
): Promise<Awaited<ReturnType<typeof scanLockfile>>[]> {
  const scans: Array<Awaited<ReturnType<typeof scanLockfile>>> = [];
  let nextFile = 0;
  const workerCount = Math.min(2, files.length);
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (nextFile < files.length) {
        const index = nextFile++;
        const file = files[index];
        if (!file) continue;
        scans[index] = await scanLockfile(file, context, mode);
      }
    }),
  );
  return scans;
}

function lockfileLabel(count: number, scope: SecurityScanScope): string {
  return `${scope === "diff" ? "changed " : ""}lockfile${count === 1 ? "" : "s"}`;
}

export async function runSecurityScan(
  files: string[],
  context: PreFlightContext,
  options: SecurityScanOptions,
  scope: SecurityScanScope,
): Promise<CheckResult> {
  if (files.length === 0) {
    return {
      status: "skipped",
      findings: [],
      message:
        scope === "diff"
          ? "No supported lockfiles changed in this diff."
          : "No supported lockfiles found in this workspace.",
    };
  }

  const scans = await scanLockfiles(files, context, options.mode);
  const unscannableScans = scans.filter((scan) => scan.unscannable);
  if (scans.every((scan) => !scan.configured)) {
    return {
      status: unscannableScans.length > 0 ? "warning" : "not-configured",
      findings: [],
      message:
        unscannableScans.length > 0
          ? `${unscannableScans.length} ${lockfileLabel(unscannableScans.length, scope)} could not be safely scanned.`
          : options.mode === "docker"
            ? "Docker is unavailable or the workspace path cannot be mounted safely."
            : "OSV Scanner and Trivy are not available on PATH.",
    };
  }

  const outputs = scans.flatMap((scan) => scan.outputs);
  const failedScans = outputs.filter((output) => output.code !== 0);
  const partialScans = scans.filter((scan) => scan.partial);
  const parsedFindings = outputs.map(parseFindings);
  const malformedScans = parsedFindings.filter((findings) => findings === null);
  const findings = dedupeFindings(
    parsedFindings.flatMap((findings) => findings ?? []),
  );

  if (findings.length > 0) {
    return {
      status: "fail",
      findings,
      message: `${findings.length} known vulnerabilit${findings.length === 1 ? "y" : "ies"} found in ${scope === "diff" ? "changed " : ""}lockfiles.`,
    };
  }
  if (
    failedScans.length > 0 ||
    malformedScans.length > 0 ||
    partialScans.length > 0 ||
    unscannableScans.length > 0
  ) {
    return {
      status: "warning",
      findings,
      message:
        partialScans.length > 0
          ? "Only one scanner is available. Install both OSV Scanner and Trivy for complete coverage."
          : unscannableScans.length > 0
            ? `${unscannableScans.length} ${lockfileLabel(unscannableScans.length, scope)} could not be safely scanned.`
            : `${failedScans.length + malformedScans.length} scanner invocation${failedScans.length + malformedScans.length === 1 ? "" : "s"} could not complete. Review scanner output and retry.`,
    };
  }
  return {
    status: "pass",
    findings: [],
    message: `No known vulnerabilities found in ${scope === "diff" ? "changed " : ""}lockfiles.`,
  };
}

export function buildSecurityScanCheck(
  options: SecurityScanOptions,
): CheckRunner {
  const scope = options.scope ?? "diff";
  return {
    id: "mewra-dependency-guard:security-scan",
    label: "Mewra Dependency Guard — Security Scan",
    severity: "error",
    pack: "mewra-dependency-guard",
    installable: false,
    setupCommand: "mewra-dependency-guard.configureScanner",
    actionCommand: "mewra-dependency-guard.configureScanScope",
    actionLabel: "Configure scope",

    appliesTo(diff: GitDiff): boolean {
      return (
        scope === "workspace" || changedLockfiles(diff.changedFiles).length > 0
      );
    },

    async run(diff: GitDiff, context: PreFlightContext): Promise<CheckResult> {
      if (scope === "workspace") {
        const discovery = await discoverSupportedLockfiles(
          context.workspaceRoot,
        );
        if (discovery.truncated) {
          return {
            status: "warning",
            findings: [],
            message:
              "Full dependency scan found more than 32 supported lockfiles. Narrow the workspace before scanning.",
          };
        }
        return runSecurityScan(discovery.files, context, options, "workspace");
      }
      return runSecurityScan(
        changedLockfiles(diff.changedFiles),
        context,
        options,
        "diff",
      );
    },
  };
}
