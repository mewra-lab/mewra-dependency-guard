import { access, constants, realpath } from "node:fs/promises";
import { execFile } from "node:child_process";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import type {
  CommandResult,
  PreFlightContext,
} from "../shared/preflight-api.js";

const execFileAsync = promisify(execFile);
const TRUSTED_BINARIES = new Set(["docker", "osv-scanner", "trivy"]);

function isInsideWorkspace(workspaceRoot: string, candidate: string): boolean {
  const workspaceRelative = relative(workspaceRoot, candidate);
  return (
    workspaceRelative !== "" &&
    workspaceRelative !== ".." &&
    !workspaceRelative.startsWith(`..${sep}`) &&
    !isAbsolute(workspaceRelative)
  );
}

async function isTrustedExecutable(
  workspaceRoot: string,
  candidate: string,
): Promise<string | null> {
  try {
    const [realWorkspace, realCandidate] = await Promise.all([
      realpath(workspaceRoot),
      realpath(candidate),
    ]);
    if (isInsideWorkspace(realWorkspace, realCandidate)) return null;
    await access(realCandidate, constants.X_OK);
    return realCandidate;
  } catch {
    return null;
  }
}

async function resolveTrustedScannerTool(
  workspaceRoot: string,
  binName: string,
): Promise<string | null> {
  if (!TRUSTED_BINARIES.has(binName)) return null;
  const executable = process.platform === "win32" ? `${binName}.exe` : binName;
  const home = process.env.HOME ?? "";
  const userProfile = process.env.USERPROFILE ?? "";
  const programFiles = process.env.ProgramFiles ?? "";
  const candidates = [
    ...(home
      ? [
          resolve(home, ".local", "bin", executable),
          resolve(home, ".cargo", "bin", executable),
          resolve(home, "go", "bin", executable),
          resolve(home, ".config", "composer", "vendor", "bin", executable),
        ]
      : []),
    ...(process.platform === "win32" && userProfile
      ? [
          resolve(userProfile, ".cargo", "bin", executable),
          resolve(userProfile, "scoop", "shims", executable),
          resolve(userProfile, "go", "bin", executable),
        ]
      : []),
    ...(process.platform === "win32" && programFiles
      ? [
          resolve(
            programFiles,
            "Docker",
            "Docker",
            "resources",
            "bin",
            executable,
          ),
          resolve(programFiles, "Trivy", executable),
          resolve(programFiles, "osv-scanner", executable),
        ]
      : []),
    `/opt/homebrew/bin/${executable}`,
    `/usr/local/bin/${executable}`,
    `/usr/local/go/bin/${executable}`,
    `/usr/bin/${executable}`,
  ];

  for (const candidate of candidates) {
    const trusted = await isTrustedExecutable(workspaceRoot, candidate);
    if (trusted) return trusted;
  }
  return null;
}

export function createScannerContext(workspaceRoot: string): PreFlightContext {
  return {
    workspaceRoot,
    resolveTool: async () => null,
    resolveTrustedTool: (binName) =>
      resolveTrustedScannerTool(workspaceRoot, binName),
    async runCommand(
      command: string,
      args: string[],
      cwd = workspaceRoot,
      timeoutMs = 120_000,
    ): Promise<CommandResult> {
      try {
        const { stdout, stderr } = await execFileAsync(command, args, {
          cwd,
          timeout: timeoutMs,
          maxBuffer: 16 * 1024 * 1024,
        });
        return { stdout, stderr, code: 0 };
      } catch (error: unknown) {
        const result = error as {
          code?: number | string;
          killed?: boolean;
          signal?: string;
          stderr?: string;
          stdout?: string;
        };
        const timedOut =
          result.killed ||
          result.code === "ETIMEDOUT" ||
          result.signal === "SIGTERM";
        return {
          stdout: result.stdout ?? "",
          stderr: timedOut ? "Command timed out." : (result.stderr ?? ""),
          code: typeof result.code === "number" ? result.code : 1,
        };
      }
    },
  };
}
