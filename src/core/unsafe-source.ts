import type {
  CheckFinding,
  CheckResult,
  CheckRunner,
  GitDiff,
} from "../shared/preflight-api.js";

const DEPENDENCY_FILES = new Set([
  "bun.lock",
  "bun.lockb",
  "Cargo.lock",
  "composer.lock",
  "go.sum",
  "package.json",
  "package-lock.json",
  "Pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "requirements.txt",
  "yarn.lock",
]);

function isDependencyFile(path: string): boolean {
  return DEPENDENCY_FILES.has(path.split("/").at(-1) ?? path);
}

function isInsecureSource(line: string): boolean {
  return /(?:resolved|version|url|source)?[^\n]*\b(?:git\+)?http:\/\//i.test(
    line,
  );
}

function addedLines(rawPatch: string): Array<{
  file: string;
  line: number;
  content: string;
}> {
  const lines: Array<{ file: string; line: number; content: string }> = [];
  let file = "";
  let nextLine = 0;

  for (const patchLine of rawPatch.split("\n")) {
    if (patchLine.startsWith("+++ b/")) {
      file = patchLine.slice(6);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(patchLine);
    if (hunk) {
      nextLine = Number(hunk[1]);
      continue;
    }
    if (!file || nextLine === 0) continue;
    if (patchLine.startsWith("+") && !patchLine.startsWith("+++")) {
      lines.push({ file, line: nextLine, content: patchLine.slice(1) });
      nextLine += 1;
    } else if (!patchLine.startsWith("-")) {
      nextLine += 1;
    }
  }
  return lines;
}

export const dependencyUnsafeSourceCheck: CheckRunner = {
  id: "dependency-guard:unsafe-source",
  label: "Dependency Guard — Secure Sources",
  severity: "error",
  pack: "mewra-dependency-guard",

  appliesTo(diff: GitDiff): boolean {
    return diff.changedFiles.some((file) => isDependencyFile(file.path));
  },

  async run(diff: GitDiff): Promise<CheckResult> {
    const findings: CheckFinding[] = addedLines(diff.rawPatch)
      .filter(
        (line) => isDependencyFile(line.file) && isInsecureSource(line.content),
      )
      .map((line) => ({
        file: line.file,
        line: line.line,
        message:
          "Dependency source uses insecure HTTP. Use HTTPS or a trusted registry.",
        rule: "dependency-guard:unsafe-source",
      }));

    return findings.length > 0
      ? {
          status: "fail",
          findings,
          message: `${findings.length} insecure dependency source${findings.length === 1 ? "" : "s"} found.`,
        }
      : {
          status: "pass",
          findings: [],
          message:
            "Changed dependency sources use HTTPS or local package references.",
        };
  },
};
