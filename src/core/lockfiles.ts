import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { ChangedFile } from "../shared/preflight-api.js";

const SUPPORTED_LOCKFILES = new Set([
  "bun.lock",
  "composer.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "go.mod",
  "package-lock.json",
  "Pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pubspec.lock",
  "requirements.txt",
  "yarn.lock",
]);

export function isSupportedLockfile(path: string): boolean {
  return SUPPORTED_LOCKFILES.has(path.split("/").at(-1) ?? path);
}

export function changedLockfiles(files: ChangedFile[]): string[] {
  return files
    .filter(
      (file) => file.status !== "deleted" && isSupportedLockfile(file.path),
    )
    .map((file) => file.path);
}

function isInsideWorkspace(workspaceRoot: string, candidate: string): boolean {
  const workspaceRelative = relative(workspaceRoot, candidate);
  return (
    workspaceRelative !== "" &&
    workspaceRelative !== ".." &&
    !workspaceRelative.startsWith(`..${sep}`) &&
    !isAbsolute(workspaceRelative)
  );
}

export async function resolveWorkspaceFile(
  workspaceRoot: string,
  workspacePath: string,
): Promise<string | null> {
  const absolutePath = resolve(workspaceRoot, workspacePath);
  if (!isInsideWorkspace(workspaceRoot, absolutePath)) return null;

  try {
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) return null;

    const [realWorkspaceRoot, realFile] = await Promise.all([
      realpath(workspaceRoot),
      realpath(absolutePath),
    ]);
    return isInsideWorkspace(realWorkspaceRoot, realFile) ? realFile : null;
  } catch {
    return null;
  }
}

export function dockerWorkspacePath(workspacePath: string): string | null {
  if (
    workspacePath.startsWith("/") ||
    workspacePath.split("/").includes("..")
  ) {
    return null;
  }
  return `/workspace/${workspacePath}`;
}
