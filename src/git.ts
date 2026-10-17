// Thin git wrappers. Every reader returns null when git is unavailable or the answer does not exist,
// so callers can fall back to asking; writers fail loudly.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { causeOf, external } from "./utils.js";

const execFileAsync = promisify(execFile);

async function git(args: string[], cwd?: string): Promise<string | null> {
  try {
    return (await execFileAsync("git", args, { cwd })).stdout.trim();
  } catch {
    return null;
  }
}

export const gitRoot = (cwd?: string): Promise<string | null> => git(["rev-parse", "--show-toplevel"], cwd);
// The origin remote as a URL with a protocol, as the spec wants for `source`: scp-like git@host:path becomes ssh://.
export const gitRemote = async (cwd?: string): Promise<string | null> => {
  const url = await git(["remote", "get-url", "origin"], cwd);
  const scp = url?.match(/^([^@/:]+@[^:/]+):(.+)$/);
  return scp ? `ssh://${scp[1]}/${scp[2]}` : url;
};
export const gitTagAtHead = (cwd?: string): Promise<string | null> => git(["describe", "--tags", "--exact-match", "HEAD"], cwd);
export const gitTagExists = async (tag: string, cwd?: string): Promise<boolean> => (await git(["rev-parse", "--verify", "--quiet", `refs/tags/${tag}`], cwd)) !== null;
export const gitLatestTag = (cwd?: string): Promise<string | null> => git(["describe", "--tags", "--abbrev=0"], cwd);
// Tracked files with uncommitted changes (untracked files are not a reproducibility problem).
export const gitDirtyFiles = async (cwd?: string): Promise<string[]> => ((await git(["status", "--porcelain", "--untracked-files=no"], cwd)) ?? "").split("\n").filter(Boolean);
// "M path" / "D path" / "A path" lines for a directory between a ref and the working tree.
export const gitChangedSince = async (ref: string, dir: string, cwd?: string): Promise<Array<[status: string, path: string]>> =>
  ((await git(["diff", "--name-status", "--no-renames", ref, "--", dir], cwd)) ?? "").split("\n").filter(Boolean).map((l) => l.split("\t") as [string, string]);

export async function gitStage(paths: string[], commitMessage?: string, cwd?: string): Promise<void> {
  try {
    await execFileAsync("git", ["add", "--", ...paths], { cwd });
    if (commitMessage) {
      await execFileAsync("git", ["commit", "-m", commitMessage, "--", ...paths], { cwd });
    }
  } catch (err) {
    throw external(`failed to run git: ${causeOf(err)}`);
  }
}
