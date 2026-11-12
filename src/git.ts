// Thin git wrappers. Every reader returns null when git is unavailable or the answer does not exist,
// so callers can fall back to asking; writers fail loudly.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { causeOf, external, invalid } from "./utils.js";

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
// The release before the one HEAD is tagged with: the nearest tag reachable from HEAD's parent.
export const gitPreviousTag = (cwd?: string): Promise<string | null> => git(["describe", "--tags", "--abbrev=0", "HEAD^"], cwd);
// Tracked files with uncommitted changes (untracked files are not a reproducibility problem).
export const gitDirtyFiles = async (cwd?: string): Promise<string[]> => ((await git(["status", "--porcelain", "--untracked-files=no"], cwd)) ?? "").split("\n").filter(Boolean);
// "M path" / "D path" / "A path" lines for a directory between a ref and the working tree.
export const gitChangedSince = async (ref: string, dir: string, cwd?: string): Promise<Array<[status: string, path: string]>> =>
  ((await git(["diff", "--name-status", "--no-renames", ref, "--", dir], cwd)) ?? "").split("\n").filter(Boolean).map((l) => l.split("\t") as [string, string]);

// Whether `tag` exists on the remote at `url`; null when the remote cannot be listed.
export const gitRemoteTagExists = async (url: string, tag: string, cwd?: string): Promise<boolean | null> => {
  const out = await git(["ls-remote", "--tags", url, `refs/tags/${tag}`], cwd);
  return out === null ? null : out.length > 0;
};

// A manifest with source claims the files build from the repository at tag `version` (spec manifest.md). Before
// anything is signed: HEAD is that tag, the tag is on the source remote, and a CI job runs for that tag.
export async function assertReleaseTag(version: string, source: string, env: NodeJS.ProcessEnv = process.env, cwd?: string): Promise<void> {
  const tag = await gitTagAtHead(cwd);
  if (tag !== version) {
    const exists = await gitTagExists(version, cwd);
    throw invalid(
      `config.version ${version} must be the git tag at HEAD because config.source is set (HEAD is ${tag ? `tagged ${tag}` : "not tagged"}${exists ? "" : `, and no tag ${version} exists`}); tag the release or pass --skip-git-checks`,
    );
  }
  const remote = await gitRemoteTagExists(source, version, cwd);
  if (remote === null) throw invalid(`cannot list the tags of ${source} to confirm ${version} is there; check the source URL and network, or pass --skip-git-checks`);
  if (!remote) throw invalid(`tag ${version} is not on ${source}; push the tag before releasing (or pass --skip-git-checks)`);
  // GitHub, Forgejo and Gitea Actions: a release job must have been started by that tag, not by a branch push.
  if (env.GITHUB_REF_TYPE && (env.GITHUB_REF_TYPE !== "tag" || env.GITHUB_REF_NAME !== version)) {
    throw invalid(`this job runs on ${env.GITHUB_REF_TYPE} ${env.GITHUB_REF_NAME}, not on tag ${version}; release from the tag push (or pass --skip-git-checks)`);
  }
}

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
