// CI jobs a site copies into its own repository, so the signing identity is the site's workflow and nothing here
// has to stay online for it. One template per CI system and signing type under templates/; init writes them.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { version as CLI_VERSION } from "../package.json";

export type Forge = "github" | "gitlab" | "forgejo";

// Where the remote lives decides the CI system: GitHub, GitLab, or Forgejo and Gitea (same syntax, their own actions).
export function forgeOf(source: string | undefined): Forge | null {
  try {
    const host = new URL(source ?? "").host;
    if (host === "github.com") return "github";
    if (/gitlab/.test(host)) return "gitlab";
    if (host === "codeberg.org" || /forgejo|gitea/.test(host)) return "forgejo";
    return null;
  } catch {
    return null;
  }
}

// The OIDC issuer the remote's CI signs with: GitHub Actions has one for everyone, a GitLab is its own, and Forgejo
// and Gitea Actions issue none.
export function ciIssuer(source: string | undefined): string | null {
  const forge = forgeOf(source);
  if (forge === "github") return "https://token.actions.githubusercontent.com";
  if (forge === "gitlab") return `https://${new URL(source!).host}`;
  return null;
}

// Whether the Sigstore CA certifies that issuer: asked from its live configuration, so a self-hosted GitLab the
// Sigstore project has added works without a CLI change. Offline, the two it has always had.
export async function sigstoreFromCi(source: string | undefined, fulcioUrl = "https://fulcio.sigstore.dev"): Promise<boolean> {
  const issuer = ciIssuer(source);
  if (!issuer) return false;
  try {
    const config = await (await fetch(`${fulcioUrl.replace(/\/+$/, "")}/api/v2/configuration`)).json();
    return (config.issuers as Array<{ issuerUrl?: string }>).some((i) => i.issuerUrl === issuer);
  } catch {
    return ["https://token.actions.githubusercontent.com", "https://gitlab.com"].includes(issuer);
  }
}

// {{name}} is a value; {{#name}}...{{/name}} is kept when the value is true, dropped otherwise (a whole line when alone on it).
export function render(template: string, vars: Record<string, string | boolean>): string {
  return template
    .replace(/^[ \t]*\{\{#(\w+)\}\}\n([\s\S]*?)^[ \t]*\{\{\/\1\}\}\n/gm, (_, name, body) => (vars[name] ? body : ""))
    .replace(/\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g, (_, name, body) => (vars[name] ? body : ""))
    .replace(/\{\{(\w+)\}\}/g, (_, name) => String(vars[name] ?? ""));
}

// dist/cli.cjs (CommonJS, __dirname) and src/ci.ts (ESM under tsx) both sit one level below the repository root.
const here = typeof __dirname === "string" ? __dirname : path.dirname(fileURLToPath(import.meta.url));
const TEMPLATES = path.join(here, "..", "templates");
const template = (forge: Forge, name: string): string => readFileSync(path.join(TEMPLATES, forge, `${name}.yml`), "utf8");

export interface CiOptions {
  forge: Forge;
  type: "sigsum" | "sigstore";
  host: string;
  directory: string;
  token: boolean; // a rate-limit token key for the production Sigsum logs
  artifact: boolean; // an archive to publish
  oidc: boolean; // the CI issues an identity the public Sigstore CA certifies (sigstoreFromCi)
}

// The files to write, relative to the repository root, with null for a release job the CI cannot run: Sigstore where
// the CI issues no identity the public CA certifies.
export function ciJobs(o: CiOptions): Array<[file: string, text: string | null]> {
  const vars = { host: o.host, directory: o.directory, cli_version: CLI_VERSION, token: o.token, artifact: o.artifact };
  const canSign = o.type === "sigsum" || o.oidc;
  switch (o.forge) {
    case "gitlab":
      return [[".gitlab-ci.yml", canSign ? render(template("gitlab", `ci-${o.type}`), vars) : null]];
    case "forgejo":
      return [
        [".forgejo/workflows/webcat-release.yml", canSign ? render(template("forgejo", `release-${o.type}`), vars) : null],
        [".forgejo/workflows/webcat-verify.yml", render(template("forgejo", "verify"), vars)],
      ];
    case "github":
      return [
        [".github/workflows/webcat-release.yml", render(template("github", `release-${o.type}`), vars)],
        [".github/workflows/webcat-verify.yml", render(template("github", "verify"), vars)],
      ];
  }
}
