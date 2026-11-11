// CI jobs a site copies into its own repository, so the signing identity is the site's workflow and nothing here
// has to stay online for it. Written by init; the README shows the same text.
import { version as CLI_VERSION } from "../package.json";

export type Forge = "github" | "forgejo";

// Where the remote lives decides the workflow syntax: GitHub, or Forgejo and Gitea (same syntax, their own actions).
export function forgeOf(source: string | undefined): Forge | null {
  try {
    const host = new URL(source ?? "").host;
    return host === "github.com" ? "github" : host === "codeberg.org" || /forgejo|gitea/.test(host) ? "forgejo" : null;
  } catch {
    return null;
  }
}

export const workflowDir = (forge: Forge): string => (forge === "github" ? ".github/workflows" : ".forgejo/workflows");

const actions = (forge: Forge) => (forge === "github" ? "" : "https://code.forgejo.org/");
const runner = (forge: Forge) => (forge === "github" ? "    runs-on: ubuntu-latest\n" : "    runs-on: docker\n    container:\n      image: node:22\n");

// The release job: a tag push builds, signs, publishes the archive the artifact URL points to, and deploys.
// Forgejo Actions issue no OIDC identity, so a Sigstore site on Forgejo signs elsewhere: returns null.
export function releaseWorkflow(o: { forge: Forge; type: "sigsum" | "sigstore"; host: string; directory: string; tokenKey: boolean; artifact: boolean }): string | null {
  if (o.forge === "forgejo" && o.type === "sigstore") return null;
  const a = actions(o.forge);
  const sign =
    o.type === "sigstore"
      ? "      - run: webcat release --type sigstore\n"
      : `      - run: go install sigsum.org/sigsum-go/cmd/sigsum-submit@latest && echo "$HOME/go/bin" >> "$GITHUB_PATH"
      - run: |
          install -m 600 /dev/stdin keys/key1 <<< "$SIGSUM_KEY"${o.tokenKey ? '\n          install -m 600 /dev/stdin keys/token <<< "$SIGSUM_TOKEN_KEY"' : ""}
        env:
          SIGSUM_KEY: \${{ secrets.SIGSUM_KEY }}${o.tokenKey ? "\n          SIGSUM_TOKEN_KEY: ${{ secrets.SIGSUM_TOKEN_KEY }}" : ""}
      - run: webcat release -k keys/key1${o.tokenKey ? ` --token-signing-key keys/token --token-domain ${o.host}` : ""}
`;
  const upload = !o.artifact
    ? ""
    : o.forge === "github"
      ? `      - run: gh release create "$GITHUB_REF_NAME" site-*.tar.gz --generate-notes
        env:
          GH_TOKEN: \${{ github.token }}
`
      : `      - run: mkdir release && mv site-*.tar.gz release/
      - uses: https://code.forgejo.org/actions/forgejo-release@v2
        with:
          direction: upload
          release-dir: release
`;
  return `# Written by webcat init. A pushed tag is a release: build, sign, publish the archive, deploy.
# The clone must carry the tags: the tag at HEAD is the version, the previous tag is where the history is inherited from.
name: WEBCAT release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write${o.type === "sigstore" ? "\n  id-token: write     # the Sigstore identity the enrollment names" : ""}
jobs:
  release:
${runner(o.forge)}    steps:
      - uses: ${a}actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      - uses: ${a}actions/setup-node@v4
        with:
          node-version: 22
${o.type === "sigsum" ? `      - uses: ${a}actions/setup-go@v5\n        with:\n          go-version: stable\n` : ""}      - run: npm ci && npm run build                          # must produce ${o.directory}/
      - run: npm install -g @freedomofpress/webcat-cli@${CLI_VERSION}
${sign}${upload}      - run: cp -r .well-known ${o.directory}/
      # deploy ${o.directory}/ as usual; webcat-verify.yml then checks what visitors and auditors see
`;
}

// The verify job: what visitors and auditors see, on a schedule, so drift and a stale cache are caught by the site itself.
export function verifyWorkflow(o: { forge: Forge; host: string }): string {
  const a = actions(o.forge);
  return `# Written by webcat init. Checks the live site the way the extension and the auditors do; a failure is a broken site.
name: WEBCAT verify
on:
  schedule:
    - cron: "17 */6 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
${runner(o.forge)}    steps:
      - uses: ${a}actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g @freedomofpress/webcat-cli@${CLI_VERSION}
      - run: webcat site check ${o.host}
      - run: webcat audit ${o.host}
`;
}
