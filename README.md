# WEBCAT CLI

Utilities for creating, validating, and packaging WEBCAT enrollments and manifests.
## Quick Start

This utility, together with the GitHub Actions provided in the same repository, can be used to quickly integrate and enroll a web application or domain into WEBCAT. Below are the recommended steps.

## Prepare the web application for compatibility

Before anything else, you should evaluate whether your website or web application is compatible with WEBCAT. There are a few strict requirements:

* The frontend **must be fully static** (i.e., no server-generated HTML, JavaScript, or CSS).
* **No inline JavaScript** is allowed.
* A **Content Security Policy (CSP)** must be provided via an HTTP header and must satisfy specific constraints (see: [CSP Guide](https://github.com/freedomofpress/webcat/blob/main/docs/DeveloperGuide.md), [explanation blog post](https://securedrop.org/news/webcat-towards-auditable-web-application-runtimes/)).

See the following examples and porting guides (outdated):
 - [Cryptpad](https://github.com/freedomofpress/webcat/tree/main/apps/cryptpad)
 - [Element](https://github.com/freedomofpress/webcat/tree/main/apps/element)
 - [Globaleaks](https://github.com/freedomofpress/webcat/tree/main/apps/globaleaks)
 - [Jitsi](https://github.com/freedomofpress/webcat/tree/main/apps/jitsi)

At the end, you should have compiled a `webcat.config.json` base file for your use case.

Quick yes-or-no check of a candidate policy, with the extension's own validator, and a
hinter that explains each incompatibility with the documented workaround and proposes the
nearest policy that passes. It accepts a policy string or a page URL to read the policy from:

```sh
webcat csp check "default-src 'none'; script-src 'self'; style-src 'self'"
webcat csp hint "default-src 'self'; script-src 'self' https://cdn.example 'unsafe-inline'"
webcat csp hint https://example.org/
```

## Decide and prepare enrollment information

A WEBCAT manifest describes a web application by listing its files, cryptographic hashes, CSP policies, and additional metadata useful for auditability. But how is this information verified?

Manifests are authenticated using either **Sigsum** or **Sigstore** signatures. The metadata required to validate these signatures or attestations must be **registered beforehand** with WEBCAT’s distributed validation system.

Changes to enrollment information are:

* Transparently logged
* Auditable
* Subject to a delay (cool-down window)

Keep this in mind: if you make a mistake, you may need to wait before updating the enrollment again.

The first decision you must make is whether to use **Sigsum** or **Sigstore**.

### Choosing Sigsum

[Sigsum](https://www.sigsum.org/), developed by [Glasklar Teknik](https://www.glasklarteknik.se/), provides:

* Compact Ed25519 signatures
* Easy offline signing
* Threshold signing support in WEBCAT

You can choose among multiple transparency logs and witness policies, or even run your own witness if you want to define your own trust roots.

Sigsum is generally the better choice if:

* You want offline, manual signing
* You do not want to depend on GitHub or other centralized infrastructure

However, due to current tooling limitations, Sigsum is less convenient for fully automated deployment workflows.

To learn more about Sigsum and how to write a policy, see Sigsum's [_Getting Started_](https://www.sigsum.org/getting-started/) guide.

### Choosing Sigstore

If you choose Sigstore, signing happens in CI with the workflow's own identity, so no key
material is stored anywhere. This guide assumes the Sigstore [_Public Good_ instance](https://openssf.org/blog/2023/10/03/running-sigstore-as-a-managed-service-a-tour-of-sigstores-public-good-instance/),
the same one used by GitHub and public container registries.

> [!WARNING]
> Sigstore support is still a work in progress. Claim-based enrollment constraints are supported.

Enroll once, naming the workflow that will sign. The identity is the workflow file and the
ref that runs it; a leading `^` makes the claim a prefix, so `@refs/tags/` covers every release
tag and no new enrollment is needed per release. `init` and `enrollment create` add the `^`
when an identity ends in `@refs/tags/` or `@refs/heads/`. For a GitHub Actions workflow `init`
pins what the enrolled sites converged on: the workflow on its ref prefix (build signer URI),
the repository (source repository URI), the ref prefix (source repository ref), the hosted
runner, and the issuer. Any other identity is pinned by SAN and issuer:

```sh
webcat init --type sigstore \
  --origin https://example.org \
  --identity '^https://github.com/acme/repo/.github/workflows/webcat-release.yml@refs/tags/' \
  --issuer https://token.actions.githubusercontent.com
```

Then have that workflow run `webcat release` on every tag; see [Releasing from CI](#releasing-from-ci).

`manifest sign` checks the enrollment before requesting a certificate and fails the job with
exit 2 if the enrollment's pinned trusted root can no longer verify new signatures. When that
happens, re-run `init` (or `enrollment create --community-trusted-root`) to refresh the root,
then `enrollment submit` so the chain records the new enrollment.

## Using the CLI

### If you are using Sigsum

Take a look at [`demo.sh`](./demo.sh) or the [end-to-end example] below.

[end-to-end example]: #end-to-end-example-based-on-demosh

### If you are using Sigstore

See the CI job above; every step is a plain CLI invocation.

## Requirements

- Node.js 22 or newer.
- `sigsum-submit` must be available on your `$PATH` for `manifest sign` operations. (See the [installation instructions][#installation] below.)
- A Sigsum trust policy and keypair for signing manifests.
- An OIDC identity token in the environment (CI-supported) or interactive login for `manifest sign --type sigstore`.

## Installation

```sh
npm install -g @freedomofpress/webcat-cli
```

This puts `webcat` on the PATH:

```sh
webcat --help
webcat --version
```

Informational messages are written to stderr, so command output (JSON, hashes) can be
piped or redirected directly when `--output` is omitted.

Sigsum needs to be installed separately, as it currently is only available in Go binaries:

```
go install sigsum.org/sigsum-go/cmd/sigsum-key@latest
go install sigsum.org/sigsum-go/cmd/sigsum-submit@latest
```

By default, these binaries will be available in `$HOME/go/bin`.

For development, the flake bundles the CLI with the sigsum-go tools it shells out to:

```sh
nix profile install github:freedomofpress/webcat-cli#toolchain   # webcat, sigsum-key, sigsum-submit
nix run github:freedomofpress/webcat-cli -- --help               # or run once, without installing
nix develop                                                      # dev shell for working on the CLI
```

## Getting started

`init` offers two built-in Sigsum policies: `test` (the Sigsum test logs, no rate limiting)
and `production` (`sigsum-generic-2025-1`, logs and witnesses vetted by the Sigsum project).
Production logs rate-limit submissions per domain: `init` generates `keys/token` and prints
the `_sigsum_v1.<domain>` TXT record to publish, and the `manifest sign` flags that use it
(`--token-signing-key keys/token --token-domain <domain>`).

### Hardware keys and ssh-agent

`sigsum-submit` signs through the SSH agent when it is given a public key instead of a private
one, which is how YubiKeys and other tokens holding an ed25519 key are used. Pass the `.pub`
everywhere a key is expected: `init --keys 0 --signer ~/.ssh/webcat.pub`,
`manifest sign -k ~/.ssh/webcat.pub`, `--token-signing-key token.pub`. The key must be a plain
ed25519 key (FIDO2 `sk-ed25519` keys produce a different signature format and do not work).

`init` asks the few things a site needs (origin, Sigsum or Sigstore, a CSP preset, signer keys
or a signing identity), writes `webcat.config.json`, a Sigsum `trust_policy`, and
`.well-known/webcat/enrollment.json`, and prints the next steps. Every answer is also a flag,
so it runs unattended in CI:

```sh
webcat init
webcat init --origin https://example.org --signer <hex pubkey>
webcat init --origin https://example.org --type sigstore --identity you@example.org --issuer https://accounts.google.com
```

## Enrollment helpers

The `enrollment` namespace manages Sigsum or Sigstore enrollment payloads. Sigsum enrollments
are the default; use `--type sigstore` along with Sigstore claim constraints (`--claim`
and/or compatibility flags `--issuer` + `--identity`) and either `--trusted-root` or
`--community-trusted-root` to build Sigstore enrollments. Either way the legacy Rekor v1 log
(`rekor.sigstore.dev`) is removed from the pinned trusted root: manifests signed for such an
enrollment must be logged to Rekor v2, and a Rekor v1 entry alone does not verify. Pass
`--keep-rekor-v1` to leave it in, for example to keep signing with `--rekor-api-version 1`; `init`
takes the same flag. Existing enrollments are not affected and report no drift for the log they
still trust.

| Command | Purpose |
| --- | --- |
| `enrollment create` | Compile a Sigsum policy file and create a normalized enrollment JSON document. |
| `enrollment canonicalize` | Canonicalize an enrollment JSON document using canonical JSON rules. |
| `enrollment hash` | Canonicalize and SHA-256 hash an enrollment, outputting a base64url digest. |
| `enrollment submit` | Ask the WEBCAT oracles to observe the enrollment a domain serves. |
| `enrollment status` | Show a domain's served, on-chain, and published enrollment hashes. |

Example – hash the sample enrollment definition:

```sh
webcat enrollment hash -i examples/enrollment.json
# => sMShxw62oTUjfzQ35Q5WOnQria1sXHMdI3e9lqODk6c
```

The canonicalized document (useful for audits) can be produced with:

```sh
webcat enrollment canonicalize -i examples/enrollment.json
```

Sigstore enrollment example with claims (legacy `--identity` and `--issuer` are mapped to claims):

```sh
webcat enrollment create \
  --type sigstore \
  --community-trusted-root \
  --identity alice@example.com \
  --issuer https://token.actions.githubusercontent.com \
  --build-signer-uri '^https://github.com/acme/repo/.github/workflows/webcat-release.yml@refs/tags/' \
  --claim 1.3.6.1.4.1.57264.1.11=platform-hosted \
  --max-age 3600
```

### Migrating an existing site

Enrollments and manifests gained a schema field (spec server.md and manifest.md). Extension 3.3.0
accepts both generations; a later release will set a minimum and reject the old one. There is
nothing to run on purpose: the commands a release already goes through migrate as they go.

1. In `webcat.config.json`: drop `app`; add `source`, `artifact`, `directory` and `origin`
   (the site's https origin); make `version` a semantic version, or remove it and tag releases.
   `clean_urls: true` if the host serves `/page.html` at `/page` too.
2. Move the enrollment to `.well-known/webcat/enrollment.json` if it lives elsewhere; it and
   the `.well-known/webcat/` directory belong in the repository.
3. Fix the policy if `csp hint` rejects it; extension 3.3.0 requires a `sandbox` directive on a
   policy that can frame another origin.
4. Tag and run `webcat release`, by hand or from the CI job `init` writes. The first
   release inherits the history from the previous tag's archive when `artifact` points at one,
   even one made by the old CLI, else from what `origin` serves today, so the manifest served
   now stays in the history and the old bundle becomes `bundle-prev.json`.
5. Deploy, then `webcat enrollment submit <domain>`: the enrollment hash changed, and the chain
   must record it. `site check` and `audit` confirm what visitors and auditors see.

- `manifest generate` writes schema 1 from the same `webcat.config.json`; `manifest sign`
  migrates an unsigned schema 0 manifest before signing. Either verifies under the existing
  enrollment, old or new.
- `bundle create` (and so `release`) writes the enrollment as schema 1 (no `cas_url`). Nothing
  signatures depend on changes, so the signed manifest keeps verifying and no re-signing is
  needed. The hash does change: the previous bundle is kept as `bundle-prev.json`, so serve both
  and run `enrollment submit <domain>` for the chain to record the new hash.

### Submitting and checking an enrollment

Once `enrollment.json` is served at `https://<domain>/.well-known/webcat/enrollment.json`,
ask the network's oracles to observe it. Each oracle hands out a small proof-of-work
challenge, fetches the file itself, and votes for its hash on the enrollment chain; after a
quorum and a cool-down delay the hash becomes canonical and appears in the published list.

```sh
webcat enrollment submit example.com -e enrollment.json   # -e checks the served file matches
webcat enrollment status example.com
```

`enrollment status` prints the hash the domain serves, what the chain holds (canonical,
pending, and live oracle votes), and the entry in the published list. Hashes are hex
`sha256` of the canonical enrollment, the same value `enrollment hash` prints in base64url.
`enrollment submit` refuses to run when the domain serves no enrollment unless `--unenroll`
is given, because oracles would then vote to remove the domain. `--dry-run` performs every
check and the proof of work without submitting. `--chain-api` and `--oracle` point at other
infrastructure.

## Manifest helpers

`manifest generate` writes a schema 1 manifest (`manifest_schema: 1`, spec manifest.md): directory
keys in `files`, `fallback_hashes`, optional `source` and `artifact`, and none of `app`,
`default_index` or `default_fallback`. It is hashed under RFC 8785 (JCS), as extension 3.3.0 does,
and verifies under any enrollment, schema 1 or older. Extensions from 3.2.0 accept it; older ones
do not. Manifests without `manifest_schema` keep verifying under the OLPC hash they were signed with.

The `manifest` namespace operates on WEBCAT manifests:

| Command | Purpose |
| --- | --- |
| `manifest generate` | Scan a directory of static assets, apply a manifest config, and embed a timestamp for `--type sigsum` (Sigsum log); sigstore manifests omit timestamps. |
| `manifest sign` | Sign a manifest with Sigsum (default) or Sigstore and attach proofs/bundles. |
| `manifest canonicalize` | Canonicalize an existing manifest JSON document. |
| `manifest hash` | Canonicalize and SHA-256 hash a manifest, outputting a base64url digest. |
| `manifest verify` | Verify a manifest (or bundle) against its enrollment: Sigsum signer threshold, or Sigstore bundles against the enrollment claims and trusted root. Exits 1 on failure. |

`manifest generate` skips dotfiles and dotfolders by default; pass `--include-dotfiles` to include them. It also
skips what `init` writes next to the site (`webcat.config.json`, `trust_policy`, `keys/`) and its own config and
output files when they are inside the directory. Use `--exclude <path>` (repeatable) to omit anything else.

Example – hash the provided manifest:

```sh
webcat manifest hash -i examples/manifest.json
# => KC20rk9wEouC18wkosAM2I7-ANnIxdBNTw6NibRGh88
```

Example – verify a bundle, or an enrollment plus a signed manifest:

```sh
webcat manifest verify examples/bundle.json
webcat manifest verify --enrollment enrollment.json --manifest manifest.json
```

Verification, and all enrollment, manifest and CSP validation, is done by
[`@freedomofpress/webcat`](https://www.npmjs.com/package/@freedomofpress/webcat), the
browser extension's own code, so the CLI accepts exactly what browsers accept. Failures
are reported with the extension's error codes (`ERR_WEBCAT_...`), for example an expired
manifest is `ERR_WEBCAT_MANIFEST_EXPIRED`. A successful verification prints the time until
which the manifest stays valid. The `examples/` bundle was signed against the Sigsum test
logs with throwaway keys and expires after a year; regenerate it with `demo.sh` when it does.

`manifest sign` reads the enrollment (default `.well-known/webcat/enrollment.json`) and signs
for it: a key that is not an enrolled signer or a policy that does not compile to the
enrollment's is refused before anything is submitted to a log, and the result is verified
with the extension's own verifier before it is written, reporting how many of the required
signatures are present.

### Sigstore signing

Sigstore signing defaults to the community Fulcio, Rekor v2 (`log2025-1.rekor.sigstore.dev`)
and timestamp authority (`timestamp.sigstore.dev`) services. Rekor v2 entries carry no
integrated time, so a TSA timestamp is always requested with them. You can override the
endpoints with `--fulcio-url`, `--rekor-url`, and `--tsa-url`, or pass `--rekor-api-version 1`
to log to the legacy `rekor.sigstore.dev` instead (no TSA unless `--tsa-url` is given). Rekor v1
is only useful with a hand-made trusted root that still lists it; enrollments created by
`enrollment create` do not trust it.

To sign with Sigstore using an ambient OIDC token (for example, in CI):

```sh
webcat manifest sign \
  --type sigstore \
  --input manifest.json
```

If you already have an OIDC ID token, you can pass it explicitly:

```sh
webcat manifest sign \
  --type sigstore \
  --input manifest.json \
  --oidc-token "$OIDC_ID_TOKEN"
```

To perform an interactive device authorization flow (opens a browser and prompts for a code):

```sh
webcat manifest sign \
  --type sigstore \
  --input manifest.json \
  --interactive
```

To use custom Sigstore infrastructure:

```sh
webcat manifest sign \
  --type sigstore \
  --input manifest.json \
  --fulcio-url https://fulcio.example.com \
  --rekor-url https://rekor.example.com \
  --tsa-url https://tsa.example.com \
  --oidc-issuer https://oauth2.example.com/auth \
  --oidc-client-id example-client \
  --interactive
```

`enrollment status` reads the published list the way the extension does: it fetches
`block.json` alongside `list.json`, verifies the block commit against the chain's validator
set and chain id shipped with the extension, and checks the leaves prove into the block's app
hash before reporting what the list says.

For Sigstore enrollments, `enrollment status` and `site check` compare the enrollment's pinned
trusted root with the current community root and warn when a certificate authority, log or
timestamp authority has been added or given an end date: that is the signal to re-enroll
before signing again.

## Site checks

`site check` fetches a deployed site the way the extension does and reports everything a
visitor's browser would reject: it verifies `bundle.json` (and `bundle-prev.json` if served),
compares the embedded enrollment with `enrollment.json` and the chain, then requests `/` and
every file in the manifest and checks the response for exactly one `content-security-policy`
header equal to the manifest's policy for that path, forbidden headers (`refresh`, `link`,
`origin-agent-cluster` other than `?1`), redirects, and the content hash.

```sh
webcat site check example.org
webcat site check example.org --path / --path /app/main.js
```

Exits 1 when the bundle does not verify, the enrollment does not match, or any path has a problem.

## Auditing a domain

`audit <domain>` runs the checks of the spec's auditors ([auditing.md](https://github.com/freedomofpress/webcat-spec))
from the outside, with nothing but what the domain serves:

- `bundle.json` and `bundle-prev.json` verified like the extension does;
- `enrollment.<hash>.json` for every hash the chain or the bundles name, hashing to its name;
- `manifest.<type>.<hash>.json` for every served manifest, equal to what the bundle serves;
- every release reachable from there: the tag on `source`, the `artifact` archive downloaded and
  every path in `files` hashed against the manifest, the well-known directory inside the archive
  consistent, and every hash-named file it carried still served unchanged. The archives are
  walked backwards, since each one carries the directory of its time, until the first release.

```sh
webcat audit example.org                       # exit 1 when anything above fails
webcat audit example.org --repro               # plus how to rebuild each release from its source
webcat audit example.org --version 1.4.0 --built dist   # compare a local build with that release's manifest
```

`--built` is the reproducibility check of manifest.md section 2.2: build the release from
`source` at its tag, then compare the output with the manifest. The build recipe itself is not
yet specified.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | The command ran and the answer is negative: `manifest verify` did not pass |
| 2 | Invalid input: fix the command line or the file named in the error |
| 3 | External failure: a network service, the `sigsum-*` tools, or the environment |

Errors are printed to stderr as `Error: <message>`. Messages name the CLI flag (`--max-age`) or the JSON path from the file root (`enrollment.max_age`, `config.app`) they refer to.

## Bundle helpers

`bundle create` publishes a signed manifest into the well-known directory: `bundle.json`, the
hash-named manifest file, each fallback under `hashes/`, and the previous bundle as
`bundle-prev.json` when the enrollment changed. With `-o` it only writes the bundle:

```sh
webcat bundle create -e examples/enrollment.json -m examples/manifest.json -o bundle.json
```

### History and releases

`.well-known/webcat/` is the site's append-only history and the directory auditors read
([spec, server.md section 1](https://github.com/freedomofpress/webcat-spec)). The CLI writes
into it and never rewrites a hash-named file:

| File | Written by |
|------|-----------|
| `enrollment.json`, `enrollment.<hash>.json` | `init`, `enrollment create -o` |
| `bundle.json`, `manifest.sigsum.<checksum>.json` or `manifest.sigstore.<hash>.json` | `bundle create` |
| `bundle-prev.json` | `bundle create`, when the enrollment changed since the previous bundle |
| `hashes/<hash>` | `bundle create`, one per `fallback_hashes` entry, copied from the built site (`--directory`, or `directory` in the config) |

The history travels with the releases, not with git. The archive `release` writes, the one the
`artifact` URL serves for the version, is the web root with `.well-known/webcat/` inside. The
next `release` downloads the archive of the previous tag, checks every file in it against the
manifest it ships and every hash-named file against its name, and only then copies the
directory in and adds the new release on top. Each release thereby proves the previous one was
what it claimed before building on it, and a single archive carries the whole history. A
missing or mismatching archive stops the release; `--no-history` overrides, and loses
everything before this release for every later one. `history inherit <archive-url>` does the
same step on its own.

Sites that prefer to keep the directory in the repository can: `release --commit` and
`bundle create --commit` commit the written files, and `history check [ref]` verifies that every
hash-named file hashes to its name, that the current pointers match them, that every fallback
the manifest lists is under `hashes/`, and that nothing was modified or deleted since `ref`.

When `webcat.config.json` sets `source`, the manifest claims the files build from that
repository at tag `version`. Before anything is signed, `manifest generate` and `manifest sign`
both require HEAD to be that tag, the tag to exist on the `source` remote, and, under GitHub,
Forgejo or Gitea Actions, the job to have been started by that tag rather than a branch push;
`manifest sign` also requires a clean working tree. `--skip-git-checks` overrides all of it.
Without `version` in the config, the tag at HEAD is the version.

## Releasing from CI

A release is a tag. Work lands on branches as usual; when a commit is tagged, CI checks it out,
builds the site, runs `webcat release`, uploads the archive where the `artifact` URL resolves
and deploys the build directory with `.well-known/webcat/` inside. Nothing is pushed back to
the repository, so the job needs no write access to it. Two things the checkout must provide:
the tag at HEAD, which is the version, and the previous tag, from which the history is inherited,
so the clone must not be shallow.

`artifact` in `webcat.config.json` names where each release's archive lives, for example
`https://github.com/acme/site/releases/download/${version}/site-${version}.tar.gz`;
`release` writes `site-<version>.tar.gz` in the working directory for the job to upload.

`init` writes both jobs below into your repository for the forge `source` points at
(`.github/workflows/` on GitHub, `.forgejo/workflows/` on Codeberg and other Forgejo or Gitea
hosts), with your host, build directory and keys filled in, and never overwrites an existing
file. They are plain files you own: no reusable workflow from this repository is involved, so
the identity in your certificates is your own workflow and nothing here can break your release.
Pass `--no-workflows` to skip them. The same text, to copy by hand:

#### GitHub Actions, Sigstore

The job signs with its own identity; the `id-token` permission is what lets it obtain a
certificate. The enrollment names that workflow on any tag with a prefix claim, see
[above](#choosing-sigstore).

```yaml
# .github/workflows/webcat-release.yml
# Written by webcat init. A pushed tag is a release: build, sign, publish the archive, deploy.
# The clone must carry the tags: the tag at HEAD is the version, the previous tag is where the history is inherited from.
name: WEBCAT release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write     # the Sigstore identity the enrollment names
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm run build                          # must produce dist/
      - run: npm install -g @freedomofpress/webcat-cli@0.1.2
      - run: webcat release --type sigstore
      - run: gh release create "$GITHUB_REF_NAME" site-*.tar.gz --generate-notes
        env:
          GH_TOKEN: ${{ github.token }}
      - run: cp -r .well-known dist/
      # deploy dist/ as usual; webcat-verify.yml then checks what visitors and auditors see
```

#### Forgejo Actions, Sigsum

Sigsum signs with a key, so the job holds one as a secret, and production logs want the
rate-limit token key too (`init` generates both under `keys/`). Every signature the key makes
is public in the Sigsum logs; that, not the secrecy of the CI runner, is what keeps a stolen
key from going unnoticed. Forgejo Actions issue no OIDC identity, so Sigstore sites sign
elsewhere.

```yaml
# .forgejo/workflows/webcat-release.yml
# Written by webcat init. A pushed tag is a release: build, sign, publish the archive, deploy.
# The clone must carry the tags: the tag at HEAD is the version, the previous tag is where the history is inherited from.
name: WEBCAT release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  release:
    runs-on: docker
    container:
      image: node:22
    steps:
      - uses: https://code.forgejo.org/actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      - uses: https://code.forgejo.org/actions/setup-node@v4
        with:
          node-version: 22
      - uses: https://code.forgejo.org/actions/setup-go@v5
        with:
          go-version: stable
      - run: npm ci && npm run build                          # must produce dist/
      - run: npm install -g @freedomofpress/webcat-cli@0.1.2
      - run: go install sigsum.org/sigsum-go/cmd/sigsum-submit@latest && echo "$HOME/go/bin" >> "$GITHUB_PATH"
      - run: |
          install -m 600 /dev/stdin keys/key1 <<< "$SIGSUM_KEY"
          install -m 600 /dev/stdin keys/token <<< "$SIGSUM_TOKEN_KEY"
        env:
          SIGSUM_KEY: ${{ secrets.SIGSUM_KEY }}
          SIGSUM_TOKEN_KEY: ${{ secrets.SIGSUM_TOKEN_KEY }}
      - run: webcat release -k keys/key1 --token-signing-key keys/token --token-domain example.org
      - run: mkdir release && mv site-*.tar.gz release/
      - uses: https://code.forgejo.org/actions/forgejo-release@v2
        with:
          direction: upload
          release-dir: release
      - run: cp -r .well-known dist/
      # deploy dist/ as usual; webcat-verify.yml then checks what visitors and auditors see
```

#### Verifying the live site on a schedule

Deploys drift: a cache serves a stale file, a host setting changes a header. The second job
checks what visitors and auditors see every six hours and fails when anything is off.

```yaml
# .github/workflows/webcat-verify.yml
# Written by webcat init. Checks the live site the way the extension and the auditors do; a failure is a broken site.
name: WEBCAT verify
on:
  schedule:
    - cron: "17 */6 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g @freedomofpress/webcat-cli@0.1.2
      - run: webcat site check example.org
      - run: webcat audit example.org
```

## End-to-end example (based on `demo.sh`)

The repository includes [`demo.sh`](./demo.sh), which exercises the full workflow. The commands
below mirror that script so you can quickly test the CLI end to end:

```sh
# 1) Prepare demo keys
mkdir -p keys
sigsum-key generate -o keys/key1
sigsum-key generate -o keys/key2
HEX1=$(sigsum-key to-hex -k keys/key1.pub)
HEX2=$(sigsum-key to-hex -k keys/key2.pub)

# 2) Create trust policy and app config
cat > trust_policy <<'EOF'
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
EOF

cat > webcat.config.json <<'EOF'
{
  "source": "https://github.com/element-hq/element-web",
  "version": "1.12.3",
  "default_csp": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self'; frame-ancestors 'self'",
  "fallbacks": ["/error.html"],
  "wasm": ["8A7Ecx-qI7PnFNAOiNTRDi31wKQn06K0rm41Jv3RTvc"],
  "extra_csp": {}
}
EOF

# 3) Produce enrollment and manifest
TMPDIR=$(mktemp -d)
echo index > "$TMPDIR/index.html"
echo error > "$TMPDIR/error.html"

webcat enrollment create \
  --policy-file trust_policy \
  --threshold 1 \
  --max-age 15552000 \
  --signer "$HEX1" \
  --signer "$HEX2" \
  --output enrollment.json

webcat manifest generate \
  --policy-file trust_policy \
  --config webcat.config.json \
  --directory "$TMPDIR" \
  --output manifest_unsigned.json

webcat manifest sign \
  --policy-file trust_policy \
  -i manifest_unsigned.json \
  -k keys/key1 \
  -o manifest.json

# 4) Bundle and verify
webcat bundle create \
  --enrollment enrollment.json \
  --manifest manifest.json \
  --output bundle.json
webcat manifest verify bundle.json
```

The script prints intermediate JSON artifacts with `jq` so you can inspect the
resulting enrollment, manifest, and bundle.

## `webcat.config.json` schema

The manifest generator expects a Webcat config file (commonly `webcat.config.json`
or a JSON equivalent) matching the schema below:

| Field | Type | Description |
| --- | --- | --- |
| `source` | string | Optional. Git repository URL the site is built from; `version` must be a tag there. Auditors rebuild from it. |
| `artifact` | string | Optional. Release archive URL template containing `${version}`; auditors fetch it. |
| `version` | string | Semantic version of this release, such as `1.4.0`; a leading `v` is tolerated. Optional: without it the git tag at HEAD is the version. |
| `directory` | string | Optional. Where the build writes the site; `release` and `bundle create` read it. |
| `origin` | string | Optional. The site's https origin; `release` inherits the history from what it serves when no archive has it. |
| `clean_urls` | boolean | Optional. The host serves `/page.html` at `/page` too (Vercel, Netlify, Cloudflare Pages): both are listed. |
| `app` | string | Deprecated and ignored: manifests no longer carry it. |
| `default_csp` | string | Base Content-Security-Policy applied to all assets. |
| `default_index` | string | Optional, `index.html`. The file a directory path stands for: `/docs/` gets the hash of `/docs/index.html`. |
| `fallbacks` | string[] | Optional, `["/<default_index>"]`. Pages the extension also accepts at any path on a navigation: a SPA shell, a 404 page. Each is published at `/.well-known/webcat/hashes/<hash>` by `bundle create`, and `site check` warns when one is not served there. `default_fallback` (one path) is the pre-3.2.0 spelling and still accepted. |
| `wasm` | string[] | Optional list of base64url SHA-256 digests for inline WebAssembly modules. `.wasm` files are added automatically during generation. |
| `extra_csp` | Record<string, string> | Optional per-path CSP overrides; keys must start with `/`. | `{}` or `{ "/app": "default-src 'none'" }` |

Use the JSON example in the workflow above as a starting point and adjust fields
to match your application.
