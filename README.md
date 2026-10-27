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
npx webcat csp check "default-src 'none'; script-src 'self'; style-src 'self'"
npx webcat csp hint "default-src 'self'; script-src 'self' https://cdn.example 'unsafe-inline'"
npx webcat csp hint https://example.org/
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

Enroll once, naming the workflow that will sign (the identity is the workflow file at the
branch that runs it):

```sh
npx webcat init --type sigstore \
  --origin https://example.org \
  --identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main \
  --issuer https://token.actions.githubusercontent.com
```

Then have that workflow call the CLI directly. The `id-token` permission is what lets the job
obtain a Sigstore certificate for its identity:

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm run build                      # produces dist/
      - run: npx @freedomofpress/webcat-cli manifest generate --type sigstore -d dist -o manifest.json
      - run: npx @freedomofpress/webcat-cli manifest sign --type sigstore -o manifest.signed.json
      - run: npx @freedomofpress/webcat-cli bundle create -o dist/.well-known/webcat/bundle.json
      - run: cp .well-known/webcat/enrollment.json dist/.well-known/webcat/
      # deploy dist/ as usual; keep the previous bundle.json as bundle-prev.json across enrollment changes
```

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
npm install @freedomofpress/webcat-cli
```

To run the installed CLI:

```sh
npx webcat --help
npx webcat --version
```

Informational messages are written to stderr, so command output (JSON, hashes) can be
piped or redirected directly when `--output` is omitted.

Sigsum needs to be installed separately, as it currently is only available in Go binaries:

```
go install sigsum.org/sigsum-go/cmd/sigsum-key@latest
go install sigsum.org/sigsum-go/cmd/sigsum-submit@latest
```

By default, these binaries will be available in `$HOME/go/bin`.

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

### Content-addressable storage (`cas_url`)

A Sigsum enrollment names a `cas_url`. Each `manifest sign` writes two objects under `./cas/`,
named by their SHA-256: the submitted message (the manifest's SHA-256) and the canonical manifest.
A log entry's checksum is the SHA-256 of the message, so an auditor fetches `cas_url/<checksum>`
to get the message and `cas_url/<sha256 of message>` to get the manifest; the site must serve the
`cas/` directory at `cas_url` as static files (any https URL you control works, for example
`https://example.org/cas/`). With `WEBCAT_CAS_S3_ENDPOINT`, `WEBCAT_CAS_S3_BUCKET` and
`WEBCAT_CAS_S3_TOKEN` set, `manifest sign` also uploads them to an S3-compatible bucket.

`init` asks the few things a site needs (origin, Sigsum or Sigstore, a CSP preset, signer keys
or a signing identity), writes `webcat.config.json`, a Sigsum `trust_policy`, and
`.well-known/webcat/enrollment.json`, and prints the next steps. Every answer is also a flag,
so it runs unattended in CI:

```sh
npx webcat init
npx webcat init --origin https://example.org --signer <hex pubkey> --cas-url https://example.org/cas/
npx webcat init --origin https://example.org --type sigstore --identity you@example.org --issuer https://accounts.google.com
```

## Enrollment helpers

The `enrollment` namespace manages Sigsum or Sigstore enrollment payloads. Sigsum enrollments
are the default; use `--type sigstore` along with Sigstore claim constraints (`--claim`
and/or compatibility flags `--issuer` + `--identity`) and either `--trusted-root` or
`--community-trusted-root` to build Sigstore enrollments.

| Command | Purpose |
| --- | --- |
| `enrollment create` | Compile a Sigsum policy file and create a normalized enrollment JSON document. |
| `enrollment canonicalize` | Canonicalize an enrollment JSON document using canonical JSON rules. |
| `enrollment hash` | Canonicalize and SHA-256 hash an enrollment, outputting a base64url digest. |
| `enrollment submit` | Ask the WEBCAT oracles to observe the enrollment a domain serves. |
| `enrollment status` | Show a domain's served, on-chain, and published enrollment hashes. |

Example – hash the sample enrollment definition:

```sh
npx webcat enrollment hash -i examples/enrollment.json
# => sMShxw62oTUjfzQ35Q5WOnQria1sXHMdI3e9lqODk6c
```

The canonicalized document (useful for audits) can be produced with:

```sh
npx webcat enrollment canonicalize -i examples/enrollment.json
```

Sigstore enrollment example with claims (legacy `--identity` and `--issuer` are mapped to claims):

```sh
npx webcat enrollment create \
  --type sigstore \
  --community-trusted-root \
  --identity alice@example.com \
  --issuer https://token.actions.githubusercontent.com \
  --build-signer-uri https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main \
  --claim 1.3.6.1.4.1.57264.1.11=platform-hosted \
  --max-age 3600
```

### Submitting and checking an enrollment

Once `enrollment.json` is served at `https://<domain>/.well-known/webcat/enrollment.json`,
ask the network's oracles to observe it. Each oracle hands out a small proof-of-work
challenge, fetches the file itself, and votes for its hash on the enrollment chain; after a
quorum and a cool-down delay the hash becomes canonical and appears in the published list.

```sh
npx webcat enrollment submit example.com -e enrollment.json   # -e checks the served file matches
npx webcat enrollment status example.com
```

`enrollment status` prints the hash the domain serves, what the chain holds (canonical,
pending, and live oracle votes), and the entry in the published list. Hashes are hex
`sha256` of the canonical enrollment, the same value `enrollment hash` prints in base64url.
`enrollment submit` refuses to run when the domain serves no enrollment unless `--unenroll`
is given, because oracles would then vote to remove the domain. `--dry-run` performs every
check and the proof of work without submitting. `--chain-api` and `--oracle` point at other
infrastructure.

## Manifest helpers

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
npx webcat manifest hash -i examples/manifest.json
# => KC20rk9wEouC18wkosAM2I7-ANnIxdBNTw6NibRGh88
```

Example – verify a bundle, or an enrollment plus a signed manifest:

```sh
npx webcat manifest verify examples/bundle.json
npx webcat manifest verify --enrollment enrollment.json --manifest manifest.json
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

Sigstore signing defaults to the community Fulcio/Rekor services. You can override the
endpoints with `--fulcio-url`, `--rekor-url`, and `--tsa-url` when signing.

To sign with Sigstore using an ambient OIDC token (for example, in CI):

```sh
npx webcat manifest sign \
  --type sigstore \
  --input manifest.json
```

If you already have an OIDC ID token, you can pass it explicitly:

```sh
npx webcat manifest sign \
  --type sigstore \
  --input manifest.json \
  --oidc-token "$OIDC_ID_TOKEN"
```

To perform an interactive device authorization flow (opens a browser and prompts for a code):

```sh
npx webcat manifest sign \
  --type sigstore \
  --input manifest.json \
  --interactive
```

To use custom Sigstore infrastructure:

```sh
npx webcat manifest sign \
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
npx webcat site check example.org
npx webcat site check example.org --path / --path /app/main.js
```

Exits 1 when the bundle does not verify, the enrollment does not match, or any path has a problem.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | The command ran and the answer is negative: `manifest verify` did not pass |
| 2 | Invalid input: fix the command line or the file named in the error |
| 3 | External failure: a network service, the `sigsum-*` tools, or the environment |

Errors are printed to stderr as `Error: <message>`. Messages name the CLI flag (`--max-age`) or the JSON path from the file root (`enrollment.max_age`, `config.app`) they refer to.

## Bundle helpers

Use `bundle create` to combine an enrollment and a manifest (with signatures) into a WEBCAT bundle that can be distributed to verifiers:

```sh
npx webcat bundle create -e examples/enrollment.json -m examples/manifest.json > bundle.json
```

The resulting `bundle.json` matches the fixture located in `examples/bundle.json`.

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
  "app": "https://github.com/element-hq/element-web",
  "version": "1.12.3",
  "default_csp": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self'; frame-ancestors 'self'",
  "default_index": "index.html",
  "default_fallback": "/error.html",
  "wasm": ["8A7Ecx-qI7PnFNAOiNTRDi31wKQn06K0rm41Jv3RTvc"],
  "extra_csp": {}
}
EOF

# 3) Produce enrollment and manifest
TMPDIR=$(mktemp -d)
echo index > "$TMPDIR/index.html"
echo error > "$TMPDIR/error.html"

npx webcat enrollment create \
  --policy-file trust_policy \
  --threshold 1 \
  --max-age 15552000 \
  --cas-url https://cas.demoelement.com \
  --signer "$HEX1" \
  --signer "$HEX2" \
  --output enrollment.json

npx webcat manifest generate \
  --policy-file trust_policy \
  --config webcat.config.json \
  --directory "$TMPDIR" \
  --output manifest_unsigned.json

npx webcat manifest sign \
  --policy-file trust_policy \
  -i manifest_unsigned.json \
  -k keys/key1 \
  -o manifest.json

# 4) Bundle and verify
npx webcat bundle create \
  --enrollment enrollment.json \
  --manifest manifest.json \
  --output bundle.json
npx webcat manifest verify bundle.json
```

The script prints intermediate JSON artifacts with `jq` so you can inspect the
resulting enrollment, manifest, and bundle.

## `webcat.config.json` schema

The manifest generator expects a Webcat config file (commonly `webcat.config.json`
or a JSON equivalent) matching the schema below:

| Field | Type | Description |
| --- | --- | --- |
| `app` | string | Origin URL of the application being packaged. |
| `version` | string | Git tag to be used for reproducibility and auditing. |
| `default_csp` | string | Base Content-Security-Policy applied to all assets. |
| `default_index` | string | Default index file served when a directory is requested; leading `/` is stripped automatically. |
| `default_fallback` | string | Absolute path served when a file is missing. |
| `wasm` | string[] | Optional list of base64url SHA-256 digests for inline WebAssembly modules. `.wasm` files are added automatically during generation. |
| `extra_csp` | Record<string, string> | Optional per-path CSP overrides; keys must start with `/`. | `{}` or `{ "/app": "default-src 'none'" }` |

Use the JSON example in the workflow above as a starting point and adjust fields
to match your application.
