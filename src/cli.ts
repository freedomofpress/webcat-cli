#!/usr/bin/env node
import { Command, CommanderError, Option } from "commander";
import { WebcatError, WebcatErrorCode } from "@freedomofpress/webcat/webcat/interfaces/errors";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { type Enrollment, EnrollmentTypes, buildEnrollmentObject, canonicalizeEnrollment, loadEnrollment } from "./enrollment.js";
import {
  ManifestDocument,
  buildManifest,
  canonicalizeManifestBody,
  loadManifestConfig,
  loadManifestDocument,
  manifestHash,
  scanDirectory,
} from "./manifest.js";
import { describeValidity, loadBundleDocument, verifyBundle } from "./bundle.js";
import { CSP_PRESETS, DEFAULT_MAX_AGE, SIGSUM_POLICIES, runInit } from "./init.js";
import { fetchSiteCsp, formatCspReport, hintCsp } from "./csp.js";
import { gitDirtyFiles, gitRoot, gitStage, gitTagAtHead, gitTagExists } from "./git.js";
import { WELL_KNOWN_DIR, checkHistory, enrollmentFileName, publishBundle, writeOnce } from "./history.js";
import { checkSite } from "./site.js";
import {
  DEFAULT_CHAIN_API,
  DEFAULT_LIST_ENDPOINT,
  WELL_KNOWN_PATH,
  type Oracle,
  bareDomain,
  enrollmentHashHex,
  fetchDomainStatus,
  fetchVerifiedList,
  fetchOracles,
  fetchServedEnrollment,
  submitObservation,
} from "./chain.js";
import { fetchTimestampFromPolicy, signManifestWithSigsum, sigsumEnrollmentFromPolicy } from "./sigsum.js";
import {
  DEFAULT_FULCIO_URL,
  DEFAULT_REKOR_URL,
  ISSUER_V2_OID,
  SAN_OID,
  SIGSTORE_CLAIM_FLAGS,
  SIGSTORE_OIDC_CLIENT_ID,
  SIGSTORE_OIDC_ISSUER,
  SIGSTORE_OIDC_SCOPE,
  ciIdentityProvider,
  fetchCommunityTrustedRoot,
  fetchInteractiveOidcToken,
  signManifestWithSigstore,
  signingBlockedBy,
  staticIdentityProvider,
  trustedRootDrift,
} from "./sigstore.js";
import {
  CliError,
  OID_RE,
  causeOf,
  describeWebcatError,
  ensureObject,
  external,
  hashPolicyBytes,
  invalid,
  log,
  readJson,
  readText,
  sha256,
  toBase64Url,
  validateAll,
  writeOutput,
} from "./utils.js";
import pkg from "../package.json" with { type: "json" };

const collect = (value: string, previous: string[] = []): string[] => previous.concat(value);
const camel = (flag: string): string => flag.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

const typeOption = (what: string) => new Option("--type <type>", `${what} type`).choices(["sigsum", "sigstore"]).default("sigsum");

function requireOption<T>(value: T | undefined, flag: string, context: string): T {
  if (value === undefined || value === null || value === "") {
    throw invalid(`${flag} is required for ${context}`);
  }
  return value;
}
// Writes are staged in git when inside a repository (or committed on request); never silently.
async function stageInGit(paths: string[], git: boolean | undefined, commitMessage?: string): Promise<void> {
  if (git === false || !(await gitRoot())) return;
  await gitStage(paths, commitMessage);
  log(commitMessage ? `committed: ${commitMessage}` : `staged in git: ${paths.map((p) => path.relative(process.cwd(), p)).join(", ")}`);
}

// Reports every missing flag at once.
const requireOptions = (context: string, ...flags: Array<[value: unknown, flag: string]>): void =>
  validateAll(flags.map(([value, flag]) => () => requireOption(value, flag, context)));

function parseClaim(value: string, previous: Record<string, string> = {}): Record<string, string> {
  const separator = value.indexOf("=");
  if (separator <= 0) {
    throw invalid("--claim must be in OID=value format");
  }
  const oid = value.slice(0, separator).trim();
  const claim = value.slice(separator + 1).trim();
  if (!OID_RE.test(oid)) {
    throw invalid(`--claim key must be an OID, got '${oid}'`);
  }
  if (!claim) {
    throw invalid("--claim value must be non-empty");
  }
  return { ...previous, [oid]: claim };
}

const program = new Command()
  .name("webcat")
  .description("Utilities for WEBCAT enrollment and manifest generation and validation")
  .version(pkg.version)
  .exitOverride() // must precede .command() so subcommands inherit it; errors are mapped to exit codes at the bottom of this file
  .configureOutput({ outputError: (str, write) => write(str.replace(/^error: /, "Error: ")) });

// ---------------------------------------------------------------------------
// init

const SIGSUM = "Sigsum enrollment options:";
const SIGSTORE = "Sigstore enrollment options:";

program
  .command("init")
  .description("Set up a site for WEBCAT: writes webcat.config.json, trust_policy and .well-known/webcat/enrollment.json, then prints the next steps")
  .option("--origin <url>", "Site origin, e.g. https://example.org")
  .option("--source <url>", "Git repository the site is built from (default: the origin remote)")
  .option("--artifact <template>", "Release archive URL template containing ${version}")
  .option("--no-git", "Do not stage written files in git")
  .option("--app-version <string>", "Version string for this release (default: 1.0.0)")
  .addOption(typeOption("Enrollment"))
  .option("--csp <policy>", `Content Security Policy; presets: ${Object.keys(CSP_PRESETS).join(", ")}`)
  .option("--max-age <seconds>", "How long a signed manifest stays valid", String(DEFAULT_MAX_AGE))
  .addOption(new Option("--policy <choice>", `Sigsum policy: ${Object.keys(SIGSUM_POLICIES).join(", ")}, or a policy file path`).helpGroup(SIGSUM))
  .addOption(new Option("--signer <key>", "Existing signer public key: hex, base64 or an OpenSSH .pub path (repeatable)").argParser(collect).helpGroup(SIGSUM))
  .addOption(new Option("--keys <n>", "Generate this many Sigsum keys into keys/ with sigsum-key (default when no --signer: 2)").helpGroup(SIGSUM))
  .addOption(new Option("--threshold <k>", "Signatures required").default("1").helpGroup(SIGSUM))
  .addOption(new Option("--identity <value>", "Signing identity").helpGroup(SIGSTORE))
  .addOption(new Option("--issuer <url>", "OIDC issuer").helpGroup(SIGSTORE))
  .option("-d, --dir <path>", "Directory to write into", ".")
  .action(async (options, command: Command) => {
    // Flags with defaults are only "answered" when given explicitly; otherwise init asks (and uses the default off a terminal).
    const explicit = (name: string) => (command.getOptionValueSource(name) === "cli" ? options[name] : undefined);
    await runInit({
      ...options,
      version: options.appVersion,
      type: explicit("type"),
      threshold: explicit("threshold"),
      maxAge: explicit("maxAge"),
      csp: options.csp && (CSP_PRESETS[options.csp]?.csp ?? options.csp),
    });
  });

// ---------------------------------------------------------------------------
// csp

const csp = program.command("csp").description("Content Security Policy helpers");

csp
  .command("check")
  .description("Answer whether a policy satisfies WEBCAT's CSP rules (exit 1 if not)")
  .argument("<policy>", "The policy string, quoted")
  .action((policy: string) => {
    try {
      validateCSP(policy);
      process.stdout.write("OK: WEBCAT-compatible\n");
    } catch (err) {
      process.stdout.write(`NOT OK: ${causeOf(err)}\n  run: webcat csp hint '<policy>' for what to change\n`);
      process.exitCode = 1;
    }
  });

csp
  .command("hint")
  .description("Explain what WEBCAT would reject in a policy, with the documented workaround for each, and suggest the nearest compatible policy")
  .argument("<policy-or-url>", "A policy string, or an https:// page to read the policy from")
  .action(async (input: string) => {
    let policy = input;
    if (/^https?:\/\//.test(input)) {
      const site = await fetchSiteCsp(input);
      if (!site.csp) {
        process.stdout.write(`${input} sends no Content-Security-Policy. Start from a preset: webcat init picks one, or run: webcat csp hint "${CSP_PRESETS.static.csp}"\n`);
        process.exitCode = 1;
        return;
      }
      process.stdout.write(`Read from ${site.from}\n`);
      policy = site.csp;
    }
    process.stdout.write(`Policy: ${policy}\n\n`);
    const report = hintCsp(policy);
    process.stdout.write(formatCspReport(report));
    if (report.groups.length) {
      process.exitCode = 1;
    }
  });

// ---------------------------------------------------------------------------
// enrollment

const enrollment = program.command("enrollment").description("Create, canonicalize and hash enrollments");

const enrollmentCreate = enrollment
  .command("create")
  .description("Create an enrollment definition")
  .addOption(typeOption("Enrollment"))
  .option("-m, --max-age <seconds>", "Maximum age in seconds")
  .option("-o, --output <path>", "Write result to file instead of stdout")
  .addOption(new Option("-p, --policy-file <path>", "Sigsum policy file to compile").default("trust_policy").helpGroup(SIGSUM))
  .addOption(new Option("-s, --signer <key>", "Signer public key: hex, base64 or an OpenSSH .pub path (repeatable)").argParser(collect).helpGroup(SIGSUM))
  .addOption(new Option("-t, --threshold <k>", "Threshold for signature approval").helpGroup(SIGSUM))
  .addOption(new Option("-c, --cas-url <url>").hideHelp()) // removed from the spec; accepted and ignored
  .option("--no-git", "Do not stage the written files in git")
  .addOption(new Option("--trusted-root <path>", "Sigstore trusted root file").helpGroup(SIGSTORE))
  .addOption(new Option("--community-trusted-root", "Fetch the Sigstore community trusted root via TUF").helpGroup(SIGSTORE))
  .addOption(new Option("--identity <value>", `Signing identity (SAN, OID ${SAN_OID})`).helpGroup(SIGSTORE))
  .addOption(new Option("--issuer <value>", `OIDC issuer (OID ${ISSUER_V2_OID})`).helpGroup(SIGSTORE))
  .addOption(
    new Option("--claim <oid=value>", "Any other certificate claim by OID (repeatable); named aliases such as --source-repository-uri also work")
      .argParser(parseClaim)
      .helpGroup(SIGSTORE),
  );
for (const [flag, oid] of SIGSTORE_CLAIM_FLAGS) {
  enrollmentCreate.addOption(new Option(`--${flag} <value>`, `Sigstore claim OID ${oid}`).hideHelp());
}
enrollmentCreate.action(async (options) => {
  let enrollmentObject: Enrollment;
  if (options.type === "sigsum") {
    requireOptions(
      "sigsum enrollments",
      [options.signer, "--signer"],
      [options.threshold, "--threshold"],
      [options.maxAge, "--max-age"],
    );
    if (options.casUrl) log("Warning: --cas-url is no longer part of enrollments (the well-known directory carries the history); ignored");
    const policyText = await readText(options.policyFile, "policy");
    enrollmentObject = await buildEnrollmentObject({
      type: "sigsum",
      ...(await sigsumEnrollmentFromPolicy(policyText)),
      signers: options.signer,
      threshold: options.threshold,
      maxAge: options.maxAge,
    });
  } else {
    // Explicit --claim first, then legacy aliases, then named flags; later entries win per OID.
    const claims: Record<string, string> = { ...(options.claim ?? {}) };
    if (options.identity) claims[SAN_OID] = options.identity.trim();
    if (options.issuer) claims[ISSUER_V2_OID] = options.issuer.trim();
    for (const [flag, oid] of SIGSTORE_CLAIM_FLAGS) {
      const value = options[camel(flag)];
      if (value) claims[oid] = String(value).trim();
    }
    validateAll([
      () => {
        if (options.communityTrustedRoot && options.trustedRoot) {
          throw invalid("--trusted-root and --community-trusted-root are mutually exclusive");
        }
        if (!options.communityTrustedRoot && !options.trustedRoot) {
          throw invalid("--trusted-root or --community-trusted-root is required for sigstore enrollments");
        }
      },
      () => {
        if (Object.keys(claims).length === 0) {
          throw invalid("--identity, --issuer or --claim is required for sigstore enrollments");
        }
      },
      () => requireOption(options.maxAge, "--max-age", "sigstore enrollments"),
    ]);
    const trustedRoot = options.communityTrustedRoot
      ? await fetchCommunityTrustedRoot()
      : ensureObject(await readJson(options.trustedRoot, "trusted root"), `trusted root from ${options.trustedRoot}`);
    enrollmentObject = await buildEnrollmentObject({ type: "sigstore", trustedRoot, claims, maxAge: options.maxAge });
  }

  const json = JSON.stringify(enrollmentObject, null, 2) + "\n";
  await writeOutput(options.output, json);
  if (options.output) {
    // The hash-named copy lives next to the enrollment: the history auditors read (spec server.md section 1).
    const dir = path.dirname(options.output);
    const name = enrollmentFileName(enrollmentObject);
    const added = await writeOnce(dir, name, json);
    log(`${added ? "wrote" : "already present"} ${path.join(dir, name)}`);
    await stageInGit([options.output, path.join(dir, name)], options.git);
  }
});

enrollment
  .command("canonicalize")
  .description("Canonicalize an enrollment JSON file")
  .option("-i, --input <path>", "Enrollment file to canonicalize")
  .addOption(new Option("-e, --enrollment <path>").hideHelp()) // legacy alias
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options) => {
    const input = requireOption(options.input ?? options.enrollment, "--input", "enrollment canonicalize");
    await writeOutput(options.output, canonicalizeEnrollment(await loadEnrollment(input)));
  });

enrollment
  .command("hash")
  .description("Canonicalize and hash an enrollment file")
  .requiredOption("-i, --input <path>", "Enrollment file to hash")
  .action(async (options) => {
    const canonical = canonicalizeEnrollment(await loadEnrollment(options.input));
    process.stdout.write(toBase64Url(sha256(canonical)) + "\n");
  });

enrollment
  .command("submit")
  .description("Ask the WEBCAT oracles to observe the enrollment served at https://<domain>/.well-known/webcat/enrollment.json")
  .argument("<domain>", "Domain to enroll (must already serve the enrollment file)")
  .option("--chain-api <url>", "Chain query API used to discover oracles", DEFAULT_CHAIN_API)
  .option("--oracle <url>", "Oracle endpoint to submit to instead of the chain's list (repeatable)", collect)
  .option("-e, --enrollment <path>", "Local enrollment file that must match what the domain serves")
  .option("--unenroll", "Allow submitting when the domain serves no enrollment (oracles will vote to unenroll)")
  .option("--dry-run", "Check the served enrollment and solve the proof of work, but do not submit")
  .action(async (domain: string, options) => {
    const served = await fetchServedEnrollment(domain);
    if (!served) {
      if (!options.unenroll) {
        throw invalid(`https://${bareDomain(domain)}${WELL_KNOWN_PATH} is not found; --unenroll is required to request removal`);
      }
      log(`Warning: ${bareDomain(domain)} serves no enrollment; oracles will vote to unenroll it.`);
    } else {
      log(`Served enrollment hash: ${served.hash}`);
      // Auditors read the enrollment by its hash (spec server.md section 1); warn until the spec is final.
      const historyUrl = `https://${bareDomain(domain)}/${WELL_KNOWN_DIR}/enrollment.${served.hash}.json`;
      const history = await fetch(historyUrl).catch(() => null);
      if (!history?.ok) log(`Warning: ${historyUrl} is not served; auditors will need it (webcat bundle create and init write it)`);
      if (options.enrollment) {
        const local = enrollmentHashHex(await loadEnrollment(options.enrollment));
        if (local !== served.hash) {
          throw invalid(`--enrollment must match the served enrollment: local hash ${local}, served ${served.hash}`);
        }
      }
    }
    const oracles: Oracle[] = options.oracle ? options.oracle.map((endpoint: string) => ({ endpoint })) : await fetchOracles(options.chainApi);
    if (oracles.length === 0) {
      throw external(`failed to find oracles: ${options.oracle ? "--oracle list is empty" : `${options.chainApi} lists none`}`);
    }
    const results = await Promise.all(oracles.map((oracle) => submitObservation(oracle, domain, { dryRun: options.dryRun })));
    for (const { endpoint, ok, message } of results) {
      process.stdout.write(`${endpoint}: ${ok ? "OK" : "FAIL"} (${message})\n`);
    }
    const succeeded = results.filter((r) => r.ok).length;
    process.stdout.write(`${succeeded}/${results.length} oracles ${options.dryRun ? "reachable (dry run, nothing submitted)" : "accepted the observation"}\n`);
    if (succeeded === 0) {
      process.exitCode = 1;
    }
  });

enrollment
  .command("status")
  .description("Show a domain's enrollment as served, as recorded on the chain, and as published in the list")
  .argument("<domain>", "Domain to inspect")
  .option("--chain-api <url>", "Chain query API", DEFAULT_CHAIN_API)
  .option("--list <url>", "Endpoint serving the published list.json and block.json; verified like the extension does", DEFAULT_LIST_ENDPOINT)
  .option("--no-list", "Skip the published list check")
  .action(async (domain: string, options) => {
    const [served, status, list] = await Promise.all([
      fetchServedEnrollment(domain).catch((err) => err as Error),
      fetchDomainStatus(options.chainApi, domain),
      options.list ? fetchVerifiedList(String(options.list).replace(/list\.json$/, "")).catch((err) => err as Error) : null,
    ]);
    const show = (value: string | null | undefined) => value ?? "none";
    process.stdout.write(`Domain: ${bareDomain(domain)}\n`);
    process.stdout.write(`Served enrollment: ${served instanceof Error ? `ERROR (${served.message})` : show(served?.hash)}\n`);
    if (!(served instanceof Error) && served?.enrollment.type === EnrollmentTypes.Sigstore) {
      const drift = trustedRootDrift(served.enrollment.trusted_root, await fetchCommunityTrustedRoot());
      process.stdout.write(`Trusted root:      ${drift.length ? "WARNING, re-enroll before signing again" : "up to date with the community root"}\n`);
      drift.forEach((line) => process.stdout.write(`                   - ${line}\n`));
    }
    process.stdout.write(`Chain canonical:   ${show(status.canonical)}\n`);
    for (const p of status.pending) {
      process.stdout.write(`Chain pending:     ${show(p.hash)} (since ${p.time})\n`);
    }
    for (const v of status.votes) {
      process.stdout.write(`Oracle vote:       ${show(v.hash)} (${v.oracle?.slice(0, 16)}... at ${v.time})\n`);
    }
    if (list) {
      process.stdout.write(
        list instanceof Error
          ? `Published list:    ERROR (${list.message})\n`
          : `Published list:    ${show(list.leaves.get(bareDomain(domain)))} (block ${list.blockHeight} at ${list.blockTime.toISOString()}, commit verified)\n`,
      );
    }
    const servedHash = served instanceof Error ? undefined : (served?.hash ?? null);
    if (servedHash !== undefined) {
      process.stdout.write(
        servedHash === null && status.canonical === null
          ? "Status: not enrolled\n"
          : servedHash === status.canonical
            ? "Status: served enrollment matches the chain\n"
          : status.pending.some((p) => p.hash === servedHash)
            ? "Status: served enrollment is pending promotion on the chain\n"
            : "Status: served enrollment is NOT what the chain records; run `enrollment submit` to request an observation\n",
      );
    }
  });

// ---------------------------------------------------------------------------
// manifest

const manifest = program.command("manifest").description("Generate, sign, hash and verify manifests");

manifest
  .command("generate")
  .description("Generate a manifest from a directory and config")
  .addOption(typeOption("Manifest"))
  .option("-c, --config <path>", "Manifest config JSON file", "webcat.config.json")
  .requiredOption("-d, --directory <path>", "Directory containing site assets")
  .option("-p, --policy-file <path>", "Sigsum policy file for timestamps", "trust_policy")
  .option("--include-dotfiles", "Include dotfiles and dotfolders in the manifest")
  .option("--exclude <path>", "Exclude a file or directory from the manifest (repeatable)", collect)
  .option("--archive <path>", "Also write the release archive (gzip tar of the directory) that the artifact URL will serve")
  .option("--skip-git-checks", "Do not require version to be the tag at HEAD when source is set")
  .option("-o, --output <path>", "Write manifest to a file instead of stdout")
  .action(async (options) => {
    const policyFile = options.type === "sigsum" ? options.policyFile : undefined;
    const [config, scan, timestamp] = await Promise.all([
      loadManifestConfig(options.config),
      scanDirectory(options.directory, { includeDotfiles: options.includeDotfiles, excludePaths: options.exclude }),
      policyFile ? readText(policyFile, "policy").then(fetchTimestampFromPolicy) : undefined,
    ]);
    const inRepo = await gitRoot();
    // With no version in the config, the release is whatever tag HEAD carries.
    const tagAtHead = inRepo ? await gitTagAtHead() : null;
    const version = config.version ?? tagAtHead;
    if (!version) {
      throw invalid("config.version is required: set it in webcat.config.json, or tag the commit being released");
    }
    if (config.source && !options.skipGitChecks && inRepo) {
      // A manifest with source claims the files build from the repository at tag `version`: HEAD must be that tag.
      const tag = tagAtHead;
      if (tag !== version) {
        const exists = await gitTagExists(version);
        throw invalid(
          `config.version ${version} must be the git tag at HEAD because config.source is set (HEAD is ${tag ? `tagged ${tag}` : "not tagged"}${exists ? "" : `, and no tag ${version} exists`}); tag the release or pass --skip-git-checks`,
        );
      }
    }
    const document: ManifestDocument = { manifest: buildManifest({ ...config, version }, scan, timestamp) };
    if (options.archive) {
      await new Promise<void>((resolve, reject) => {
        const tar = spawn("tar", ["-czf", options.archive, "-C", options.directory, "--exclude=./.well-known/webcat", "."], { stdio: ["ignore", "inherit", "inherit"] });
        tar.on("error", (err) => reject(external(`failed to run tar: ${causeOf(err)}`)));
        tar.on("exit", (code) => (code === 0 ? resolve() : reject(external(`failed to run tar: exit code ${code}`))));
      });
      log(`wrote ${options.archive}; publish it where ${config.artifact ?? "the artifact URL"} resolves for version ${version}`);
    }
    await writeOutput(options.output, JSON.stringify(document, null, 2));
  });

manifest
  .command("sign")
  .description("Sign a manifest with sigsum (default) or sigstore")
  .addOption(typeOption("Signature"))
  .option("-i, --input <path>", "Manifest file to sign", "manifest.json")
  .option("-e, --enrollment <path>", "Enrollment to sign for: refuses keys or policies it would not accept and verifies the result", ".well-known/webcat/enrollment.json")
  .option("-p, --policy-file <path>", "Sigsum trust policy file for sigsum-submit", "trust_policy")
  .option("-k, --key <path>", "Sigsum signing key: a private key file, or a .pub whose private key is in ssh-agent (hardware tokens)")
  .option("--token-signing-key <path>", "Rate-limit token key: a private key file, or a .pub held in ssh-agent")
  .option("--token-domain <domain>", "Domain name to use for Sigsum rate limiting")
  .addOption(new Option("--bundle-type <type>", "Sigstore bundle type to generate").choices(["message", "dsse"]).default("message"))
  .option("--fulcio-url <url>", "Sigstore Fulcio base URL", DEFAULT_FULCIO_URL)
  .option("--rekor-url <url>", "Sigstore Rekor base URL", DEFAULT_REKOR_URL)
  .option("--tsa-url <url>", "Sigstore timestamp authority base URL")
  .option("--oidc-audience <value>", "OIDC audience for CI identity provider", "sigstore")
  .option("--oidc-issuer <url>", "OIDC issuer for interactive login", SIGSTORE_OIDC_ISSUER)
  .option("--oidc-client-id <value>", "OIDC client ID for interactive login", SIGSTORE_OIDC_CLIENT_ID)
  .option("--oidc-scope <value>", "OIDC scope for interactive login", SIGSTORE_OIDC_SCOPE)
  .option("--oidc-token <value>", "Explicit OIDC ID token to use for Sigstore signing")
  .option("--interactive", "Use OIDC device authorization flow for Sigstore signing")
  .option("--no-open-browser", "Do not open a browser window for device authorization")
  .option("--skip-git-checks", "Sign even with uncommitted changes when the manifest has source")
  .option("-o, --output <path>", "Write updated manifest to a file")
  .action(async (options, command: Command) => {
    const document = await loadManifestDocument(options.input);
    if (document.manifest.source && !options.skipGitChecks && (await gitRoot())) {
      const dirty = await gitDirtyFiles();
      if (dirty.length) {
        throw invalid(`the working tree has uncommitted changes and the manifest has source; commit or stash first (or pass --skip-git-checks):\n  - ${dirty.join("\n  - ")}`);
      }
    }
    // The default enrollment path may simply not exist; an explicit one must.
    const enrollment = await loadEnrollment(options.enrollment).catch((err) => {
      if (command.getOptionValueSource("enrollment") === "default" && err instanceof CliError && /not found/.test(err.message)) {
        log(`Warning: ${options.enrollment} not found, the signed manifest is not checked against an enrollment`);
        return undefined;
      }
      throw err;
    });
    if (enrollment && enrollment.type !== options.type) {
      throw invalid(`--type ${options.type} but ${options.enrollment} is a ${enrollment.type} enrollment`);
    }

    if (options.type === "sigsum") {
      requireOption(options.key, "--key", "sigsum signing");
      await signManifestWithSigsum(document, {
        policyFile: options.policyFile,
        key: options.key,
        enrollment: enrollment?.type === EnrollmentTypes.Sigsum ? enrollment : undefined,
        tokenSigningKey: options.tokenSigningKey,
        tokenDomain: options.tokenDomain,
      });
    } else {
      if (options.bundleType === "dsse") {
        log("Warning: WEBCAT verifiers only accept message-signature bundles; a dsse bundle will not verify.");
      }
      if (options.oidcToken && options.interactive) {
        throw invalid("--oidc-token and --interactive are mutually exclusive");
      }
      if (enrollment?.type === EnrollmentTypes.Sigstore) {
        // Fail before requesting a certificate when the pinned root can no longer verify new signatures.
        const community = await fetchCommunityTrustedRoot();
        const blocked = signingBlockedBy(enrollment.trusted_root, community, { withTsa: Boolean(options.tsaUrl) });
        if (blocked.length) {
          throw invalid(`signing cannot produce a manifest that verifies under ${options.enrollment}; re-enroll with a fresh trusted root first:\n  - ${blocked.join("\n  - ")}`);
        }
        trustedRootDrift(enrollment.trusted_root, community).forEach((line) => log(`Warning: ${line}; plan a re-enrollment`));
      }
      const identityProvider = options.oidcToken
        ? staticIdentityProvider(options.oidcToken)
        : options.interactive
          ? staticIdentityProvider(
              await fetchInteractiveOidcToken({
                issuer: options.oidcIssuer,
                clientId: options.oidcClientId,
                scope: options.oidcScope,
                openBrowser: options.openBrowser,
              }),
            )
          : ciIdentityProvider(options.oidcAudience);
      await signManifestWithSigstore(document, {
        bundleType: options.bundleType,
        fulcioUrl: options.fulcioUrl,
        rekorUrl: options.rekorUrl,
        tsaUrl: options.tsaUrl,
        identityProvider,
      });
    }
    if (enrollment) {
      // Verify before publishing anything; a partial threshold still gets the timestamp and expiry checks (threshold 1).
      let result = await verifyBundle({ enrollment, manifest: document });
      const partial = result instanceof WebcatError && result.code === WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED ? result : null;
      if (partial && enrollment.type === EnrollmentTypes.Sigsum) {
        result = await verifyBundle({ enrollment: { ...enrollment, threshold: 1 }, manifest: document });
      }
      if (result instanceof WebcatError) {
        throw invalid(`the signed manifest does not verify against ${options.enrollment}: ${describeWebcatError(result)}; nothing written`);
      }
      log(partial ? `Signed: ${partial.details?.[0]} of ${partial.details?.[1]} required signatures present, sign again with another enrolled key` : `Verified against ${options.enrollment}: ${describeValidity(result)}`);
    }
    await writeOutput(options.output, JSON.stringify(document, null, 2));
  });

manifest
  .command("canonicalize")
  .description("Canonicalize a manifest JSON file")
  .requiredOption("-i, --input <path>", "Manifest file to canonicalize")
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options) => {
    await writeOutput(options.output, canonicalizeManifestBody(await loadManifestDocument(options.input)));
  });

manifest
  .command("hash")
  .description("Canonicalize and hash a manifest file")
  .option("-i, --input <path>", "Manifest file to hash")
  .addOption(new Option("-m, --manifest <path>").hideHelp()) // legacy alias
  .action(async (options) => {
    const input = requireOption(options.input ?? options.manifest, "--input", "manifest hash");
    process.stdout.write(toBase64Url(manifestHash(await loadManifestDocument(input))) + "\n");
  });

manifest
  .command("verify")
  .description("Verify a signed manifest against its enrollment: sigsum signer threshold or Sigstore claims")
  .argument("[bundle]", "Bundle JSON file (enrollment plus signed manifest)")
  .option("-e, --enrollment <path>", "Enrollment JSON file (use with --manifest instead of a bundle)")
  .option("-m, --manifest <path>", "Signed manifest JSON file")
  .allowExcessArguments() // legacy form: verify <enrollment> <manifest>
  .action(async (first: string | undefined, options, command: Command) => {
    if (command.args.length > 2) {
      throw invalid("manifest verify takes at most one bundle argument");
    }
    const legacy = command.args.length === 2;
    const bundlePath = legacy ? undefined : first;
    const enrollmentPath = legacy ? command.args[0] : options.enrollment;
    const manifestPath = legacy ? command.args[1] : options.manifest;
    if (!bundlePath === !enrollmentPath || !enrollmentPath !== !manifestPath) {
      throw invalid("a bundle argument, or --enrollment together with --manifest, is required for manifest verify");
    }
    const bundle = enrollmentPath
      ? { enrollment: await loadEnrollment(enrollmentPath), manifest: await loadManifestDocument(manifestPath) }
      : await loadBundleDocument(bundlePath!);
    const result = await verifyBundle(bundle);
    if (bundle.enrollment.type === EnrollmentTypes.Sigsum) {
      process.stdout.write(`Enrollment policy hash: ${hashPolicyBytes(bundle.enrollment.policy)}\n`);
    }
    if (result instanceof WebcatError) {
      process.stdout.write(`FAILED: ${describeWebcatError(result)}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write(`VERIFIED: ${describeValidity(result)}\n`);
    }
  });

// ---------------------------------------------------------------------------
// site

program
  .command("site")
  .description("Check deployed sites")
  .command("check")
  .description("Fetch a live site like the extension does: verify its bundle, then check headers, CSP and file hashes for every path")
  .argument("<domain>", "Domain to check")
  .option("--path <path>", "Only check this path (repeatable); default: / plus every file in the manifest", collect)
  .option("--chain-api <url>", "Chain query API", DEFAULT_CHAIN_API)
  .action(async (domain: string, options) => {
    const report = await checkSite(domain, { chainApi: options.chainApi, paths: options.path });
    process.stdout.write(`Bundle:          ${report.bundle}\n`);
    process.stdout.write(`Previous bundle: ${report.previousBundle}\n`);
    process.stdout.write(`Enrollment:      ${report.enrollment}\n`);
    if (report.trustedRoot.length) {
      process.stdout.write("Trusted root:    WARNING, re-enroll before signing again\n");
      report.trustedRoot.forEach((line) => process.stdout.write(`  - ${line}\n`));
    }
    // Warning only until the auditing spec is final: no site serves these files yet.
    process.stdout.write(`History:         ${report.history.length ? `WARNING, ${report.history.length} file(s) auditors will need are missing` : "hash-named files served"}\n`);
    report.history.forEach((line) => process.stdout.write(`  - ${line}\n`));
    const failed = report.paths.filter((p) => p.problems.length > 0);
    process.stdout.write(`Paths:           ${report.paths.length} checked, ${failed.length} with problems\n`);
    for (const { path, problems } of failed) {
      process.stdout.write(`  ${path}\n`);
      for (const problem of problems) {
        process.stdout.write(`    - ${problem}\n`);
      }
    }
    const broken = failed.length > 0 || !report.bundle.startsWith("VERIFIED") || /MISMATCH|ERROR/.test(report.enrollment);
    process.stdout.write(broken ? "Status: NOT OK, visitors with the extension will see errors\n" : "Status: OK\n");
    if (broken) {
      process.exitCode = 1;
    }
  });

// ---------------------------------------------------------------------------
// bundle

program
  .command("bundle")
  .description("Combine an enrollment and a signed manifest into a bundle")
  .command("create")
  .description("Publish a signed manifest: writes bundle.json and the hash-named manifest file into the well-known directory, keeps the previous bundle when the enrollment changed")
  .option("-e, --enrollment <path>", "Enrollment JSON file", `${WELL_KNOWN_DIR}/enrollment.json`)
  .option("-m, --manifest <path>", "Signed manifest JSON file", "manifest.signed.json")
  .option("-d, --dir <path>", "Well-known directory to publish into", WELL_KNOWN_DIR)
  .option("--commit", "Commit the written files")
  .option("--no-git", "Do not stage the written files in git")
  .option("-o, --output <path>", "Only write the bundle to this file (no history files)")
  .action(async (options) => {
    const [enrollment, document] = await Promise.all([loadEnrollment(options.enrollment), loadManifestDocument(options.manifest)]);
    if (options.output) {
      await writeOutput(options.output, JSON.stringify({ enrollment, manifest: document.manifest, signatures: document.signatures }, null, 2));
      return;
    }
    const written = await publishBundle(options.dir, enrollment, document);
    written.forEach((f) => log(`wrote ${f}`));
    await stageInGit(written, options.git, options.commit ? `webcat: publish manifest ${document.manifest.version}` : undefined);
  });

// ---------------------------------------------------------------------------
// release

// One step for the common case: the tag at HEAD is the version, the config knows the build directory.
// Runs the granular commands as subprocesses so every flag and exit code behaves exactly as documented.
program
  .command("release")
  .description("Generate, sign, bundle and commit the release that HEAD is tagged with (manifest generate + sign + bundle create --commit in one step)")
  .option("-d, --directory <path>", "Directory with the built site (default: config.directory)")
  .addOption(typeOption("Signature"))
  .option("-k, --key <path>", "Sigsum signing key, repeatable up to the threshold (private key, or .pub held in ssh-agent)", collect)
  .option("--token-signing-key <path>", "Rate-limit token key for production Sigsum logs")
  .option("--token-domain <domain>", "Domain for Sigsum rate limiting")
  .option("--oidc-token <value>", "Explicit OIDC token for Sigstore signing")
  .option("--interactive", "OIDC device flow for Sigstore signing")
  .option("--no-archive", "Do not write the release archive even when the config has artifact")
  .option("--no-commit", "Stage the published files instead of committing them")
  .option("--skip-git-checks", "Skip the tag-at-HEAD and clean-tree checks")
  .action(async (options) => {
    const config = await loadManifestConfig("webcat.config.json");
    const directory = options.directory ?? config.directory;
    if (!directory) throw invalid("--directory is required (or set directory in webcat.config.json)");
    if (options.type === "sigsum") requireOption(options.key, "--key", "a sigsum release");
    const version = config.version ?? (await gitTagAtHead());
    const archive = options.archive && config.artifact && version ? path.basename(config.artifact.replace(/\$\{version\}/g, version)) : undefined;
    const run = (...args: string[]) =>
      new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, [...process.execArgv, process.argv[1], ...args], { stdio: "inherit" });
        child.on("exit", (code) => (code === 0 ? resolve() : reject(new CliError(`release stopped at: webcat ${args.join(" ")}`, code === 3 ? 3 : 2))));
      });
    const work = await mkdtemp(path.join(tmpdir(), "webcat-release-"));
    const skip = options.skipGitChecks ? ["--skip-git-checks"] : [];
    const unsigned = path.join(work, "manifest.json");
    const signed = path.join(work, "manifest.signed.json");
    await run("manifest", "generate", "--type", options.type, "-d", directory, "-o", unsigned, ...(archive ? ["--archive", archive] : []), ...skip);
    if (options.type === "sigsum") {
      let input = unsigned;
      for (const key of options.key as string[]) {
        const token = options.tokenSigningKey && options.tokenDomain ? ["--token-signing-key", options.tokenSigningKey, "--token-domain", options.tokenDomain] : [];
        await run("manifest", "sign", "-i", input, "-k", key, ...token, "-o", signed, ...skip);
        input = signed;
      }
    } else {
      const auth = options.oidcToken ? ["--oidc-token", options.oidcToken] : options.interactive ? ["--interactive"] : [];
      await run("manifest", "sign", "--type", "sigstore", "-i", unsigned, ...auth, "-o", signed, ...skip);
    }
    await run("bundle", "create", "-m", signed, ...(options.commit ? ["--commit"] : []));
    await rm(work, { recursive: true, force: true });
    log(`Released ${version ?? "(unversioned)"}. Left to do: push the commit and tag${archive ? `, upload ${archive} where ${config.artifact} resolves` : ""}, deploy with ${WELL_KNOWN_DIR}/ in the web root`);
  });

// ---------------------------------------------------------------------------
// history

program
  .command("history")
  .description("The well-known directory as an append-only ledger")
  .command("check")
  .description("Check every hash-named file hashes to its name, the current pointers match them, and nothing was modified or deleted since a git ref (exit 1 on problems)")
  .argument("[ref]", "Git ref to compare against (e.g. HEAD, origin/main); default: no git comparison")
  .option("-d, --dir <path>", "Well-known directory", WELL_KNOWN_DIR)
  .action(async (ref: string | undefined, options) => {
    const problems = await checkHistory(options.dir, ref);
    if (problems.length === 0) {
      process.stdout.write(`OK: ${options.dir} is consistent${ref ? ` and append-only since ${ref}` : ""}\n`);
      return;
    }
    process.stdout.write(`${problems.length} problem${problems.length > 1 ? "s" : ""} in ${options.dir}:\n`);
    problems.forEach((p) => process.stdout.write(`  - ${p}\n`));
    process.exitCode = 1;
  });

// Exit codes: 0 ok, 1 negative verification result, 2 invalid input or usage, 3 external failure (see utils.ts).
program
  .parseAsync(process.argv)
  .catch((err: unknown) => {
    if (err instanceof CommanderError) {
      process.exit(err.exitCode === 0 ? 0 : 2); // commander already printed the message
    }
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(err instanceof CliError ? err.exitCode : 3);
  });
