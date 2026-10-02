#!/usr/bin/env node
import { Command, CommanderError, Option } from "commander";
import { canonicalize } from "./canonicalize.js";
import { EnrollmentInput, buildEnrollmentObject, loadEnrollment } from "./enrollment.js";
import { publishSigsumProofToCas, writeCasObject } from "./cas.js";
import {
  ManifestDocument,
  buildManifest,
  canonicalizeManifestBody,
  loadManifestConfig,
  loadManifestDocument,
  manifestHash,
  scanDirectory,
} from "./manifest.js";
import { loadBundleDocument } from "./bundle.js";
import {
  DEFAULT_CHAIN_API,
  DEFAULT_LIST_URL,
  WELL_KNOWN_PATH,
  type Oracle,
  bareDomain,
  enrollmentHashHex,
  fetchDomainStatus,
  fetchListEntry,
  fetchOracles,
  fetchServedEnrollment,
  submitObservation,
} from "./chain.js";
import { fetchTimestampFromPolicy, signManifestWithSigsum, sigsumEnrollmentFromPolicy, verifySigsumManifest } from "./sigsum.js";
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
  staticIdentityProvider,
  verifySigstoreManifest,
} from "./sigstore.js";
import { CliError, OID_RE, ensureObject, external, hashPolicyBytes, invalid, log, readJson, readText, sha256, toBase64Url, writeOutput } from "./utils.js";
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
// enrollment

const enrollment = program.command("enrollment").description("Create, canonicalize and hash enrollments");

const SIGSUM = "Sigsum enrollment options:";
const SIGSTORE = "Sigstore enrollment options:";
const enrollmentCreate = enrollment
  .command("create")
  .description("Create an enrollment definition")
  .addOption(typeOption("Enrollment"))
  .option("-m, --max-age <seconds>", "Maximum age in seconds")
  .option("-o, --output <path>", "Write result to file instead of stdout")
  .addOption(new Option("-p, --policy-file <path>", "Sigsum policy file to compile").helpGroup(SIGSUM))
  .addOption(new Option("-s, --signer <key>", "Signer public key, hex or base64 (repeatable)").argParser(collect).helpGroup(SIGSUM))
  .addOption(new Option("-t, --threshold <k>", "Threshold for signature approval").helpGroup(SIGSUM))
  .addOption(new Option("-c, --cas-url <url>", "CAS https URL").helpGroup(SIGSUM))
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
  let enrollmentObject: EnrollmentInput;
  if (options.type === "sigsum") {
    const policyText = await readText(requireOption(options.policyFile, "--policy-file", "sigsum enrollments"), "policy");
    enrollmentObject = buildEnrollmentObject({
      type: "sigsum",
      ...(await sigsumEnrollmentFromPolicy(policyText)),
      signers: options.signer ?? [],
      threshold: requireOption(options.threshold, "--threshold", "sigsum enrollments"),
      maxAge: requireOption(options.maxAge, "--max-age", "sigsum enrollments"),
      casUrl: requireOption(options.casUrl, "--cas-url", "sigsum enrollments"),
    });
  } else {
    if (options.communityTrustedRoot && options.trustedRoot) {
      throw invalid("--trusted-root and --community-trusted-root are mutually exclusive");
    }
    if (!options.communityTrustedRoot && !options.trustedRoot) {
      throw invalid("--trusted-root or --community-trusted-root is required for sigstore enrollments");
    }
    // Explicit --claim first, then legacy aliases, then named flags; later entries win per OID.
    const claims: Record<string, string> = { ...(options.claim ?? {}) };
    if (options.identity) claims[SAN_OID] = options.identity.trim();
    if (options.issuer) claims[ISSUER_V2_OID] = options.issuer.trim();
    for (const [flag, oid] of SIGSTORE_CLAIM_FLAGS) {
      const value = options[camel(flag)];
      if (value) claims[oid] = String(value).trim();
    }
    if (Object.keys(claims).length === 0) {
      throw invalid("--identity, --issuer or --claim is required for sigstore enrollments");
    }
    const trustedRoot = options.communityTrustedRoot
      ? await fetchCommunityTrustedRoot()
      : ensureObject(await readJson(options.trustedRoot, "trusted root"), `trusted root from ${options.trustedRoot}`);
    enrollmentObject = buildEnrollmentObject({
      type: "sigstore",
      trustedRoot,
      claims,
      maxAge: requireOption(options.maxAge, "--max-age", "sigstore enrollments"),
    });
  }

  const json = JSON.stringify(enrollmentObject, null, 2);
  const { hash, filePath } = await writeCasObject(json);
  log(`Saved enrollment to ${filePath} (sha256=${hash}).`);
  await writeOutput(options.output, json);
});

enrollment
  .command("canonicalize")
  .description("Canonicalize an enrollment JSON file")
  .option("-i, --input <path>", "Enrollment file to canonicalize")
  .addOption(new Option("-e, --enrollment <path>").hideHelp()) // legacy alias
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options) => {
    const input = requireOption(options.input ?? options.enrollment, "--input", "enrollment canonicalize");
    await writeOutput(options.output, canonicalize(await loadEnrollment(input)));
  });

enrollment
  .command("hash")
  .description("Canonicalize and hash an enrollment file")
  .requiredOption("-i, --input <path>", "Enrollment file to hash")
  .action(async (options) => {
    const canonical = canonicalize(await loadEnrollment(options.input));
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
  .option("--list <url>", "Published enrollment list to check", DEFAULT_LIST_URL)
  .option("--no-list", "Skip the published list check")
  .action(async (domain: string, options) => {
    const [served, status, list] = await Promise.all([
      fetchServedEnrollment(domain).catch((err) => err as Error),
      fetchDomainStatus(options.chainApi, domain),
      options.list ? fetchListEntry(options.list, domain).catch((err) => err as Error) : null,
    ]);
    const show = (value: string | null | undefined) => value ?? "none";
    process.stdout.write(`Domain: ${bareDomain(domain)}\n`);
    process.stdout.write(`Served enrollment: ${served instanceof Error ? `ERROR (${served.message})` : show(served?.hash)}\n`);
    process.stdout.write(`Chain canonical:   ${show(status.canonical)}\n`);
    for (const p of status.pending) {
      process.stdout.write(`Chain pending:     ${show(p.hash)} (since ${p.time})\n`);
    }
    for (const v of status.votes) {
      process.stdout.write(`Oracle vote:       ${show(v.hash)} (${v.oracle?.slice(0, 16)}... at ${v.time})\n`);
    }
    if (list) {
      process.stdout.write(
        list instanceof Error ? `Published list:    ERROR (${list.message})\n` : `Published list:    ${show(list.hash)} (block ${list.blockHeight})\n`,
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
  .requiredOption("-c, --config <path>", "Manifest config JSON file")
  .requiredOption("-d, --directory <path>", "Directory containing site assets")
  .option("-p, --policy-file <path>", "Sigsum policy file for timestamps")
  .option("--include-dotfiles", "Include dotfiles and dotfolders in the manifest")
  .option("--exclude <path>", "Exclude a file or directory from the manifest (repeatable)", collect)
  .option("-o, --output <path>", "Write manifest to a file instead of stdout")
  .action(async (options) => {
    const policyFile = options.type === "sigsum" ? requireOption(options.policyFile, "--policy-file", "sigsum manifests") : undefined;
    const [config, scan, timestamp] = await Promise.all([
      loadManifestConfig(options.config),
      scanDirectory(options.directory, { includeDotfiles: options.includeDotfiles, excludePaths: options.exclude }),
      policyFile ? readText(policyFile, "policy").then(fetchTimestampFromPolicy) : undefined,
    ]);
    const document: ManifestDocument = { manifest: buildManifest(config, scan, timestamp) };
    await writeOutput(options.output, JSON.stringify(document, null, 2));
  });

manifest
  .command("sign")
  .description("Sign a manifest with sigsum (default) or sigstore")
  .addOption(typeOption("Signature"))
  .requiredOption("-i, --input <path>", "Manifest file to sign")
  .option("-p, --policy-file <path>", "Sigsum trust policy file for sigsum-submit")
  .option("-k, --key <path>", "Sigsum private key for signing")
  .option("--token-signing-key <path>", "Sigsum private key for token signing")
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
  .option("-o, --output <path>", "Write updated manifest to a file")
  .action(async (options) => {
    const document = await loadManifestDocument(options.input);

    if (options.type === "sigsum") {
      const proofText = await signManifestWithSigsum(document, {
        policyFile: requireOption(options.policyFile, "--policy-file", "sigsum signing"),
        key: requireOption(options.key, "--key", "sigsum signing"),
        tokenSigningKey: options.tokenSigningKey,
        tokenDomain: options.tokenDomain,
      });
      const { leaf, checksum, manifest: canonical } = await publishSigsumProofToCas(canonicalizeManifestBody(document), proofText);
      log(`Saved raw Sigsum leaf to ${leaf.filePath} (sha256=${leaf.hash}).`);
      log(`Saved Sigsum checksum payload to ${checksum.filePath} (sha256=${checksum.hash}).`);
      log(`Saved canonical manifest to ${canonical.filePath} (sha256=${canonical.hash}).`);
    } else {
      if (options.bundleType === "dsse") {
        log("Warning: WEBCAT verifiers only accept message-signature bundles; a dsse bundle will not verify.");
      }
      if (options.oidcToken && options.interactive) {
        throw invalid("--oidc-token and --interactive are mutually exclusive");
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
    const { enrollment, manifest: document } = enrollmentPath
      ? { enrollment: await loadEnrollment(enrollmentPath), manifest: await loadManifestDocument(manifestPath) }
      : await loadBundleDocument(bundlePath!);

    let passed: boolean;
    if (enrollment.type === "sigsum") {
      const results = await verifySigsumManifest(enrollment, document);
      for (const { signer, ok, message } of results) {
        process.stdout.write(`Signer ${signer}: ${ok ? "OK" : "FAIL"}${message ? ` (${message})` : ""}\n`);
      }
      const verified = results.filter((r) => r.ok).length;
      passed = verified >= enrollment.threshold;
      process.stdout.write(`${passed ? "VERIFIED" : "FAILED"}: ${verified}/${enrollment.threshold} required signatures verified\n`);
      process.stdout.write(`Enrollment policy hash: ${hashPolicyBytes(enrollment.policy)}\n`);
    } else {
      const results = await verifySigstoreManifest(enrollment, document);
      for (const { index, ok, message } of results) {
        process.stdout.write(`Bundle ${index}: ${ok ? "OK" : "FAIL"}${message ? ` (${message})` : ""}\n`);
      }
      passed = results.some((r) => r.ok);
      process.stdout.write(
        `${passed ? "VERIFIED" : "FAILED"}: ${results.filter((r) => r.ok).length}/${results.length} sigstore bundle(s) satisfy the enrollment claims\n`,
      );
    }
    if (!passed) {
      process.exitCode = 1;
    }
  });

// ---------------------------------------------------------------------------
// bundle

program
  .command("bundle")
  .description("Combine an enrollment and a signed manifest into a bundle")
  .command("create")
  .description("Create a bundle from enrollment and a signed manifest")
  .requiredOption("-e, --enrollment <path>", "Enrollment JSON file")
  .requiredOption("-m, --manifest <path>", "Signed manifest JSON file")
  .option("-o, --output <path>", "Write bundle JSON to a file")
  .action(async (options) => {
    const [enrollment, document] = await Promise.all([loadEnrollment(options.enrollment), loadManifestDocument(options.manifest)]);
    const bundleDocument = { enrollment, manifest: document.manifest, signatures: document.signatures };
    await writeOutput(options.output, JSON.stringify(bundleDocument, null, 2));
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
