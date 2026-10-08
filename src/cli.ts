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
import { fetchTimestampFromPolicy, signManifestWithSigsum, sigsumEnrollmentFromPolicy, verifySigsumManifest } from "./sigsum.js";
import {
  DEFAULT_FULCIO_URL,
  DEFAULT_REKOR_URL,
  DEFAULT_REKOR_V2_URL,
  DEFAULT_TSA_URL,
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
import { CliError, OID_RE, ensureObject, hashPolicyBytes, invalid, log, readJson, readText, sha256, toBase64Url, writeOutput } from "./utils.js";
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
  .addOption(
    new Option("--rekor-api-version <version>", "Rekor API major version: 2 (tile-based log, timestamped by a TSA) or 1 (legacy rekor.sigstore.dev)")
      .choices(["1", "2"])
      .default("2"),
  )
  .option("--rekor-url <url>", `Sigstore Rekor base URL (default: ${DEFAULT_REKOR_V2_URL} for v2, ${DEFAULT_REKOR_URL} for v1)`)
  .option("--tsa-url <url>", `Sigstore timestamp authority base URL (default: ${DEFAULT_TSA_URL} for Rekor v2, none for v1)`)
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
        rekorApiVersion: Number(options.rekorApiVersion) as 1 | 2,
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
