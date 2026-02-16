#!/usr/bin/env node
import { Command } from "commander";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import process from "node:process";
import path from "node:path";
import { tmpdir } from "node:os";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler.js";
import { parsePolicyText } from "@freedomofpress/sigsum/dist/config.js";
import {
  Hash,
  KeyHash,
  Leaf,
  RawPublicKey,
  Signature,
} from "@freedomofpress/sigsum/dist/types.js";
import { verifyHashWithCompiledPolicy } from "@freedomofpress/sigsum/dist/verify.js";
import { SigsumProof } from "@freedomofpress/sigsum/dist/proof.js";
import { bundleToJSON } from "@sigstore/bundle";
import {
  CIContextProvider,
  DEFAULT_FULCIO_URL,
  DEFAULT_REKOR_URL,
  DSSEBundleBuilder,
  FulcioSigner,
  MessageSignatureBundleBuilder,
  RekorWitness,
  TSAWitness,
  type Witness,
} from "@sigstore/sign";
import { Updater } from "tuf-js";
import { canonicalize } from "./canonicalize.js";
import { EnrollmentInput, buildEnrollmentObject, loadEnrollment } from "./enrollment.js";
import { writeCasObject } from "./cas.js";
import {
  ManifestDocument,
  ManifestContent,
  canonicalizeManifestBody,
  loadManifestConfig,
  loadManifestDocument,
  scanDirectory,
} from "./manifest.js";
import { loadBundleDocument } from "./bundle.js";
import { deriveSignerKeyFromPrivateKey, fetchTimestampFromPolicy, runSigsumSubmit } from "./sigsum.js";
import { decodeKeyMaterial, decodePolicyBytes, hashPolicyBytes, toBase64Url } from "./utils.js";

const SIGSTORE_TUF_BASE_URL = "https://tuf-repo-cdn.sigstore.dev";
const SIGSTORE_TUF_ROOT_URL = `${SIGSTORE_TUF_BASE_URL}/1.root.json`;
const SIGSTORE_TUF_TARGETS_URL = `${SIGSTORE_TUF_BASE_URL}/targets`;
const SIGSTORE_TRUSTED_ROOT_TARGET = "trusted_root.json";
const SIGSTORE_OIDC_ISSUER = "https://oauth2.sigstore.dev/auth";
const SIGSTORE_OIDC_CLIENT_ID = "sigstore";
const SIGSTORE_OIDC_SCOPE = "openid email";

export const SIGSTORE_CLAIM_OIDS = {
  // Standard X.509
  subjectAltName: "2.5.29.17",

  // Fulcio base
  issuerV1: "1.3.6.1.4.1.57264.1.1",
  workflowTriggerLegacy: "1.3.6.1.4.1.57264.1.2",
  workflowShaLegacy: "1.3.6.1.4.1.57264.1.3",
  workflowNameLegacy: "1.3.6.1.4.1.57264.1.4",
  workflowRepositoryLegacy: "1.3.6.1.4.1.57264.1.5",
  workflowRefLegacy: "1.3.6.1.4.1.57264.1.6",

  // Current issuer
  issuerV2: "1.3.6.1.4.1.57264.1.8",

  // Workflow identity
  buildSignerUri: "1.3.6.1.4.1.57264.1.9",
  buildSignerDigest: "1.3.6.1.4.1.57264.1.10",
  runnerEnvironment: "1.3.6.1.4.1.57264.1.11",

  // Source repository
  sourceRepositoryUri: "1.3.6.1.4.1.57264.1.12",
  sourceRepositoryDigest: "1.3.6.1.4.1.57264.1.13",
  sourceRepositoryRef: "1.3.6.1.4.1.57264.1.14",
  sourceRepositoryIdentifier: "1.3.6.1.4.1.57264.1.15",
  sourceRepositoryOwnerUri: "1.3.6.1.4.1.57264.1.16",
  sourceRepositoryOwnerIdentifier: "1.3.6.1.4.1.57264.1.17",

  // Build config
  buildConfigUri: "1.3.6.1.4.1.57264.1.18",
  buildConfigDigest: "1.3.6.1.4.1.57264.1.19",

  // Execution context
  buildTrigger: "1.3.6.1.4.1.57264.1.20",
  runInvocationUri: "1.3.6.1.4.1.57264.1.21",
  sourceRepositoryVisibilityAtSigning: "1.3.6.1.4.1.57264.1.22",
  deploymentEnvironment: "1.3.6.1.4.1.57264.1.23",
} as const;

type SigstoreClaimOption = { oid: string; value: string };

type DeviceAuthResponse = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
};

type OidcConfig = {
  device_authorization_endpoint?: string;
  token_endpoint?: string;
};

type PkcePair = {
  verifier: string;
  challenge: string;
};

async function writeMaybe(filePath: string | undefined, contents: string): Promise<void> {
  if (filePath) {
    await writeFile(filePath, contents);
  } else {
    process.stdout.write(contents + "\n");
  }
}

function collectSigner(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}


function collectClaim(value: string, previous: SigstoreClaimOption[]): SigstoreClaimOption[] {
  const separatorIndex = value.indexOf("=");
  if (separatorIndex <= 0) {
    throw new Error("--claim values must be in OID=value format");
  }
  const oid = value.slice(0, separatorIndex).trim();
  const claimValue = value.slice(separatorIndex + 1).trim();
  if (!/^\d+(?:\.\d+)+$/.test(oid)) {
    throw new Error(`--claim key must be an OID, got '${oid}'`);
  }
  if (!claimValue) {
    throw new Error("--claim value must be non-empty");
  }
  previous.push({ oid, value: claimValue });
  return previous;
}

function setClaim(
  previous: SigstoreClaimOption[] | undefined,
  oid: string,
  value: string,
): SigstoreClaimOption[] {
  const claims = previous ?? [];
  claims.push({ oid, value: value.trim() });
  return claims;
}

function claimsToRecord(claims: SigstoreClaimOption[]): Record<string, string> {
  const record: Record<string, string> = {};
  for (const claim of claims) {
    if (!claim.value) {
      throw new Error(`claim value for OID '${claim.oid}' must be non-empty`);
    }
    record[claim.oid] = claim.value;
  }
  return record;
}

async function fetchSigstoreCommunityTrustedRoot(): Promise<string> {
  const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-sigstore-tuf-"));
  try {
    const rootResponse = await fetch(SIGSTORE_TUF_ROOT_URL);
    if (!rootResponse.ok) {
      throw new Error(
        `failed to download Sigstore TUF root (${rootResponse.status} ${rootResponse.statusText})`,
      );
    }
    const rootText = await rootResponse.text();
    await writeFile(path.join(tempDir, "root.json"), rootText);

    const updater = new Updater({
      metadataDir: tempDir,
      metadataBaseUrl: SIGSTORE_TUF_BASE_URL,
      targetDir: tempDir,
      targetBaseUrl: SIGSTORE_TUF_TARGETS_URL,
      config: { userAgent: "webcat-cli" },
    });
    await updater.refresh();

    const targetInfo = await updater.getTargetInfo(SIGSTORE_TRUSTED_ROOT_TARGET);
    if (!targetInfo) {
      throw new Error("Sigstore trusted_root.json target not found in the TUF repository");
    }
    const targetPath = await updater.downloadTarget(targetInfo);
    return await readFile(targetPath, "utf8");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function fetchOidcConfiguration(issuer: string): Promise<OidcConfig> {
  const trimmed = issuer.replace(/\/+$/, "");
  const response = await fetch(`${trimmed}/.well-known/openid-configuration`);
  if (!response.ok) {
    throw new Error(`failed to load OIDC configuration (${response.status} ${response.statusText})`);
  }
  const parsed = (await response.json()) as OidcConfig;
  return parsed;
}

async function requestDeviceAuthorization(
  issuer: string,
  clientId: string,
  scope: string,
  pkce: PkcePair,
): Promise<DeviceAuthResponse> {
  const config = await fetchOidcConfiguration(issuer);
  if (!config.device_authorization_endpoint) {
    throw new Error("OIDC configuration is missing device authorization endpoint");
  }
  const response = await fetch(config.device_authorization_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      scope,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    }).toString(),
  });
  if (!response.ok) {
    throw new Error(
      `failed to request device authorization (${response.status} ${response.statusText})`,
    );
  }
  return (await response.json()) as DeviceAuthResponse;
}

async function exchangeDeviceCode(
  issuer: string,
  clientId: string,
  deviceCode: string,
  intervalSeconds: number,
  pkce: PkcePair,
): Promise<string> {
  const config = await fetchOidcConfiguration(issuer);
  if (!config.token_endpoint) {
    throw new Error("OIDC configuration is missing token endpoint");
  }
  let interval = Math.max(intervalSeconds, 1);
  const started = Date.now();
  while (true) {
    await new Promise((resolve) => setTimeout(resolve, interval * 1000));
    const response = await fetch(config.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: clientId,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    const payload = (await response.json()) as {
      access_token?: string;
      id_token?: string;
      error?: string;
    };
    if (payload.id_token) {
      return payload.id_token;
    }
    if (payload.access_token) {
      throw new Error("OIDC device authorization returned access_token but no id_token");
    }
    if (payload.error === "authorization_pending") {
      continue;
    }
    if (payload.error === "slow_down") {
      interval += 5;
      continue;
    }
    if (payload.error === "expired_token") {
      throw new Error("OIDC device code expired before authorization completed");
    }
    if (payload.error) {
      throw new Error(`OIDC device authorization failed: ${payload.error}`);
    }
    if (Date.now() - started > 10 * 60 * 1000) {
      throw new Error("OIDC device authorization timed out");
    }
  }
}

function openBrowser(url: string): void {
  const platform = process.platform;
  let command: string;
  let args: string[];
  if (platform === "darwin") {
    command = "open";
    args = [url];
  } else if (platform === "win32") {
    command = "cmd";
    args = ["/c", "start", "", url];
  } else {
    command = "xdg-open";
    args = [url];
  }
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.unref();
  } catch {
    // Best-effort only.
  }
}

async function fetchInteractiveOidcToken(
  issuer: string,
  clientId: string,
  scope: string,
  openBrowserWindow: boolean,
): Promise<string> {
  const pkce = createPkcePair();
  const deviceAuth = await requestDeviceAuthorization(issuer, clientId, scope, pkce);
  const verificationUrl = deviceAuth.verification_uri_complete ?? deviceAuth.verification_uri;
  process.stdout.write(
    `Open ${verificationUrl} in a browser and enter code ${deviceAuth.user_code} to authenticate.\n`,
  );
  if (openBrowserWindow) {
    openBrowser(verificationUrl);
  }
  const interval = deviceAuth.interval ?? 5;
  return await exchangeDeviceCode(issuer, clientId, deviceAuth.device_code, interval, pkce);
}

function createPkcePair(): PkcePair {
  const verifier = toBase64Url(randomBytes(32));
  const challenge = toBase64Url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function parseTrustedRootJson(value: string, source: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err: any) {
    throw new Error(`failed to parse trusted root from ${source}: ${err.message}`);
  }
}

const program = new Command();
program.name("webcat-cli").description("Utilities for WEBCAT enrollment and manifest generation and validation");

const enrollment = program.command("enrollment").description("Enrollment helpers");

enrollment
  .command("create")
  .description("Create an enrollment definition")
  .option("-p, --policy-file <path>", "Sigsum policy file to compile")
  .option("-s, --signer <key>", "Signer public key (hex or base64)", collectSigner, [] as string[])
  .option("-t, --threshold <k>", "Threshold for signature approval")
  .option("-m, --max-age <seconds>", "Maximum age in seconds")
  .option("-c, --cas-url <url>", "CAS https URL")
  .option("--type <type>", "Enrollment type (sigsum or sigstore)", "sigsum")
  .option("--trusted-root <path>", "Sigstore trusted root file")
  .option("--community-trusted-root", "Fetch the Sigstore community trusted root via TUF")
  .option("--issuer <value>", "Sigstore issuer (maps to OID 1.3.6.1.4.1.57264.1.8)")
  .option("--identity <value>", "Sigstore identity (maps to OID 2.5.29.17)")
  .option("--claim <oid=value>", "Sigstore claim constraint by OID", collectClaim, [] as SigstoreClaimOption[])
  .option("--source-repository-uri <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.12")
  .option("--source-repository-digest <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.13")
  .option("--source-repository-ref <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.14")
  .option("--source-repository-identifier <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.15")
  .option("--source-repository-owner-uri <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.16")
  .option("--source-repository-owner-identifier <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.17")

  .option("--build-signer-uri <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.9")
  .option("--build-signer-digest <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.10")
  .option("--runner-environment <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.11")

  .option("--build-config-uri <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.18")
  .option("--build-config-digest <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.19")

  .option("--build-trigger <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.20")
  .option("--run-invocation-uri <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.21")
  .option("--source-repository-visibility-at-signing <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.22")
  .option("--deployment-environment <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.23")

  .option("--issuer-v1 <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.1")
  .option("--issuer-v2 <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.8")
  .option("--subject-alt-name <value>", "Sigstore claim OID 2.5.29.17")

  .option("--workflow-trigger-legacy <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.2")
  .option("--workflow-sha-legacy <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.3")
  .option("--workflow-name-legacy <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.4")
  .option("--workflow-repository-legacy <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.5")
  .option("--workflow-ref-legacy <value>", "Sigstore claim OID 1.3.6.1.4.1.57264.1.6")
  .option("-o, --output <path>", "Write result to file instead of stdout")
  .action(async (options: any) => {
    const enrollmentType = options.type ?? "sigsum";
    if (enrollmentType !== "sigsum" && enrollmentType !== "sigstore") {
      throw new Error("enrollment type must be 'sigsum' or 'sigstore'");
    }

    let enrollmentObject: EnrollmentInput;
    if (enrollmentType === "sigsum") {
      if (!options.policyFile) {
        throw new Error("--policy-file is required for sigsum enrollments");
      }
      if (!options.threshold) {
        throw new Error("--threshold is required for sigsum enrollments");
      }
      if (!options.maxAge) {
        throw new Error("--max-age is required for sigsum enrollments");
      }
      if (!options.casUrl) {
        throw new Error("--cas-url is required for sigsum enrollments");
      }

      const policyText = await readFile(options.policyFile, "utf8");
      const compiled = await compilePolicy(policyText);
      const policyEncoded = toBase64Url(compiled);
      const parsedPolicy = await parsePolicyText(policyText);
      const logsEntries = await Promise.all(
        Array.from(parsedPolicy.logs.values()).map(async (entity) => {
          const rawKey = await crypto.subtle.exportKey("raw", entity.publicKey.key);
          const key = toBase64Url(new Uint8Array(rawKey));
          const url = typeof entity.url === "string" ? entity.url : "";
          return [key, url] as const;
        })
      );
      logsEntries.sort(([a], [b]) => a.localeCompare(b));
      const logs = Object.fromEntries(logsEntries);

      enrollmentObject = buildEnrollmentObject({
        type: "sigsum",
        policy: policyEncoded,
        signers: options.signer,
        threshold: options.threshold,
        maxAge: options.maxAge,
        casUrl: options.casUrl,
        logs,
      });
    } else {
      if (options.communityTrustedRoot && options.trustedRoot) {
        throw new Error("use either --trusted-root or --community-trusted-root for sigstore enrollments");
      }
      if (!options.trustedRoot && !options.communityTrustedRoot) {
        throw new Error("--trusted-root or --community-trusted-root is required for sigstore enrollments");
      }
      if (!options.maxAge) {
        throw new Error("--max-age is required for sigstore enrollments");
      }
      const claims: SigstoreClaimOption[] = [...(options.claim ?? [])];

      // helper
      const add = (oid: string, value?: string) => {
        if (value) {
          claims.push({ oid, value: String(value).trim() });
        }
      };

      // baseline
      add(SIGSTORE_CLAIM_OIDS.subjectAltName, options.identity);
      add(SIGSTORE_CLAIM_OIDS.subjectAltName, options.subjectAltName);

      add(SIGSTORE_CLAIM_OIDS.issuerV2, options.issuerV2 ?? options.issuer);
      add(SIGSTORE_CLAIM_OIDS.issuerV1, options.issuerV1);

      // structured OIDs
      add(SIGSTORE_CLAIM_OIDS.buildSignerUri, options.buildSignerUri);
      add(SIGSTORE_CLAIM_OIDS.buildSignerDigest, options.buildSignerDigest);
      add(SIGSTORE_CLAIM_OIDS.runnerEnvironment, options.runnerEnvironment);

      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryUri, options.sourceRepositoryUri);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryDigest, options.sourceRepositoryDigest);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryRef, options.sourceRepositoryRef);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryIdentifier, options.sourceRepositoryIdentifier);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryOwnerUri, options.sourceRepositoryOwnerUri);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryOwnerIdentifier, options.sourceRepositoryOwnerIdentifier);

      add(SIGSTORE_CLAIM_OIDS.buildConfigUri, options.buildConfigUri);
      add(SIGSTORE_CLAIM_OIDS.buildConfigDigest, options.buildConfigDigest);

      add(SIGSTORE_CLAIM_OIDS.buildTrigger, options.buildTrigger);
      add(SIGSTORE_CLAIM_OIDS.runInvocationUri, options.runInvocationUri);
      add(SIGSTORE_CLAIM_OIDS.sourceRepositoryVisibilityAtSigning, options.sourceRepositoryVisibilityAtSigning);
      add(SIGSTORE_CLAIM_OIDS.deploymentEnvironment, options.deploymentEnvironment);

      add(SIGSTORE_CLAIM_OIDS.workflowTriggerLegacy, options.workflowTriggerLegacy);
      add(SIGSTORE_CLAIM_OIDS.workflowShaLegacy, options.workflowShaLegacy);
      add(SIGSTORE_CLAIM_OIDS.workflowNameLegacy, options.workflowNameLegacy);
      add(SIGSTORE_CLAIM_OIDS.workflowRepositoryLegacy, options.workflowRepositoryLegacy);
      add(SIGSTORE_CLAIM_OIDS.workflowRefLegacy, options.workflowRefLegacy);

      if (claims.length === 0) {
        throw new Error(
          "at least one sigstore claim is required (use --claim and/or --identity/--issuer)",
        );
      }
      let trustedRoot: Record<string, unknown>;
      if (options.communityTrustedRoot) {
        trustedRoot = parseTrustedRootJson(
          await fetchSigstoreCommunityTrustedRoot(),
          "Sigstore TUF community trusted root",
        );
      } else {
        const trustedRootPath = options.trustedRoot;
        if (!trustedRootPath) {
          throw new Error("--trusted-root is required for sigstore enrollments");
        }
        trustedRoot = parseTrustedRootJson(
          await readFile(trustedRootPath, "utf8"),
          trustedRootPath,
        );
      }
      enrollmentObject = buildEnrollmentObject({
        type: "sigstore",
        trustedRoot,
        claims: claimsToRecord(claims),
        maxAge: options.maxAge,
      });
    }

    const json = JSON.stringify(enrollmentObject, null, 2);
    const { hash, filePath } = await writeCasObject(json);
    process.stdout.write(`Saved enrollment to ${filePath} (sha256=${hash}).\n`);
    await writeMaybe(options.output, json);
  });

enrollment
  .command("canonicalize")
  .description("Canonicalize an enrollment JSON file")
  .requiredOption("-e, --enrollment <path>", "Enrollment file to canonicalize")
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options: { input: string; output?: string }) => {
    const enrollmentObject = await loadEnrollment(options.input);
    const canonical = canonicalize(enrollmentObject);
    await writeMaybe(options.output, canonical);
  });

enrollment
  .command("hash")
  .description("Canonicalize and hash an enrollment file")
  .requiredOption("-i, --input <path>", "Enrollment file to hash")
  .action(async (options: { input: string }) => {
    const enrollmentObject = await loadEnrollment(options.input);
    const canonical = canonicalize(enrollmentObject);
    const digest = createHash("sha256").update(canonical).digest();
    const encodedHash = toBase64Url(digest);
    process.stdout.write(encodedHash + "\n");
  });


const manifest = program.command("manifest").description("Manifest helpers");
const collectValues = (value: string, previous: string[] = []) => previous.concat(value);

manifest
  .command("generate")
  .description("Generate a manifest from a directory and config")
  .option("--type <type>", "Manifest type (sigsum or sigstore)", "sigsum")
  .requiredOption("-c, --config <path>", "Manifest config JSON file")
  .requiredOption("-d, --directory <path>", "Directory containing site assets")
  .option("-p, --policy-file <path>", "Sigsum policy file for timestamps")
  .option("--include-dotfiles", "Include dotfiles and dotfolders in the manifest")
  .option("--exclude <path>", "Exclude a file or directory from the manifest (repeatable)", collectValues)
  .option("-o, --output <path>", "Write manifest to a file instead of stdout")
  .action(
    async (options: {
      type?: string;
      config: string;
      directory: string;
      policyFile?: string;
      includeDotfiles?: boolean;
      exclude?: string[];
      output?: string;
    }) => {
      const type = options.type ?? "sigsum";
      if (type !== "sigsum" && type !== "sigstore") {
        throw new Error("manifest type must be 'sigsum' or 'sigstore'");
      }
      if (type === "sigsum" && !options.policyFile) {
        throw new Error("--policy-file is required for sigsum manifests");
      }
      const [config, scan, policyText] = await Promise.all([
        loadManifestConfig(options.config),
        scanDirectory(options.directory, {
          includeDotfiles: options.includeDotfiles,
          excludePaths: options.exclude,
        }),
        type === "sigsum" && options.policyFile ? readFile(options.policyFile, "utf8") : Promise.resolve(""),
      ]);
      const indexKey = "/" + config.default_index.replace(/^\/+/, "");
      if (!scan.files.has(indexKey)) {
        throw new Error(`default_index ${config.default_index} was not found in the scanned files`);
      }
      if (!scan.files.has(config.default_fallback)) {
        throw new Error(`default_fallback ${config.default_fallback} was not found in the scanned files`);
      }
      const timestamp = type === "sigsum" ? await fetchTimestampFromPolicy(policyText) : undefined;
      const filesObject = Object.fromEntries(
        Array.from(scan.files.entries()).sort(([a], [b]) => a.localeCompare(b))
      );
      const wasmList = Array.from(new Set([...config.wasm, ...scan.wasm])).sort();
      const extraCsp = Object.fromEntries(
        Object.entries(config.extra_csp).sort(([a], [b]) => a.localeCompare(b))
      );
      const manifest: ManifestContent = {
        app: config.app,
        version: config.version,
        default_csp: config.default_csp,
        files: filesObject,
        default_index: config.default_index,
        default_fallback: config.default_fallback,
        wasm: wasmList,
        extra_csp: extraCsp,
      };
      if (timestamp) {
        manifest.timestamp = timestamp;
      }
      const manifestDocument: ManifestDocument = {
        manifest,
      };
      const json = JSON.stringify(manifestDocument, null, 2);
      await writeMaybe(options.output, json);
    }
  );

manifest
  .command("sign")
  .description("Sign a manifest with sigsum (default) or sigstore")
  .option("--type <type>", "Signature type (sigsum or sigstore)", "sigsum")
  .requiredOption("-i, --input <path>", "Manifest file to sign")
  .option("-p, --policy-file <path>", "Sigsum trust policy file for sigsum-submit")
  .option("-k, --key <path>", "Sigsum private key for signing")
  .option(
    "--bundle-type <type>",
    "Sigstore bundle type to generate (message or dsse)",
    "message",
  )
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
  .action(
    async (options: {
      type?: string;
      input: string;
      policyFile?: string;
      key?: string;
      bundleType?: string;
      fulcioUrl?: string;
      rekorUrl?: string;
      tsaUrl?: string;
      oidcAudience?: string;
      oidcIssuer?: string;
      oidcClientId?: string;
      oidcScope?: string;
      oidcToken?: string;
      interactive?: boolean;
      openBrowser?: boolean;
      signer: string;
      output?: string;
    }) => {
      const type = options.type ?? "sigsum";
      if (type !== "sigsum" && type !== "sigstore") {
        throw new Error("sign type must be 'sigsum' or 'sigstore'");
      }
      const document = await loadManifestDocument(options.input);
      const canonicalManifest = canonicalizeManifestBody(document);

      if (type === "sigsum") {
        if (!options.policyFile) {
          throw new Error("--policy-file is required for sigsum signing");
        }
        if (!options.key) {
          throw new Error("--key is required for sigsum signing");
        }
        const signerKey = await deriveSignerKeyFromPrivateKey(options.key);
        if (Array.isArray(document.signatures)) {
          throw new Error("manifest already contains sigstore signatures");
        }
        if (!Array.isArray(document.signatures) && document.signatures?.[signerKey]) {
          throw new Error("manifest already contains a signature for this signer");
        }
        if (!document.signatures || Array.isArray(document.signatures)) {
          document.signatures = {};
        }
        const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-manifest-"));
        const tempFile = path.join(tempDir, "manifest.json");
        try {
          await writeFile(tempFile, canonicalManifest);
          await runSigsumSubmit(options.policyFile, options.key, tempFile);
          const proofPath = `${tempFile}.proof`;
          let proofText: string;
          try {
            const proofRaw = await readFile(proofPath, "utf8");
            proofText = proofRaw.trim();
          } catch (err: any) {
            throw new Error(`failed to read Sigsum proof (${err.message})`);
          }
          if (proofText.length === 0) {
            throw new Error("Sigsum proof was empty");
          }
          const proof = await SigsumProof.fromAscii(proofText);
          const messageHash = createHash("sha256").update(canonicalManifest).digest();
          const checksum = new Hash(createHash("sha256").update(messageHash).digest());
          const leaf = new Leaf(
            checksum,
            new Signature(proof.leaf.Signature.bytes),
            new KeyHash(proof.leaf.KeyHash.bytes),
          );
          const leafBytes = leaf.toBytes();
          const { hash: leafHash, filePath: leafPath } = await writeCasObject(leafBytes, {
            upload: true,
          });
          process.stdout.write(`Saved raw Sigsum leaf to ${leafPath} (sha256=${leafHash}).\n`);
          const { hash: checksumHash, filePath: checksumPath } = await writeCasObject(messageHash, {
            upload: true,
          });
          process.stdout.write(`Saved Sigsum checksum payload to ${checksumPath} (sha256=${checksumHash}).\n`);
          const { hash: manifestHash, filePath: manifestPath } = await writeCasObject(
            canonicalManifest,
            { upload: true },
          );
          process.stdout.write(`Saved canonical manifest to ${manifestPath} (sha256=${manifestHash}).\n`);
          document.signatures[signerKey] = proofText;
        } finally {
          await rm(tempDir, { recursive: true, force: true });
        }
        const json = JSON.stringify(document, null, 2);
        await writeMaybe(options.output, json);
        return;
      }

      const bundleType = options.bundleType ?? "message";
      if (bundleType !== "message" && bundleType !== "dsse") {
        throw new Error("bundle type must be 'message' or 'dsse'");
      }
      if (options.oidcToken && options.interactive) {
        throw new Error("use either --oidc-token or --interactive, not both");
      }
      let identityProvider: CIContextProvider | { getToken: () => Promise<string> };
      if (options.oidcToken) {
        const token = options.oidcToken;
        identityProvider = { getToken: async () => token };
      } else if (options.interactive) {
        const issuer = options.oidcIssuer ?? SIGSTORE_OIDC_ISSUER;
        const clientId = options.oidcClientId ?? SIGSTORE_OIDC_CLIENT_ID;
        const scope = options.oidcScope ?? SIGSTORE_OIDC_SCOPE;
        const openBrowserWindow = options.openBrowser ?? true;
        const token = await fetchInteractiveOidcToken(issuer, clientId, scope, openBrowserWindow);
        identityProvider = { getToken: async () => token };
      } else {
        identityProvider = new CIContextProvider(options.oidcAudience ?? "sigstore");
      }
      const signer = new FulcioSigner({
        fulcioBaseURL: options.fulcioUrl ?? DEFAULT_FULCIO_URL,
        identityProvider,
      });
      const witnesses: Witness[] = [
        new RekorWitness({ rekorBaseURL: options.rekorUrl ?? DEFAULT_REKOR_URL }),
      ];
      if (options.tsaUrl) {
        witnesses.push(new TSAWitness({ tsaBaseURL: options.tsaUrl }));
      }
      const builder =
        bundleType === "dsse"
          ? new DSSEBundleBuilder({ signer, witnesses })
          : new MessageSignatureBundleBuilder({ signer, witnesses });
      const bundle = await builder.create({
        data: Buffer.from(canonicalManifest),
        type: "application/json",
      });
      const serializedBundle = bundleToJSON(bundle);
      if (document.signatures && !Array.isArray(document.signatures)) {
        throw new Error("manifest already contains sigsum signatures");
      }
      if (!document.signatures || !Array.isArray(document.signatures)) {
        document.signatures = [];
      }
      document.signatures.push(serializedBundle);
      const json = JSON.stringify(document, null, 2);
      await writeMaybe(options.output, json);
    }
  );

manifest
  .command("canonicalize")
  .description("Canonicalize a manifest JSON file")
  .requiredOption("-i, --input <path>", "Manifest file to canonicalize")
  .option("-o, --output <path>", "Write canonical JSON to a file")
  .action(async (options: { input: string; output?: string }) => {
    const document = await loadManifestDocument(options.input);
    const canonical = canonicalizeManifestBody(document);
    await writeMaybe(options.output, canonical);
  });

manifest
  .command("hash")
  .description("Canonicalize and hash a manifest file")
  .requiredOption("-m, --manifest <path>", "Manifest file to hash")
  .action(async (options: { input: string }) => {
    const document = await loadManifestDocument(options.input);
    const canonical = canonicalizeManifestBody(document);
    const digest = createHash("sha256").update(canonical).digest();
    process.stdout.write(toBase64Url(digest) + "\n");
  });

manifest
  .command("verify")
  .description(
    "Verify that a manifest (or bundle) satisfies the enrollment signer threshold",
  )
  .argument(
    "<bundle>",
    "Path to a bundle JSON file",
  )
  .argument(
    "[manifest]",
    "Path to a signed manifest JSON file (omit when providing a bundle)",
  )
  .action(
    async (primaryPath: string, manifestPath?: string) => {
      let enrollment: EnrollmentInput;
      let manifestDocument: ManifestDocument;

      if (manifestPath) {
        enrollment = await loadEnrollment(primaryPath);
        manifestDocument = await loadManifestDocument(manifestPath);
      } else {
        const bundle = await loadBundleDocument(primaryPath);
        enrollment = bundle.enrollment;
        manifestDocument = bundle.manifest;
      }
      if (enrollment.type !== "sigsum") {
        throw new Error("manifest verification is only supported for sigsum enrollments");
      }
      const canonicalManifest = canonicalizeManifestBody(manifestDocument);
      const manifestHash = new Uint8Array(
        createHash("sha256").update(canonicalManifest).digest(),
      );
      const compiledPolicy = decodePolicyBytes(enrollment.policy);
      const policyHash = hashPolicyBytes(enrollment.policy);

      const signerResults: { signer: string; ok: boolean; message?: string }[] = [];
      let verified = 0;

      for (const signer of enrollment.signers) {
        const proofText =
          manifestDocument.signatures && !Array.isArray(manifestDocument.signatures)
            ? manifestDocument.signatures[signer]
            : undefined;
        if (!proofText) {
          signerResults.push({ signer, ok: false, message: "signature missing" });
          continue;
        }
        try {
          const signerKey = new RawPublicKey(
            new Uint8Array(decodeKeyMaterial(signer, "enrollment signer")),
          );
          const ok = await verifyHashWithCompiledPolicy(
            manifestHash,
            signerKey,
            compiledPolicy,
            proofText,
          );
          if (ok) {
            verified += 1;
            signerResults.push({ signer, ok: true });
          } else {
            signerResults.push({ signer, ok: false, message: "invalid proof" });
          }
        } catch (err: any) {
          signerResults.push({ signer, ok: false, message: err.message });
        }
      }

      for (const result of signerResults) {
        const status = result.ok ? "OK" : "FAIL";
        const extra = result.message ? ` (${result.message})` : "";
        process.stdout.write(`Signer ${result.signer}: ${status}${extra}\n`);
      }

      const passed = verified >= enrollment.threshold;
      const summaryStatus = passed ? "VERIFIED" : "FAILED";
      process.stdout.write(
        `${summaryStatus}: ${verified}/${enrollment.threshold} required signatures verified\n`,
      );
      process.stdout.write(`Enrollment policy hash: ${policyHash}\n`);
    },
  );

const bundle = program.command("bundle").description("Bundle helpers");

bundle
  .command("create")
  .description("Create a bundle from enrollment and a signed manifest")
  .requiredOption("-e, --enrollment <path>", "Enrollment JSON file")
  .requiredOption("-m, --manifest <path>", "Signed manifest JSON file")
  .option("-o, --output <path>", "Write bundle JSON to a file")
  .action(
    async (options: { enrollment: string; manifest: string; output?: string }) => {
      const [enrollment, manifestDocument] = await Promise.all([
        loadEnrollment(options.enrollment),
        loadManifestDocument(options.manifest),
      ]);
      const bundleDocument = {
        enrollment,
        manifest: manifestDocument.manifest,
        signatures: manifestDocument.signatures,
      };
      const json = JSON.stringify(bundleDocument, null, 2);
      await writeMaybe(options.output, json);
    }
  );

if (process.env.NODE_ENV !== "test") {
  program.parseAsync(process.argv).catch((err: any) => {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(1);
  });
}
