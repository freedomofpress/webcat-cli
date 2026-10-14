import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { TrustedRootProvider } from "@freedomofpress/sigstore-browser";
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
  type IdentityProvider,
  type Witness,
} from "@sigstore/sign";
import { ManifestDocument, canonicalizeManifestBody } from "./manifest.js";
import { causeOf, ensureObject, external, invalid, log, sha256 } from "./utils.js";

export { DEFAULT_FULCIO_URL, DEFAULT_REKOR_URL };
export const SIGSTORE_OIDC_ISSUER = "https://oauth2.sigstore.dev/auth";
export const SIGSTORE_OIDC_CLIENT_ID = "sigstore";
export const SIGSTORE_OIDC_SCOPE = "openid email";

export const SAN_OID = "2.5.29.17";
export const ISSUER_V2_OID = "1.3.6.1.4.1.57264.1.8";

// CLI flag -> Fulcio certificate extension OID. Drives both option registration and claim collection.
export const SIGSTORE_CLAIM_FLAGS: ReadonlyArray<readonly [flag: string, oid: string]> = [
  ["subject-alt-name", SAN_OID],
  ["issuer-v1", "1.3.6.1.4.1.57264.1.1"],
  ["workflow-trigger-legacy", "1.3.6.1.4.1.57264.1.2"],
  ["workflow-sha-legacy", "1.3.6.1.4.1.57264.1.3"],
  ["workflow-name-legacy", "1.3.6.1.4.1.57264.1.4"],
  ["workflow-repository-legacy", "1.3.6.1.4.1.57264.1.5"],
  ["workflow-ref-legacy", "1.3.6.1.4.1.57264.1.6"],
  ["issuer-v2", ISSUER_V2_OID],
  ["build-signer-uri", "1.3.6.1.4.1.57264.1.9"],
  ["build-signer-digest", "1.3.6.1.4.1.57264.1.10"],
  ["runner-environment", "1.3.6.1.4.1.57264.1.11"],
  ["source-repository-uri", "1.3.6.1.4.1.57264.1.12"],
  ["source-repository-digest", "1.3.6.1.4.1.57264.1.13"],
  ["source-repository-ref", "1.3.6.1.4.1.57264.1.14"],
  ["source-repository-identifier", "1.3.6.1.4.1.57264.1.15"],
  ["source-repository-owner-uri", "1.3.6.1.4.1.57264.1.16"],
  ["source-repository-owner-identifier", "1.3.6.1.4.1.57264.1.17"],
  ["build-config-uri", "1.3.6.1.4.1.57264.1.18"],
  ["build-config-digest", "1.3.6.1.4.1.57264.1.19"],
  ["build-trigger", "1.3.6.1.4.1.57264.1.20"],
  ["run-invocation-uri", "1.3.6.1.4.1.57264.1.21"],
  ["source-repository-visibility-at-signing", "1.3.6.1.4.1.57264.1.22"],
  ["deployment-environment", "1.3.6.1.4.1.57264.1.23"],
];

export async function fetchCommunityTrustedRoot(): Promise<Record<string, unknown>> {
  const provider = new TrustedRootProvider({ disableCache: true });
  const root = await provider.getTrustedRoot().catch((err) => {
    throw external(`failed to fetch the Sigstore community trusted root via TUF: ${causeOf(err)}`);
  });
  return ensureObject(root, "community trusted root");
}

// ---------------------------------------------------------------------------
// OIDC device authorization (interactive signing)

export interface OidcDeviceFlowOptions {
  issuer: string;
  clientId: string;
  scope: string;
  openBrowser: boolean;
}

async function postForm(url: string, params: Record<string, string>): Promise<any> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  });
  return response.json(); // OAuth error replies are JSON bodies with a 4xx status
}

function openInBrowser(url: string): void {
  const [command, args] =
    process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    spawn(command, args, { stdio: "ignore", detached: true }).on("error", () => {}).unref();
  } catch {
    // best effort only; the URL was already printed
  }
}

export async function fetchInteractiveOidcToken(options: OidcDeviceFlowOptions): Promise<string> {
  const configUrl = `${options.issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  const configResponse = await fetch(configUrl).catch((err) => {
    throw external(`failed to fetch OIDC configuration from ${configUrl}: ${causeOf(err)}`);
  });
  if (!configResponse.ok) {
    throw external(`failed to fetch OIDC configuration from ${configUrl}: HTTP ${configResponse.status} ${configResponse.statusText}`);
  }
  const config = await configResponse.json();
  if (!config.device_authorization_endpoint || !config.token_endpoint) {
    throw external(`failed to use OIDC configuration from ${configUrl}: no device authorization or token endpoint`);
  }

  const verifier = randomBytes(32).toString("base64url");
  const device = await postForm(config.device_authorization_endpoint, {
    client_id: options.clientId,
    scope: options.scope,
    code_challenge: sha256(verifier).toString("base64url"),
    code_challenge_method: "S256",
  });
  if (!device.device_code) {
    throw external(`failed to request OIDC device authorization: ${device.error_description ?? device.error ?? "unexpected response"}`);
  }

  const verificationUrl = device.verification_uri_complete ?? device.verification_uri;
  log(`Open ${verificationUrl} in a browser and enter code ${device.user_code} to authenticate.`);
  if (options.openBrowser) {
    openInBrowser(verificationUrl);
  }

  let interval = Math.max(device.interval ?? 5, 1);
  const deadline = Date.now() + (device.expires_in ?? 600) * 1000;
  while (Date.now() < deadline) {
    await sleep(interval * 1000);
    const payload = await postForm(config.token_endpoint, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.device_code,
      client_id: options.clientId,
      code_verifier: verifier,
    });
    if (payload.id_token) {
      return payload.id_token;
    }
    switch (payload.error) {
      case "authorization_pending":
        continue;
      case "slow_down":
        interval += 5;
        continue;
      case "expired_token":
        throw external("failed to complete OIDC device authorization: code expired");
      default:
        throw external(`failed to complete OIDC device authorization: ${payload.error ?? "response did not include an id_token"}`);
    }
  }
  throw external("failed to complete OIDC device authorization: timed out");
}

// ---------------------------------------------------------------------------
// Signing

export interface SigstoreSignOptions {
  bundleType: "message" | "dsse";
  fulcioUrl: string;
  rekorUrl: string;
  tsaUrl?: string;
  identityProvider: IdentityProvider;
}

export async function signManifestWithSigstore(document: ManifestDocument, options: SigstoreSignOptions): Promise<void> {
  if (document.signatures && !Array.isArray(document.signatures)) {
    throw invalid("manifest.signatures already contains sigsum proofs, Sigstore bundles cannot be mixed in");
  }
  const signer = new FulcioSigner({ fulcioBaseURL: options.fulcioUrl, identityProvider: options.identityProvider });
  const witnesses: Witness[] = [new RekorWitness({ rekorBaseURL: options.rekorUrl })];
  if (options.tsaUrl) {
    witnesses.push(new TSAWitness({ tsaBaseURL: options.tsaUrl }));
  }
  const builder =
    options.bundleType === "dsse" ? new DSSEBundleBuilder({ signer, witnesses }) : new MessageSignatureBundleBuilder({ signer, witnesses });
  const bundle = await builder.create({ data: Buffer.from(canonicalizeManifestBody(document)), type: "application/json" }).catch((err) => {
    throw external(`failed to sign with Sigstore: ${causeOf(err)}`);
  });
  document.signatures = [...(document.signatures ?? []), bundleToJSON(bundle)];
}

export const staticIdentityProvider = (token: string): IdentityProvider => ({ getToken: async () => token });
export const ciIdentityProvider = (audience: string): IdentityProvider => new CIContextProvider(audience);
