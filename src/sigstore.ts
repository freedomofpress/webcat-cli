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
import { causeOf, ensureObject, external, fetchJson, invalid, log, sha256 } from "./utils.js";

export { DEFAULT_FULCIO_URL, DEFAULT_REKOR_URL };
export const DEFAULT_REKOR_V2_URL = "https://log2025-1.rekor.sigstore.dev";
export const DEFAULT_TSA_URL = "https://timestamp.sigstore.dev";
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

// Trusted-root entries by kind: logs are identified by public key, CAs and TSAs by their leaf certificate.
const ROOT_KINDS: Array<[field: string, kind: string, id: (e: any) => string, label: (e: any) => string, validFor: (e: any) => any]> = [
  ["certificateAuthorities", "certificate authority", (e) => e.certChain?.certificates?.[0]?.rawBytes ?? "", (e) => e.uri, (e) => e.validFor],
  ["tlogs", "transparency log", (e) => e.publicKey?.rawBytes ?? "", (e) => e.baseUrl, (e) => e.publicKey?.validFor],
  ["ctlogs", "certificate transparency log", (e) => e.publicKey?.rawBytes ?? "", (e) => e.baseUrl, (e) => e.publicKey?.validFor],
  ["timestampAuthorities", "timestamp authority", (e) => e.certChain?.certificates?.[0]?.rawBytes ?? "", (e) => e.uri, (e) => e.validFor],
];
const activeAt = (validFor: any, now: Date): boolean => (!validFor?.start || new Date(validFor.start) <= now) && (!validFor?.end || new Date(validFor.end) > now);

// What the community root has that a pinned enrollment root lacks: each line is a reason a re-enrollment is coming.
export function trustedRootDrift(pinned: any, community: any, now = new Date()): string[] {
  const drift: string[] = [];
  for (const [field, kind, id, label, validFor] of ROOT_KINDS) {
    const mine = new Map<string, any>((pinned?.[field] ?? []).map((e: any) => [id(e), e]));
    for (const entry of community?.[field] ?? []) {
      const pinnedEntry = mine.get(id(entry));
      if (!pinnedEntry) {
        if (validFor(entry)?.end && new Date(validFor(entry).end) < now) continue; // already retired, nothing to adopt
        drift.push(`new ${kind} ${label(entry)} (valid from ${validFor(entry)?.start ?? "?"}) is not in the enrollment's trusted root`);
      } else if (validFor(entry)?.end && !validFor(pinnedEntry)?.end) {
        drift.push(`${kind} ${label(entry)} ends on ${validFor(entry).end} in the community root`);
      }
    }
  }
  return drift;
}

// Drift that stops signing: for a service kind the signer relies on, none of the community root's currently
// valid entries is in the pinned root, so nothing issued today can verify under the enrollment.
// TSAs only matter when the signer asks for a timestamp.
export function signingBlockedBy(pinned: any, community: any, options: { withTsa?: boolean; now?: Date } = {}): string[] {
  const now = options.now ?? new Date();
  const blocked: string[] = [];
  for (const [field, kind, id, , validFor] of ROOT_KINDS) {
    if (field === "timestampAuthorities" && !options.withTsa) continue;
    const current = (community?.[field] ?? []).filter((e: any) => activeAt(validFor(e), now));
    const pinnedIds = new Set((pinned?.[field] ?? []).map(id));
    if (current.length === 0 || pinnedIds.size === 0) {
      continue; // the enrollment never relied on this kind, or the public instance has none right now
    }
    if (!current.some((e: any) => pinnedIds.has(id(e)))) {
      blocked.push(`no currently valid ${kind} in the community root is in the enrollment's trusted root`);
    }
  }
  return blocked;
}

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
  const config = await fetchJson(configUrl);
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
  rekorUrl?: string;
  rekorApiVersion: 1 | 2;
  tsaUrl?: string;
  identityProvider: IdentityProvider;
}

// Rekor v2 entries carry no signed integrated time, so verifiers need an RFC 3161 timestamp to anchor the signature.
// v2 therefore always gets a TSA; v1 only when asked for one.
export function sigstoreEndpoints(options: Pick<SigstoreSignOptions, "rekorUrl" | "tsaUrl" | "rekorApiVersion">): { rekorUrl: string; tsaUrl?: string } {
  const v2 = options.rekorApiVersion === 2;
  return {
    rekorUrl: options.rekorUrl || (v2 ? DEFAULT_REKOR_V2_URL : DEFAULT_REKOR_URL),
    tsaUrl: options.tsaUrl || (v2 ? DEFAULT_TSA_URL : undefined),
  };
}

export async function signManifestWithSigstore(document: ManifestDocument, options: SigstoreSignOptions): Promise<void> {
  if (document.signatures && !Array.isArray(document.signatures)) {
    throw invalid("manifest.signatures already contains sigsum proofs, Sigstore bundles cannot be mixed in");
  }
  const { rekorUrl, tsaUrl } = sigstoreEndpoints(options);
  const signer = new FulcioSigner({ fulcioBaseURL: options.fulcioUrl, identityProvider: options.identityProvider });
  const witnesses: Witness[] = [new RekorWitness({ rekorBaseURL: rekorUrl, majorApiVersion: options.rekorApiVersion })];
  if (tsaUrl) {
    witnesses.push(new TSAWitness({ tsaBaseURL: tsaUrl }));
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
