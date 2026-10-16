// Client for the WEBCAT enrollment chain (felidae): oracle submission and status queries.
// Protocol reference: https://github.com/freedomofpress/webcat-infra-chain
import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import { type WebcatLeavesFile, verifyWebcatProof } from "@freedomofpress/ics23/dist/webcat";
import { defaults } from "@freedomofpress/webcat/config";
import { extractHostname, extractRawHash } from "@freedomofpress/webcat/webcat/parsers";
import { type Enrollment, canonicalizeEnrollment, parseEnrollmentObject } from "./enrollment.js";
import { causeOf, external, fetchJson, invalid, sha256 } from "./utils.js";

export const DEFAULT_CHAIN_API = "https://webcat-sentry-1.freedom.press";
export const DEFAULT_LIST_ENDPOINT = defaults.endpoint; // serves list.json and block.json, the extension's own update source
export const WELL_KNOWN_PATH = "/.well-known/webcat/enrollment.json";

export interface Oracle {
  endpoint: string;
  identity?: string;
}

export interface HashRecord {
  domain: string;
  hash: string | null; // hex sha256 of the canonical enrollment; NotFound (unenroll) serializes as null
  time?: string;
  oracle?: string;
}

export interface DomainStatus {
  canonical: string | null;
  pending: HashRecord[];
  votes: HashRecord[];
}

export interface SubmitResult {
  endpoint: string;
  ok: boolean;
  message: string;
}

// Oracles observe FQDNs with a trailing dot; the API accepts both forms.
export const toFqdn = (domain: string): string => domain.trim().replace(/\.+$/, "").toLowerCase() + ".";
export const bareDomain = (domain: string): string => toFqdn(domain).slice(0, -1);

export const enrollmentHashHex = (enrollment: Enrollment): string => sha256(canonicalizeEnrollment(enrollment)).toString("hex");

const joinUrl = (base: string, path: string): string => `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;

// Fetches the enrollment a domain currently serves, exactly like an oracle would.
// Returns null when the domain answers 404/410 (which oracles record as an unenrollment vote).
export async function fetchServedEnrollment(domain: string): Promise<{ hash: string; enrollment: Enrollment } | null> {
  const url = `https://${bareDomain(domain)}${WELL_KNOWN_PATH}`;
  const response = await fetch(url, { redirect: "follow" }).catch((err) => {
    throw external(`failed to fetch ${url}: ${causeOf(err)}`);
  });
  if (response.status === 404 || response.status === 410) {
    return null;
  }
  if (!response.ok) {
    throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
  }
  const parsed = await response.json().catch((err) => {
    throw invalid(`served enrollment at ${url} is not valid JSON: ${causeOf(err)}`);
  });
  const enrollment = parseEnrollmentObject(parsed);
  return { hash: enrollmentHashHex(enrollment), enrollment };
}

// Oracle endpoints come from the chain API unverified; only ever POST to https ones.
export const fetchOracles = async (chainApi: string): Promise<Oracle[]> =>
  ((await fetchJson(joinUrl(chainApi, "/oracles"))) as Oracle[]).filter((o) => typeof o?.endpoint === "string" && o.endpoint.startsWith("https://"));

export async function fetchDomainStatus(chainApi: string, domain: string): Promise<DomainStatus> {
  const fqdn = toFqdn(domain);
  const [snapshot, pending, votes] = await Promise.all([
    fetchJson(joinUrl(chainApi, `/snapshot/${bareDomain(domain)}`)),
    fetchJson(joinUrl(chainApi, `/enrollment/pending/${bareDomain(domain)}`)),
    fetchJson(joinUrl(chainApi, `/enrollment/votes/${bareDomain(domain)}`)),
  ]);
  const onlyThisDomain = (r: HashRecord) => r.domain === fqdn;
  return {
    canonical: snapshot[fqdn] ?? null,
    pending: (pending as HashRecord[]).filter(onlyThisDomain),
    votes: (votes as HashRecord[]).filter(onlyThisDomain),
  };
}

// list.json leaves are decoded exactly as the extension does: bare domain -> hex sha256 of the canonical enrollment.
export const parseListLeaves = (leaves: readonly (readonly string[])[]): Map<string, string> =>
  new Map(leaves.map(([key, value]) => [extractHostname(key), Buffer.from(extractRawHash(value)).toString("hex")]));

export interface VerifiedList {
  blockHeight: number;
  blockTime: Date;
  leaves: Map<string, string>;
}

// Believes the published list only the way the extension does: the block commit must be signed by a quorum of
// the chain's validators (set and chain id shipped with the extension), and the leaves must prove into its app hash.
export async function verifyList(list: WebcatLeavesFile, block: unknown, source = "the published list"): Promise<VerifiedList> {
  const { proto: validators, cryptoIndex } = await importValidators(defaults.validatorSet);
  let signedHeader;
  let commit;
  try {
    signedHeader = importCommit(block as any);
    commit = await verifyCommit(signedHeader, validators, cryptoIndex, defaults.chainId);
  } catch (err) {
    throw external(`failed to verify ${source}: ${causeOf(err)}`);
  }
  if (!commit.ok || !commit.headerTime || !signedHeader.header) {
    throw external(`failed to verify ${source}: block commit is not signed by a quorum of the ${defaults.chainId} validators`);
  }
  if (!Buffer.from(commit.appHash).equals(Buffer.from(String(list.proof?.app_hash ?? ""), "hex"))) {
    throw external(`failed to verify ${source}: list app hash does not match the verified block`);
  }
  const leaves = await verifyWebcatProof(list);
  if (leaves === false) {
    throw external(`failed to verify ${source}: leaves do not prove into the block's app hash`);
  }
  return { blockHeight: Number(signedHeader.header.height), blockTime: new Date(Number(commit.headerTime.seconds) * 1000), leaves: parseListLeaves(leaves) };
}

export async function fetchVerifiedList(endpoint: string): Promise<VerifiedList> {
  const [list, block] = await Promise.all([fetchJson(joinUrl(endpoint, "list.json")), fetchJson(joinUrl(endpoint, "block.json"))]);
  return verifyList(list, block, `${endpoint}`);
}

// ---------------------------------------------------------------------------
// Oracle submission: per-oracle proof of work, then POST /observe.

function leadingZeroBits(hash: Uint8Array): number {
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      bits += 8;
    } else {
      return bits + Math.clz32(byte) - 24;
    }
  }
  return bits;
}

// Finds a nonce such that sha256(challenge + nonce) has at least `difficulty` leading zero bits.
export function solvePow(challenge: string, difficulty: number): number {
  for (let nonce = 0; nonce < 2 ** 32; nonce++) {
    if (leadingZeroBits(sha256(challenge + nonce)) >= difficulty) {
      return nonce;
    }
  }
  throw external(`failed to solve proof of work: no nonce found for difficulty ${difficulty}`);
}

export async function submitObservation(oracle: Oracle, domain: string, options: { dryRun?: boolean } = {}): Promise<SubmitResult> {
  const { endpoint } = oracle;
  try {
    const challenge = await fetchJson(joinUrl(endpoint, `/pow-challenge?domain=${encodeURIComponent(bareDomain(domain))}`));
    const nonce = solvePow(challenge.challenge, challenge.difficulty);
    if (options.dryRun) {
      return { endpoint, ok: true, message: `proof of work solved (difficulty ${challenge.difficulty}); not submitted` };
    }
    const response = await fetch(joinUrl(endpoint, "/observe"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: toFqdn(domain),
        pow_token: { challenge: challenge.challenge, nonce, timestamp: challenge.timestamp },
      }),
    });
    const body = await response.json().catch(() => ({}));
    return { endpoint, ok: response.ok && body.success === true, message: body.message ?? `HTTP ${response.status}` };
  } catch (err) {
    return { endpoint, ok: false, message: causeOf(err) };
  }
}
