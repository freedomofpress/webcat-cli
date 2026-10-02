// Client for the WEBCAT enrollment chain (felidae): oracle submission and status queries.
// Protocol reference: https://github.com/freedomofpress/webcat-infra-chain
import { canonicalize } from "./canonicalize.js";
import { EnrollmentInput, parseEnrollmentObject } from "./enrollment.js";
import { causeOf, external, invalid, sha256 } from "./utils.js";

export const DEFAULT_CHAIN_API = "https://webcat-sentry-1.freedom.press";
export const DEFAULT_LIST_URL = "https://webcat.freedom.press/list.json";
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

export const enrollmentHashHex = (enrollment: EnrollmentInput): string => sha256(canonicalize(enrollment)).toString("hex");

async function fetchJson(url: string, init?: RequestInit): Promise<any> {
  const response = await fetch(url, init).catch((err) => {
    throw external(`failed to fetch ${url}: ${causeOf(err)}`);
  });
  if (!response.ok) {
    throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
  }
  return response.json().catch((err) => {
    throw external(`failed to fetch ${url}: not valid JSON: ${causeOf(err)}`);
  });
}

const joinUrl = (base: string, path: string): string => `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;

// Fetches the enrollment a domain currently serves, exactly like an oracle would.
// Returns null when the domain answers 404/410 (which oracles record as an unenrollment vote).
export async function fetchServedEnrollment(domain: string): Promise<{ hash: string; enrollment: EnrollmentInput } | null> {
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

export const fetchOracles = (chainApi: string): Promise<Oracle[]> => fetchJson(joinUrl(chainApi, "/oracles"));

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

// list.json (and /canonical/leaves) keys are "canonical/" + the FQDN labels reversed, e.g.
// "canonical/.cat.lsd" for "lsd.cat."; values are protobuf bytes field 1 (0x0a 0x20) + 32-byte hash.
export function parseListLeaves(list: { block_height: number; leaves: [string, string][] }): Map<string, string> {
  const entries = new Map<string, string>();
  for (const [key, value] of list.leaves) {
    const domain = key.replace(/^canonical\//, "").split(".").reverse().join(".");
    entries.set(domain, value.startsWith("0a20") ? value.slice(4) : value);
  }
  return entries;
}

export async function fetchListEntry(listUrl: string, domain: string): Promise<{ blockHeight: number; hash: string | null }> {
  const list = await fetchJson(listUrl);
  return { blockHeight: list.block_height, hash: parseListLeaves(list).get(toFqdn(domain)) ?? null };
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
