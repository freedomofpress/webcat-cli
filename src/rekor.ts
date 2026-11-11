// Rekor as a history source (spec auditing.md 2.2, Sigstore): every entry whose certificate satisfies the enrollment's
// claims is a release. A v1 log is read one entry at a time, its only listing API; a v2 log by entry tiles
// (C2SP tlog-tiles, 256 entries each). Nothing sits between the CLI and the log.
// shortcut: the whole log is read on every run, so a log above --max-log-entries is skipped with a TODO; the public
// Sigstore logs (hundreds of millions of entries) always are. The upgrade is an index of certificate identities.
import { X509Certificate } from "@freedomofpress/sigstore-browser";
import { causeOf } from "./utils.js";

export const DEFAULT_MAX_LOG_ENTRIES = 200_000;
const SAN_OID = "2.5.29.17";
const OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7";

// The extension's claim rule (ClaimPolicy): every claim holds, "^" is a prefix, the SAN claim matches any SAN.
export function certificateMatchesClaims(certificate: Uint8Array | string, claims: Record<string, string>): boolean {
  let cert: X509Certificate;
  try {
    cert = X509Certificate.parse(certificate);
  } catch {
    return false;
  }
  const matches = (expected: string, got: string) => (expected.startsWith("^") ? got.startsWith(expected.slice(1)) : got === expected);
  for (const [oid, expected] of Object.entries(claims)) {
    if (oid === SAN_OID) {
      const san = cert.extSubjectAltName;
      const all = [san?.rfc822Name, san?.uri, san?.otherName(OTHERNAME_OID)].filter((v): v is string => typeof v === "string");
      if (!all.some((v) => matches(expected, v))) return false;
      continue;
    }
    const ext = cert.extension(oid);
    if (!ext) return false;
    let got: string;
    try {
      const inner = ext.valueObj.subs[0];
      got = new TextDecoder().decode(inner?.value?.length ? inner.value : ext.value);
    } catch {
      return false;
    }
    if (!matches(expected, got)) return false;
  }
  return true;
}

export interface RekorHit {
  log: string;
  index: number;
  digest: string; // hex SHA-256 of the artifact: the canonical manifest
}

// C2SP tlog-tiles path for tile N: three-digit groups, every group but the last prefixed with x.
export function tilePath(n: number): string {
  const digits = String(n).padStart(Math.ceil(Math.max(String(n).length, 3) / 3) * 3, "0");
  const groups = digits.match(/.{3}/g)!;
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join("/");
}

const b64hex = (b64: string): string => Buffer.from(b64, "base64").toString("hex");

// One hashedrekord entry, either generation, as the certificate and the artifact digest; null for anything else.
function hashedRekord(entry: any): { certificate: Uint8Array | string; digest: string } | null {
  if (entry?.kind !== "hashedrekord") return null;
  const v2 = entry.spec?.hashedRekordV002;
  if (v2) {
    const raw = v2.signature?.verifier?.x509Certificate?.rawBytes;
    return raw && v2.data?.digest ? { certificate: new Uint8Array(Buffer.from(raw, "base64")), digest: b64hex(v2.data.digest) } : null;
  }
  const pem = entry.spec?.signature?.publicKey?.content;
  const hash = entry.spec?.data?.hash?.value;
  return pem && hash ? { certificate: Buffer.from(pem, "base64").toString(), digest: hash } : null;
}

async function logSize(base: string): Promise<{ version: 1 | 2; size: number }> {
  const checkpoint = await fetch(`${base}/api/v2/checkpoint`).catch(() => null);
  if (checkpoint?.ok) {
    const size = Number((await checkpoint.text()).split("\n")[1]);
    if (Number.isSafeInteger(size)) return { version: 2, size };
  }
  const info = await fetch(`${base}/api/v1/log`);
  if (!info.ok) throw new Error(`neither a Rekor v2 checkpoint nor a v1 log info: HTTP ${info.status}`);
  const size = Number((await info.json())?.treeSize);
  if (!Number.isSafeInteger(size)) throw new Error("no treeSize in the v1 log info");
  return { version: 1, size };
}

// Entry bundles are a sequence of 16-bit big-endian length-prefixed entries.
function* bundleEntries(bundle: Buffer): Generator<Buffer> {
  for (let offset = 0; offset + 2 <= bundle.length; ) {
    const length = bundle.readUInt16BE(offset);
    yield bundle.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
  }
}

export async function scanRekorLogs(
  tlogs: Array<{ baseUrl?: string }>,
  claims: Record<string, string>[],
  maxEntries: number,
  onProgress: (line: string) => void = () => {},
): Promise<{ lines: string[]; hits: RekorHit[] }> {
  const lines: string[] = [];
  const hits: RekorHit[] = [];
  const consider = (log: string, index: number, raw: Buffer | string) => {
    let entry: any;
    try {
      entry = JSON.parse(typeof raw === "string" ? raw : raw.toString());
    } catch {
      return;
    }
    const record = hashedRekord(entry);
    if (record && claims.some((c) => certificateMatchesClaims(record.certificate, c))) hits.push({ log, index, digest: record.digest });
  };
  for (const tlog of tlogs) {
    const base = (tlog.baseUrl ?? "").replace(/\/+$/, "");
    if (!base) continue;
    let version: 1 | 2;
    let size: number;
    try {
      ({ version, size } = await logSize(base));
    } catch (err) {
      lines.push(`${base}: not scanned (${causeOf(err)})`);
      continue;
    }
    if (size > maxEntries) {
      const which = /\.sigstore\.dev$/.test(new URL(base).host) ? "the public Sigstore log" : "this log";
      lines.push(`${base}: ${size} entries, ${which} is too big to read end to end (limit ${maxEntries}, --max-log-entries); TODO: an index of certificate identities`);
      continue;
    }
    const before = hits.length;
    if (version === 2) {
      for (let tile = 0; tile * 256 < size; tile++) {
        const width = Math.min(256, size - tile * 256);
        onProgress(`scanning ${base} ${tile * 256}/${size}`);
        const url = `${base}/api/v2/tile/entries/${tilePath(tile)}${width < 256 ? `.p/${width}` : ""}`;
        const response = await fetch(url);
        if (!response.ok) {
          lines.push(`${base}: scan stopped at ${tile * 256} of ${size} (HTTP ${response.status} on ${url})`);
          break;
        }
        let i = 0;
        for (const raw of bundleEntries(Buffer.from(await response.arrayBuffer()))) consider(base, tile * 256 + i++, raw);
      }
    } else {
      for (let index = 0; index < size; index++) {
        if (index % 256 === 0) onProgress(`scanning ${base} ${index}/${size}`);
        const response = await fetch(`${base}/api/v1/log/entries?logIndex=${index}`);
        if (!response.ok) {
          lines.push(`${base}: scan stopped at ${index} of ${size} (HTTP ${response.status})`);
          break;
        }
        const body = (Object.values((await response.json()) as Record<string, { body?: string }>)[0] ?? {}).body;
        if (body) consider(base, index, Buffer.from(body, "base64"));
      }
    }
    lines.push(`${base} (Rekor v${version}): ${size} entries, ${hits.length - before} by this domain's identity`);
  }
  return { lines, hits };
}
