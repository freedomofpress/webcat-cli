// Checks a deployed site the way the extension does on every response: bundle verification,
// one CSP header equal to the manifest's policy for the path, no forbidden headers, file hashes.
import { defaults } from "@freedomofpress/webcat/config";
import { WebcatError } from "@freedomofpress/webcat/webcat/interfaces/errors";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { type BundleDocument, describeValidity, parseBundleObject, verifyBundle } from "./bundle.js";
import { bareDomain, enrollmentHashHex, fetchDomainStatus, fetchServedEnrollment } from "./chain.js";
import { EnrollmentTypes } from "./enrollment.js";
import { HASHES_PATH, type ManifestContent, effectiveManifest, isHostOnlyFile } from "./manifest.js";
import { fetchCommunityTrustedRoot, trustedRootDrift } from "./sigstore.js";
import { causeOf, describeWebcatError, external, sha256, toBase64Url } from "./utils.js";

export interface PathCheck {
  path: string;
  problems: string[];
}

export interface SiteReport {
  bundle: string;
  previousBundle: string;
  enrollment: string;
  trustedRoot: string[]; // drift lines for Sigstore enrollments, empty when up to date or not applicable
  paths: PathCheck[];
  fallbacks: string[]; // warnings: fallback hashes not published under HASHES_PATH; the extension does not need them
}

const FORBIDDEN_HEADERS = ["refresh", "link"];

// Mirrors the extension's verifyCSP: exact extra_csp key, else the longest matching prefix, else the default.
export function expectedCsp(manifest: ManifestContent, pathname: string): string {
  const extra = manifest.extra_csp ?? {};
  if (extra[pathname]) {
    return extra[pathname];
  }
  const best = Object.keys(extra)
    .filter((prefix) => pathname.startsWith(prefix))
    .sort((a, b) => b.length - a.length)[0];
  return best ? extra[best] : manifest.default_csp;
}

// Mirrors the extension's file lookup on an effective manifest: the keyed hash, plus (documents only) any fallback.
export function acceptableHashes(manifest: ManifestContent, pathname: string, isDocument: boolean): string[] {
  return [...(manifest.files[pathname] ? [manifest.files[pathname]] : []), ...(isDocument ? (manifest.fallback_hashes ?? []) : [])];
}

export function checkHeaders(manifest: ManifestContent, pathname: string, headers: Headers): string[] {
  const problems: string[] = [];
  const csp = headers.get("content-security-policy");
  if (csp === null) {
    problems.push("content-security-policy header is missing");
  } else {
    if (csp.includes(",")) {
      problems.push("content-security-policy is sent more than once or contains a comma");
    }
    const served = csp.split(",")[0].trim();
    const expected = expectedCsp(manifest, pathname);
    if (served !== expected) {
      problems.push(`content-security-policy does not match the manifest: served '${served}', manifest '${expected}'`);
    }
    try {
      validateCSP(served);
    } catch (err) {
      problems.push(`content-security-policy is not WEBCAT-compatible: ${causeOf(err)}`);
    }
  }
  for (const name of FORBIDDEN_HEADERS) {
    if (headers.has(name)) {
      problems.push(`forbidden header ${name} is present`);
    }
  }
  const oac = headers.get("origin-agent-cluster");
  if (oac !== null && oac.trim() !== "?1") {
    problems.push(`origin-agent-cluster must be ?1 when present, got '${oac}'`);
  }
  return problems;
}

// The browser decides document vs subresource per request; for a static check, html and directories are documents.
const isDocumentPath = (pathname: string): boolean => pathname === "/" || pathname.endsWith("/") || pathname.endsWith(".html");

async function checkPath(origin: string, manifest: ManifestContent, pathname: string): Promise<PathCheck> {
  const problems: string[] = [];
  const isDocument = isDocumentPath(pathname);
  if (!pathname.startsWith("/")) {
    return { path: pathname, problems: ["manifest paths must start with '/'"] };
  }
  const response = await fetch(origin + pathname, { redirect: "manual" }).catch((err) => {
    throw external(`failed to fetch ${origin}${pathname}: ${causeOf(err)}`);
  });
  // The extension validates headers on every response, redirects included.
  problems.push(...checkHeaders(manifest, pathname, response.headers));
  const location = response.headers.get("location");
  if (location !== null) {
    let sameOrigin = false;
    try {
      sameOrigin = new URL(location, origin).origin === origin;
    } catch {}
    // Same-origin redirects of documents are allowed; the target is a path of its own.
    if (!isDocument) {
      problems.push(`has a location header ('${location}'): the extension rejects redirects on subresources`);
    } else if (!sameOrigin) {
      problems.push(`redirects to '${location}': the extension rejects cross-origin redirects`);
    }
    if (response.status >= 300 && response.status < 400) {
      return { path: pathname, problems };
    }
  }
  // The extension checks content, not status: a 404 fallback that matches is fine.
  const status = response.status === 200 ? "" : `HTTP ${response.status}, `;
  const accepted = acceptableHashes(manifest, pathname, isDocument);
  if (accepted.length === 0) {
    problems.push(`${status}not in manifest.files, the extension would deny it`);
  } else {
    const served = toBase64Url(sha256(new Uint8Array(await response.arrayBuffer())));
    if (!accepted.includes(served)) {
      problems.push(`${status}content does not match the manifest: served ${served}, manifest ${accepted.join(" or ")}`);
      if (isHostOnlyFile(pathname)) problems.push(`hosts usually do not serve this file: regenerate the manifest with --exclude ${pathname.slice(1)}`);
    }
  }
  return { path: pathname, problems };
}

// A bundle a browser would reject is a verdict, not a crash: malformed JSON or shape is reported as FAILED.
async function fetchBundle(url: string): Promise<{ bundle?: BundleDocument; verdict: string; notBundle?: string } | null> {
  const response = await fetch(url).catch((err) => {
    throw external(`failed to fetch ${url}: ${causeOf(err)}`);
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
  }
  let bundle: BundleDocument;
  try {
    bundle = parseBundleObject(await response.json(), url);
  } catch (err) {
    // Catch-all servers answer every path with a page: no bundle there, as opposed to a broken one.
    return { verdict: `FAILED: ${causeOf(err)}`, notBundle: `the server answered HTTP ${response.status} ${response.headers.get("content-type") ?? "without a content type"}` };
  }
  const result = await verifyBundle(bundle);
  const verdict = result instanceof WebcatError ? `FAILED: ${describeWebcatError(result)}` : `VERIFIED (${describeValidity(result)})`;
  return { bundle, verdict };
}

// A missing previous bundle only matters while an enrollment is being rotated, and a catch-all page in its place is not one.
const previousVerdict = (previous: Awaited<ReturnType<typeof fetchBundle>>): string =>
  !previous ? "none" : previous.notBundle ? `none, ${previous.notBundle}, not a bundle; fine unless you are rotating the enrollment` : previous.verdict;

// Fixed-size worker pool; sites with thousands of files would want --path filters.
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>, onProgress?: (done: number, total: number) => void): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  let done = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      for (let i = next++; i < items.length; i = next++) {
        out[i] = await fn(items[i]);
        onProgress?.(++done, items.length);
      }
    }),
  );
  return out;
}

export async function checkSite(domain: string, options: { chainApi: string; paths?: string[]; onProgress?: (done: number, total: number) => void }): Promise<SiteReport> {
  const origin = `https://${bareDomain(domain)}`;
  const current = await fetchBundle(origin + defaults.bundlePath);
  if (!current) {
    throw external(`${origin}${defaults.bundlePath} is not found; the extension needs it to verify the site`);
  }
  const previous = await fetchBundle(origin + defaults.bundlePrevPath);
  if (!current.bundle) {
    return { bundle: current.verdict, previousBundle: previousVerdict(previous), enrollment: "not checked, the bundle did not parse", trustedRoot: [], paths: [], fallbacks: [] };
  }
  const bundleHash = enrollmentHashHex(current.bundle.enrollment);
  const [served, status] = await Promise.all([
    fetchServedEnrollment(domain).catch((err) => err as Error),
    fetchDomainStatus(options.chainApi, domain).catch((err) => err as Error),
  ]);
  // Three facts, each judged on its own: what the bundle embeds, what enrollment.json serves, what the chain records.
  const servedPart =
    served instanceof Error
      ? `enrollment.json ERROR (${served.message})`
      : served === null
        ? "enrollment.json not served (browsers only need the chain)"
        : served.hash === bundleHash
          ? "enrollment.json agrees"
          : `MISMATCH: enrollment.json serves ${served.hash}`;
  const chainPart =
    status instanceof Error
      ? `chain ERROR (${status.message})`
      : status.canonical === bundleHash
        ? "chain agrees"
        : `MISMATCH: the chain records ${status.canonical ?? "nothing"}, browsers will not verify this site`;
  const enrollment = `bundle embeds ${bundleHash}; ${servedPart}; ${chainPart}`;
  const manifest = effectiveManifest(current.bundle.manifest.manifest);
  const paths = options.paths?.length ? options.paths : [...new Set(["/", ...Object.keys(manifest.files)])];
  const trustedRoot =
    current.bundle.enrollment.type === EnrollmentTypes.Sigstore ? trustedRootDrift(current.bundle.enrollment.trusted_root, await fetchCommunityTrustedRoot()) : [];
  return {
    bundle: current.verdict,
    previousBundle: previousVerdict(previous),
    enrollment,
    trustedRoot,
    paths: await mapLimit(paths, 8, (p) => checkPath(origin, manifest, p), options.onProgress),
    fallbacks: (await Promise.all((manifest.fallback_hashes ?? []).map((hash) => checkFallbackCopy(origin, hash)))).filter((w): w is string => w !== null),
  };
}

// Each fallback should be published under its hash so auditors can read what the manifest accepts.
async function checkFallbackCopy(origin: string, hash: string): Promise<string | null> {
  const url = `${origin}${HASHES_PATH}${hash}`;
  const response = await fetch(url).catch(() => null);
  if (!response?.ok) return `${url}: ${response ? `HTTP ${response.status}` : "not reachable"}; publish the fallback there (manifest generate writes it)`;
  const served = toBase64Url(sha256(new Uint8Array(await response.arrayBuffer())));
  return served === hash ? null : `${url}: content hashes to ${served}, not ${hash}`;
}
