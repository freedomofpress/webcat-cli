// `webcat dev`: a signed site on https://<host>:8443 in a fresh Firefox profile with the test build of the
// extension, which trusts an enrollment list served at http://localhost:1234/ instead of the chain.
import { spawn } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { type ManifestContent, type ManifestDocument } from "./manifest.js";
import { expectedCsp } from "./site.js";
import { causeOf, external, invalid } from "./utils.js";

export const LIST_PORT = 1234; // the test build's enrollment list endpoint
export const SITE_PORT = 8443; // the only https port the test build accepts

// list.json as the test build reads it: the chain's canonical key and an ICS23 leaf value around the hex hash.
export const canonicalKey = (host: string): string => `canonical/.${host.split(".").reverse().join(".")}`;
export const leafValue = (hashHex: string): string => `0a${(hashHex.length / 2).toString(16).padStart(2, "0")}${hashHex}`;

export function mockList(host: string, enrollmentHashHex: string): string {
  return JSON.stringify({ leaves: [[canonicalKey(host), leafValue(enrollmentHashHex)]], proof: { app_hash: "00".repeat(32), canonical_root_hash: "00".repeat(32) } });
}

// A block the mocked light client accepts: only the chain id and a well-formed commit entry are checked.
export function mockBlock(now = new Date()): string {
  const zero32 = "00".repeat(32);
  const time = now.toISOString();
  const blockId = { hash: zero32, parts: { hash: zero32, total: 1 } };
  return JSON.stringify({
    signed_header: {
      header: {
        chain_id: "webcat-test-02", height: "0", last_block_id: blockId, last_commit_hash: zero32, data_hash: zero32,
        validators_hash: zero32, next_validators_hash: zero32, consensus_hash: zero32, app_hash: zero32, last_results_hash: zero32,
        evidence_hash: zero32, proposer_address: "00".repeat(20), time,
      },
      commit: { height: "0", round: 0, block_id: blockId, signatures: [{ block_id_flag: 2, validator_address: "00".repeat(20), timestamp: time, signature: "AA".repeat(43) + "==" }] },
    },
  });
}

// `fetched` resolves once the extension has read the list: navigating before that races the enrollment.
export function serveList(host: string, enrollmentHashHex: string): Promise<{ stop: () => void; fetched: Promise<void> }> {
  let onFetched!: () => void;
  const fetched = new Promise<void>((resolve) => (onFetched = resolve));
  const server = createHttpServer((req, res) => {
    const body = req.url === "/list.json" ? mockList(host, enrollmentHashHex) : req.url === "/block.json" ? mockBlock() : null;
    res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
    res.end(body ?? "");
    if (req.url === "/list.json") onFetched();
  });
  return new Promise((resolve, reject) => {
    server.once("error", (err) => reject(external(`failed to listen on 127.0.0.1:${LIST_PORT} for the enrollment list: ${causeOf(err)}`)));
    server.listen(LIST_PORT, "127.0.0.1", () => resolve({ stop: () => server.close(), fetched }));
  });
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".json": "application/json",
  ".wasm": "application/wasm", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon",
  ".woff2": "font/woff2", ".woff": "font/woff", ".txt": "text/plain", ".webmanifest": "application/manifest+json", ".map": "application/json",
};

export interface SiteOptions {
  directory: string;
  manifest: ManifestContent; // served as /.well-known/webcat/bundle.json together with the enrollment and signatures
  bundle: string;
  enrollment: string;
  fallback?: string; // path of the page served for unknown routes
  cleanUrls?: boolean; // serve /about from about.html
  tls: { cert: string; key: string };
  onBundleFetch?: () => void; // the extension fetches the bundle only for an origin it holds as enrolled
}

// Every response carries the manifest's policy for its path, as the extension requires.
export function serveSite(o: SiteOptions): Promise<() => void> {
  const server = createHttpsServer(o.tls, async (req, res) => {
    const pathname = decodeURIComponent(new URL(req.url ?? "/", "https://x").pathname);
    const headers: Record<string, string> = { "content-security-policy": expectedCsp(o.manifest, pathname) };
    const json = pathname === "/.well-known/webcat/bundle.json" ? o.bundle : pathname === "/.well-known/webcat/enrollment.json" ? o.enrollment : null;
    if (json) {
      if (pathname.endsWith("/bundle.json")) o.onBundleFetch?.();
      res.writeHead(200, { ...headers, "content-type": "application/json" });
      return res.end(json);
    }
    const index = o.manifest.default_index ?? "index.html";
    const isFile = async (f: string) => (await stat(f).catch(() => null))?.isFile() === true;
    let file = path.join(o.directory, pathname.endsWith("/") ? `${pathname}${index}` : pathname);
    let status = 200;
    for (const candidate of o.cleanUrls ? [file, `${file}.html`] : [file]) {
      if (await isFile(candidate)) {
        file = candidate;
        break;
      }
    }
    if (!(await isFile(file))) {
      if (!o.fallback) {
        res.writeHead(404, headers);
        return res.end();
      }
      [file, status] = [path.join(o.directory, o.cleanUrls && !(await isFile(path.join(o.directory, o.fallback))) ? `${o.fallback}.html` : o.fallback), 404];
    }
    res.writeHead(status, { ...headers, "content-type": TYPES[path.extname(file).toLowerCase()] ?? "application/octet-stream" });
    createReadStream(file).pipe(res);
  });
  return new Promise((resolve, reject) => {
    server.once("error", (err) => reject(external(`failed to listen on 127.0.0.1:${SITE_PORT}: ${causeOf(err)}`)));
    server.listen(SITE_PORT, "127.0.0.1", () => resolve(() => server.close()));
  });
}

// A self-signed certificate for the host, through the openssl binary; Node has no API to issue one.
export async function selfSignedCert(dir: string, host: string): Promise<{ cert: string; key: string }> {
  const cert = path.join(dir, "cert.pem");
  const key = path.join(dir, "key.pem");
  await new Promise<void>((resolve, reject) => {
    const child = spawn("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", `/CN=${host}`, "-addext", `subjectAltName=DNS:${host},IP:127.0.0.1`, "-keyout", key, "-out", cert], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => reject(external(`failed to run openssl: ${causeOf(err)}`)));
    child.on("exit", (code) => (code === 0 ? resolve() : reject(external(`failed to run openssl: exit code ${code}${stderr ? `: ${stderr.trim()}` : ""}`))));
  });
  return { cert: await readFile(cert, "utf8"), key: await readFile(key, "utf8") };
}

// Firefox's cert_override.txt: one line per host:port trusting this certificate.
export function certOverrideLines(certPem: string, hosts: string[], port = SITE_PORT): string {
  const x509 = new X509Certificate(certPem);
  const fingerprint = x509.fingerprint256;
  const der = x509.raw.toString("base64");
  return hosts.map((h) => `${h}:${port}\tOID.2.16.840.1.101.3.4.2.1\t${fingerprint}\t${der}\n`).join("");
}

const PREFS: Record<string, string | number | boolean> = {
  "devtools.debugger.remote-enabled": true, "devtools.debugger.prompt-connection": false, "devtools.chrome.enabled": true,
  "browser.shell.checkDefaultBrowser": false, "browser.aboutwelcome.enabled": false, "browser.startup.homepage_override.mstone": "ignore",
  "browser.startup.firstrunSkipsHomepage": true, "browser.warnOnQuit": false, "browser.tabs.warnOnClose": false, "browser.sessionstore.resume_from_crash": false,
  "datareporting.policy.dataSubmissionEnabled": false, "app.normandy.first_run": false, "termsofuse.bypassNotification": true, "app.update.enabled": false,
  "xpinstall.signatures.required": false,
};

export const userJs = (prefs = PREFS): string => Object.entries(prefs).map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});\n`).join("");

export function findFirefox(explicit?: string): string {
  if (explicit) return explicit;
  if (process.platform === "darwin") return "/Applications/Firefox.app/Contents/MacOS/firefox";
  return "firefox"; // resolved through PATH by spawn
}

// The test build of the extension, shipped by @freedomofpress/webcat: resolved from node_modules when running
// from source, next to dist/cli.cjs in the published package (the build copies it there).
export function testExtensionPath(): string {
  const here = import.meta.url ? fileURLToPath(import.meta.url) : __filename; // esbuild's cjs bundle has no import.meta.url
  try {
    return createRequire(here).resolve("@freedomofpress/webcat/test-extension.zip");
  } catch {
    return path.join(path.dirname(here), "webcat-extension-test.zip");
  }
}

// Firefox's remote debugging protocol over TCP: packets are "<length>:<json>", replies carry the actor they come from.
export class Rdp {
  #socket!: ReturnType<typeof connect>;
  #buffer = "";
  #waiting: Array<{ from: string; resolve: (p: any) => void }> = [];

  async connect(port: number): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.#socket = connect({ host: "127.0.0.1", port }, resolve).once("error", reject);
    });
    this.#socket.on("data", (d) => this.#read(d.toString()));
    await this.#next("root"); // the server's hello
  }
  close(): void {
    this.#socket.destroy();
  }
  #read(chunk: string): void {
    this.#buffer += chunk;
    for (;;) {
      const colon = this.#buffer.indexOf(":");
      if (colon < 0) return;
      const length = Number(this.#buffer.slice(0, colon));
      if (this.#buffer.length < colon + 1 + length) return;
      const packet = JSON.parse(this.#buffer.slice(colon + 1, colon + 1 + length));
      this.#buffer = this.#buffer.slice(colon + 1 + length);
      // Unsolicited events carry a type; replies do not.
      if (packet.type && !packet.error) continue;
      const i = this.#waiting.findIndex((w) => w.from === packet.from);
      if (i >= 0) this.#waiting.splice(i, 1)[0].resolve(packet);
    }
  }
  #next(from: string): Promise<any> {
    return new Promise((resolve) => this.#waiting.push({ from, resolve }));
  }
  async request(to: string, type: string, extra: Record<string, unknown> = {}): Promise<any> {
    const reply = this.#next(to);
    const body = JSON.stringify({ to, type, ...extra });
    this.#socket.write(`${Buffer.byteLength(body)}:${body}`);
    const packet = await reply;
    if (packet.error) throw external(`Firefox refused ${type}: ${packet.message ?? packet.error}`);
    return packet;
  }
}

export interface BrowserOptions {
  firefox?: string;
  profile: string;
  addon: string;
  url: string;
  ready?: Promise<void>; // awaited between installing the add-on and opening the url
  onTitle?: (title: string) => void; // the tab title a few seconds after navigation: the page's, or the error page's
  debuggerPort?: number;
}

// Launches a fresh profile, installs the extension as a temporary add-on, opens the site, and returns a stop function.
export async function launchBrowser(o: BrowserOptions): Promise<() => void> {
  const port = o.debuggerPort ?? 6100;
  const child = spawn(findFirefox(o.firefox), ["-new-instance", "-no-remote", "-profile", o.profile, "--start-debugger-server", String(port), "about:blank"], { stdio: "ignore" });
  child.on("error", (err) => {
    throw external(`failed to start Firefox: ${causeOf(err)}; pass --firefox <path>`);
  });
  const rdp = new Rdp();
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      await rdp.connect(port);
      break;
    } catch (err) {
      if (child.exitCode !== null) throw external(`Firefox exited during startup (code ${child.exitCode})`);
      if (Date.now() > deadline) throw external(`Firefox did not open the debugger port ${port} within 30s: ${causeOf(err)}`);
      await sleep(200);
    }
  }
  const root = await rdp.request("root", "getRoot");
  await rdp.request(root.addonsActor, "installTemporaryAddon", { addonPath: o.addon });
  await Promise.race([o.ready ?? Promise.resolve(), sleep(30_000).then(() => Promise.reject(external("the extension did not fetch the enrollment list within 30s")))]);
  const { tabs } = await rdp.request("root", "listTabs");
  const tab = tabs.find((t: any) => t.selected) ?? tabs[0];
  const { frame } = await rdp.request(tab.actor, "getTarget");
  await rdp.request(frame.actor, "navigateTo", { url: o.url });
  if (o.onTitle) {
    await sleep(4000);
    const { tabs: after } = await rdp.request("root", "listTabs");
    o.onTitle(after.find((t: any) => t.actor === tab.actor)?.title ?? "");
  }
  return () => {
    rdp.close();
    child.kill();
  };
}

export async function makeProfile(certPem: string, host: string): Promise<string> {
  const profile = await mkdtemp(path.join(tmpdir(), "webcat-dev-profile-"));
  await writeFile(path.join(profile, "user.js"), userJs());
  await writeFile(path.join(profile, "cert_override.txt"), certOverrideLines(certPem, [host, "127.0.0.1"]));
  return profile;
}

// Everything `webcat dev` does, in order; returns a function that stops the servers and the browser.
export async function runDev(o: { directory: string; config: string; version?: string; host: string; firefox?: string; browser: boolean }): Promise<() => Promise<void>> {
  const { DEFAULT_MAX_AGE, SIGSUM_TEST_POLICY } = await import("./init.js");
  const { buildEnrollmentObject } = await import("./enrollment.js");
  const { enrollmentHashHex } = await import("./chain.js");
  const { buildManifest, loadManifestConfig, scanDirectory, writeFallbackCopies } = await import("./manifest.js");
  const { fetchTimestampFromPolicy, generateSigsumKeys, signManifestWithSigsum, sigsumEnrollmentFromPolicy } = await import("./sigsum.js");
  const { verifyBundle } = await import("./bundle.js");
  const { log } = await import("./utils.js");

  const work = await mkdtemp(path.join(tmpdir(), "webcat-dev-"));
  const cleanups: Array<() => void | Promise<void>> = [() => rm(work, { recursive: true, force: true })];
  try {
    // 1. A throwaway Sigsum enrollment on the test logs, threshold 1, the way the integration tests enroll.
    const policyFile = path.join(work, "trust_policy");
    await writeFile(policyFile, SIGSUM_TEST_POLICY);
    const { signers, paths: keyPaths } = await generateSigsumKeys(work, 1);
    const enrollment = await buildEnrollmentObject({ type: "sigsum", ...(await sigsumEnrollmentFromPolicy(SIGSUM_TEST_POLICY)), signers, threshold: 1, maxAge: DEFAULT_MAX_AGE, casUrl: `https://${o.host}:${SITE_PORT}/cas/` });
    if (enrollment.type !== "sigsum") throw invalid("unreachable");
    log(`enrollment ${enrollmentHashHex(enrollment)} (Sigsum test logs, one throwaway key)`);

    // 2. The manifest from the directory, timestamped and signed on the test log.
    const config = await loadManifestConfig(o.config);
    if (o.version) config.version = o.version; // release workflows stamp it from the tag; a placeholder would fail the semver check
    const [scan, timestamp] = await Promise.all([scanDirectory(o.directory, { cleanUrls: config.clean_urls }), fetchTimestampFromPolicy(SIGSUM_TEST_POLICY)]);
    const document: ManifestDocument = { manifest: buildManifest(config, scan, timestamp) };
    for (const written of await writeFallbackCopies(o.directory, config, document.manifest)) log(`wrote ${written}`);
    await signManifestWithSigsum(document, { policyFile, key: keyPaths[0], enrollment });
    const result = await verifyBundle({ enrollment, manifest: document });
    if (typeof result !== "number") throw external(`the signed manifest does not verify: ${result.code}`);
    log(`manifest ${document.manifest.version} signed, ${Object.keys(document.manifest.files).length} files`);

    // 3. The servers: the enrollment list the test build trusts, and the site with the manifest's policies.
    const list = await serveList(o.host, enrollmentHashHex(enrollment));
    cleanups.push(list.stop);
    const tls = await selfSignedCert(work, o.host);
    cleanups.push(
      await serveSite({
        directory: o.directory,
        manifest: document.manifest,
        bundle: JSON.stringify({ enrollment, manifest: document.manifest, signatures: document.signatures }),
        enrollment: JSON.stringify(enrollment),
        fallback: config.fallbacks[0],
        cleanUrls: config.clean_urls,
        tls,
        onBundleFetch: () => log("the extension fetched the bundle: the origin is enrolled"),
      }),
    );
    const url = `https://${o.host}:${SITE_PORT}/`;
    log(`serving ${o.directory} at ${url}`);

    // 4. Firefox, fresh profile, the test extension as a temporary add-on.
    if (o.browser) {
      const profile = await makeProfile(tls.cert, o.host);
      cleanups.push(() => rm(profile, { recursive: true, force: true }));
      cleanups.push(await launchBrowser({ firefox: o.firefox, profile, addon: testExtensionPath(), url, ready: list.fetched, onTitle: (title) => log(`tab: ${title}`) }));
      log("Firefox is open with the WEBCAT test extension; the icon shows the verification state. Ctrl-C stops everything.");
    }
  } catch (err) {
    for (const c of cleanups.reverse()) await c();
    throw err;
  }
  return async () => {
    for (const c of cleanups.reverse()) await c();
  };
}
