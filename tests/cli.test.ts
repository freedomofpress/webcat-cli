import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { buildEnrollmentObject, loadEnrollment, parseEnrollmentObject, parseSignerKey } from "../src/enrollment";
import { loadBundleDocument } from "../src/bundle";
import { SIGSUM_TEST_POLICY } from "../src/init";
import { sigsumEnrollmentFromPolicy } from "../src/sigsum";
import { parseListLeaves, solvePow, toFqdn, verifyList } from "../src/chain";
import {
  buildManifest,
  loadManifestConfig,
  loadManifestDocument,
  parseManifestDocumentObject,
  scanDirectory,
} from "../src/manifest";
import {
  decodeKeyMaterial,
  hexToBase64Url,
  parseInteger,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "../src/utils";

describe("key parsing", () => {
  it("decodes hex and base64url strings", () => {
    const hexInput = "11".repeat(32);
    const hexResult = decodeKeyMaterial(hexInput, "test");
    expect(hexResult).toHaveLength(32);

    const base64Buffer = Buffer.alloc(32, 0xff);
    const base64Input = toBase64Url(base64Buffer);
    const base64Result = decodeKeyMaterial(base64Input, "test");
    expect(base64Result.equals(base64Buffer)).toBe(true);
  });

  it("rejects malformed key material", () => {
    expect(() => decodeKeyMaterial("abc", "key")).toThrow(
      "key must contain an even number of hex characters",
    );
    expect(() => decodeKeyMaterial("not_base64", "key")).toThrow(
      /key must be a 32-byte/,
    );
    expect(() => decodeKeyMaterial("00".repeat(8), "key")).toThrow(
      "key must be a 32-byte",
    );
  });

  it("parses signer keys and normalizes hex", () => {
    const hexInput = "11".repeat(32);
    const expected = hexToBase64Url(hexInput);
    expect(parseSignerKey(hexInput)).toBe(expected);
  });
});

describe("integer and range validation", () => {
  it("enforces positive integers", () => {
    expect(() => parseInteger(-1, "value")).toThrow("value must be a non-negative integer");
    expect(() => parseInteger("oops", "value")).toThrow("value must be a non-negative integer");
    expect(parseInteger(5, "value")).toBe(5);
  });

  it("enforces max-age bounds", () => {
    expect(() => validateMaxAge(60 * 60 * 24 * 7, "max_age")).toThrow(
      "max_age must be between one week and one year",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 365, "max_age")).toThrow(
      "max_age must be between one week and one year",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 30, "max_age")).not.toThrow();
  });

  it("validates CAS URLs", () => {
    expect(() => validateCasUrl("notaurl", "cas_url")).toThrow("cas_url must be a valid URL");
    expect(() => validateCasUrl("http://example.com", "cas_url")).toThrow("cas_url must use https://");
    expect(() => validateCasUrl("https://", "cas_url")).toThrow("cas_url must be a valid URL");
    expect(() => validateCasUrl("https://example.com", "cas_url")).not.toThrow();
  });
});

const real = await sigsumEnrollmentFromPolicy(SIGSUM_TEST_POLICY); // a genuine compiled policy plus its logs map

describe("enrollment helpers", () => {
  const baseSigner = "aa".repeat(32);
  const secondSigner = "bb".repeat(32);

  it("builds normalized enrollment objects", async () => {
    const enrollment = await buildEnrollmentObject({
      type: "sigsum",
      policy: real.policy,
      signers: [baseSigner],
      threshold: 1,
      maxAge: 1_000_000,
      casUrl: "https://example.com",
      logs: real.logs,
    });

    expect(enrollment.type).toBe("sigsum");
    if (enrollment.type !== "sigsum") {
      throw new Error("expected sigsum enrollment");
    }
    expect(enrollment.signers).toEqual([hexToBase64Url(baseSigner)]);
    expect(enrollment.threshold).toBe(1);
    expect(enrollment.max_age).toBe(1_000_000);
  });

  it("rejects duplicate or insufficient signer information", async () => {
    await expect(
      buildEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: real.logs,
      }),
    ).rejects.toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_SIGNERS_EMPTY");

    await expect(
      buildEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [baseSigner, baseSigner],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: real.logs,
      }),
    ).rejects.toThrow("enrollment.signers must not contain duplicates");

    await expect(
      buildEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [baseSigner, secondSigner],
        threshold: 3,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: real.logs,
      }),
    ).rejects.toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_THRESHOLD_IMPOSSIBLE");

    await expect(
      buildEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [baseSigner],
        threshold: 0,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: real.logs,
      }),
    ).rejects.toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_THRESHOLD_MALFORMED");

    await expect(
      buildEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [baseSigner],
        threshold: 1,
        maxAge: 60 * 60 * 24 * 8,
        casUrl: "http://example.com",
        logs: real.logs,
      }),
    ).rejects.toThrow("enrollment.cas_url must use https://");
  });

  it("builds sigstore enrollment objects", async () => {
    const trustedRoot = { fulcio: { root: "data" } };
    const enrollment = await buildEnrollmentObject({
      type: "sigstore",
      trustedRoot,
      claims: {
        "2.5.29.17": "identity@example.com",
        "1.3.6.1.4.1.57264.1.8": "issuer.example",
      },
      maxAge: 1_000_000,
    });

    expect(enrollment).toEqual({
      type: "sigstore",
      trusted_root: trustedRoot,
      claims: {
        "2.5.29.17": "identity@example.com",
        "1.3.6.1.4.1.57264.1.8": "issuer.example",
      },
      max_age: 1_000_000,
    });
  });

  it("parses enrollment JSON files", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-enroll-"));
    const file = path.join(dir, "enrollment.json");
    await writeFile(
      file,
      JSON.stringify({
        type: "sigsum",
        policy: real.policy,
        signers: [hexToBase64Url(baseSigner)],
        threshold: 1,
        max_age: 1_000_000,
        cas_url: "https://example.com",
        logs: real.logs,
      }),
    );

    const loaded = await loadEnrollment(file);
    if (loaded.type !== "sigsum") {
      throw new Error("expected sigsum enrollment");
    }
    expect(loaded.signers).toEqual([hexToBase64Url(baseSigner)]);
    expect(loaded.type).toBe("sigsum");

    await writeFile(file, "not json");
    await expect(loadEnrollment(file)).rejects.toThrow("is not valid JSON");

    await rm(dir, { recursive: true, force: true });
  });

  it("parses enrollment objects with validation", () => {
    expect(() =>
      parseEnrollmentObject({
        type: "sigsum",
        policy: "",
        signers: ["x"],
        threshold: 1,
        max_age: 1,
        cas_url: "https://example.com",
        logs: real.logs,
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_POLICY_LENGTH");

    expect(() =>
      parseEnrollmentObject({
        type: "sigsum",
        policy: real.policy,
        signers: [hexToBase64Url(baseSigner), hexToBase64Url(baseSigner)],
        threshold: 1,
        max_age: 1_000_000,
        cas_url: "https://example.com",
        logs: real.logs,
      }, { authoring: true }),
    ).toThrow("enrollment.signers must not contain duplicates");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: "",
        claims: { "2.5.29.17": "id" },
        max_age: 1_000_000,
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_TRUSTED_ROOT_MISSING");

    const base = { type: "sigsum", policy: real.policy, signers: [hexToBase64Url(baseSigner)], threshold: 1, max_age: 1_000_000, cas_url: "https://example.com" };
    const authoring = { authoring: true };
    expect(() => parseEnrollmentObject({ ...base, logs: { ...real.logs, AAAA: "https://other.example" } }, authoring)).toThrow("enrollment.logs lists AAAA, which is not a log in the policy");
    expect(() => parseEnrollmentObject({ ...base, logs: { AAAA: "https://other.example" } }, authoring)).toThrow(/enrollment.logs must give the URL of log \S+, which the policy trusts/);
    expect(() => parseEnrollmentObject({ ...base, policy: "bm90LWEtcG9saWN5", logs: real.logs }, authoring)).toThrow("enrollment.policy must be a compiled Sigsum policy");
    expect(() => parseEnrollmentObject({ ...base, logs: real.logs }, authoring)).not.toThrow();
    // Read from disk or the network, only the browser's rules apply: a two-year max_age or a stray log entry still parses.
    expect(() => parseEnrollmentObject({ ...base, max_age: 2 * 365 * 86_400, logs: { ...real.logs, AAAA: "https://other.example" } })).not.toThrow();
    expect(() => parseEnrollmentObject({ ...base, type: undefined, logs: real.logs })).toThrow("enrollment.type must be 'sigsum' or 'sigstore'");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: {},
        claims: { not_oid: "id" },
        max_age: 1_000_000,
      }, { authoring: true }),
    ).toThrow("enrollment.claims keys must be OIDs");
  });
});

describe("CAS resolution", () => {
  it("lets an auditor walk from a log entry's checksum to the manifest", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-cas-"));
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      const canonicalManifest = JSON.stringify({ app: "demo" });
      const { publishManifestToCas } = await import("../src/cas");
      await publishManifestToCas(canonicalManifest);
      // The Sigsum leaf checksum is sha256(message) where message = sha256(manifest); both are CAS object names.
      const message = createHash("sha256").update(canonicalManifest).digest();
      const leafChecksumHex = createHash("sha256").update(message).digest("hex");
      const storedMessage = await readFile(path.join(dir, "cas", leafChecksumHex));
      expect(storedMessage.equals(message)).toBe(true);
      expect(await readFile(path.join(dir, "cas", storedMessage.toString("hex")), "utf8")).toBe(canonicalManifest);
    } finally {
      process.chdir(cwd);
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("manifest configuration", () => {
  it("loads and normalizes configuration", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-config-"));
    const configPath = path.join(dir, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        app: "https://example.com",
        version: "1.0.0",
        default_csp: "default-src 'none'",
        default_index: "/index.html",
        default_fallback: "/error.html",
        wasm: ["module.wasm"],
        extra_csp: { "/path": "policy" },
      }),
    );

    const config = await loadManifestConfig(configPath);
    expect(config.default_index).toBe("index.html");
    expect(config.extra_csp["/path"]).toBe("policy");

    await writeFile(configPath, "not json");
    await expect(loadManifestConfig(configPath)).rejects.toThrow(
      "manifest config file",
    );

    await rm(dir, { recursive: true, force: true });
  });

  it("builds manifests with the extension's rules", () => {
    const hash = toBase64Url(createHash("sha256").update("x").digest());
    const scan = { files: new Map([["/index.html", hash], ["/docs/index.html", "D".repeat(42) + "A"], ["/404.html", "E".repeat(42) + "A"]]), wasm: new Set<string>() };
    const config = { app: "https://example.com", version: "1", default_csp: "default-src 'none'", default_index: "index.html", fallbacks: ["/404.html"], clean_urls: false, wasm: [], extra_csp: {} };
    const built = buildManifest(config, scan);
    // Directory keys next to each index, the fallback as a hash, and the legacy fields for extensions before 3.2.0.
    expect(Object.keys(built.files)).toEqual(["/", "/404.html", "/docs/", "/docs/index.html", "/index.html"]);
    expect(built.files["/"]).toBe(hash);
    expect(built.fallback_hashes).toEqual([scan.files.get("/404.html")]);
    expect([built.default_index, built.default_fallback]).toEqual(["index.html", "/404.html"]);
    // No fallbacks at all: nothing emitted for either generation.
    const none = buildManifest({ ...config, fallbacks: [] }, scan);
    expect([none.fallback_hashes, none.default_fallback]).toEqual([undefined, undefined]);
    expect(() => buildManifest({ ...config, fallbacks: ["/missing.html"] }, scan)).toThrow("config.fallbacks must name scanned files, '/missing.html' was not found");
    expect(() => buildManifest({ ...config, default_csp: "default-src 'self'" }, scan)).toThrow("config.default_csp must be a WEBCAT-compatible CSP");
    expect(() => buildManifest({ ...config, extra_csp: { "/a": "script-src https://cdn.example" } }, scan)).toThrow("config.extra_csp['/a'] must be a WEBCAT-compatible CSP");
    expect(() => buildManifest({ ...config, fallbacks: ["/missing.html"], default_csp: "default-src 'self'", extra_csp: { "/a": "csp" } }, scan)).toThrow(
      /3 problems:\n  - config.fallbacks must name scanned files.*\n  - config.default_csp must be .*\n  - config.extra_csp\['\/a'\] must be/,
    );
  });

  it("reads old and new configs alike and publishes fallbacks under their hash", async () => {
    const { writeFallbackCopies } = await import("../src/manifest");
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-fallback-"));
    const base = { app: "https://example.com", version: "1", default_csp: "default-src 'none'" };
    await writeFile(path.join(dir, "legacy.json"), JSON.stringify({ ...base, default_index: "/index.html", default_fallback: "/404.html" }));
    await writeFile(path.join(dir, "bare.json"), JSON.stringify(base));
    await writeFile(path.join(dir, "new.json"), JSON.stringify({ ...base, fallbacks: ["/404.html", "/index.html"] }));
    expect((await loadManifestConfig(path.join(dir, "legacy.json"))).fallbacks).toEqual(["/404.html"]);
    expect(await loadManifestConfig(path.join(dir, "bare.json"))).toMatchObject({ default_index: "index.html", fallbacks: ["/index.html"] });
    expect((await loadManifestConfig(path.join(dir, "new.json"))).fallbacks).toEqual(["/404.html", "/index.html"]);

    await writeFile(path.join(dir, "404.html"), "lost");
    await writeFile(path.join(dir, "index.html"), "home");
    const config = await loadManifestConfig(path.join(dir, "legacy.json"));
    const manifest = buildManifest(config, await scanDirectory(dir, { excludePaths: ["legacy.json", "bare.json", "new.json"] }));
    const hash = toBase64Url(createHash("sha256").update("lost").digest());
    expect(await writeFallbackCopies(dir, config, manifest)).toEqual([`/.well-known/webcat/hashes/${hash}`]);
    expect(await readFile(path.join(dir, ".well-known/webcat/hashes", hash), "utf8")).toBe("lost");
    await rm(dir, { recursive: true, force: true });
  });
});

describe("directory scanning", () => {
  it("hashes files and wasm artifacts", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-scan-"));
    await writeFile(path.join(dir, "index.html"), "hello");
    await writeFile(path.join(dir, "module.wasm"), "wasm-bytes");
    await writeFile(path.join(dir, ".env"), "secret");
    await mkdir(path.join(dir, ".hidden"));
    await writeFile(path.join(dir, ".hidden", "secret.txt"), "hidden");

    const result = await scanDirectory(dir);
    const indexHash = createHash("sha256").update("hello").digest();
    expect(result.files.get("/index.html")).toBe(toBase64Url(indexHash));
    const wasmHash = createHash("sha256").update("wasm-bytes").digest();
    expect(result.wasm.has(toBase64Url(wasmHash))).toBe(true);
    expect(result.files.has("/.env")).toBe(false);
    expect(result.files.has("/.hidden/secret.txt")).toBe(false);

    const includeResult = await scanDirectory(dir, { includeDotfiles: true });
    const dotHash = createHash("sha256").update("secret").digest();
    expect(includeResult.files.get("/.env")).toBe(toBase64Url(dotHash));
    const hiddenHash = createHash("sha256").update("hidden").digest();
    expect(includeResult.files.get("/.hidden/secret.txt")).toBe(toBase64Url(hiddenHash));

    await rm(dir, { recursive: true, force: true });
  });

  it("skips excluded files and directories", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-exclude-"));
    await writeFile(path.join(dir, "index.html"), "hello");
    await writeFile(path.join(dir, "ignore.txt"), "secret");
    await mkdir(path.join(dir, "private"));
    await writeFile(path.join(dir, "private", "hidden.txt"), "hidden");

    // What init writes is never served, so it is skipped without being asked.
    await writeFile(path.join(dir, "webcat.config.json"), "{}");
    await writeFile(path.join(dir, "trust_policy"), "policy");
    await mkdir(path.join(dir, "keys"));
    await writeFile(path.join(dir, "keys", "key1"), "private");

    // Clean URLs: the extension is dropped from every html path, index included.
    await mkdir(path.join(dir, "docs"));
    await writeFile(path.join(dir, "docs", "index.html"), "docs");
    await writeFile(path.join(dir, "about.html"), "about");
    expect([...(await scanDirectory(dir, { cleanUrls: true, excludePaths: ["/private", "ignore.txt"] })).files.keys()].sort()).toEqual(["/about", "/docs/index", "/index"]);

    const result = await scanDirectory(dir, { excludePaths: ["/private", "ignore.txt"] });
    expect(result.files.has("/index.html")).toBe(true);
    expect(result.files.has("/ignore.txt")).toBe(false);
    expect(result.files.has("/private/hidden.txt")).toBe(false);
    expect([...result.files.keys()].filter((p) => /webcat\.config|trust_policy|keys/.test(p))).toEqual([]);

    await rm(dir, { recursive: true, force: true });
  });
});

describe("manifest parsing", () => {
  it("validates manifest documents", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-manifest-"));
    const manifestPath = path.join(dir, "manifest.json");

    const hash = toBase64Url(createHash("sha256").update("x").digest());
    const manifest = {
      manifest: {
        files: { "/index.html": hash },
        wasm: [],
        extra_csp: {},
        timestamp: "2024-01-01T00:00:00Z",
        app: "app",
        version: "1",
        default_csp: "default-src 'none'",
        default_index: "index.html",
        default_fallback: "/index.html",
      },
      signatures: {},
    };

    await writeFile(manifestPath, JSON.stringify(manifest));
    const loaded = await loadManifestDocument(manifestPath);
    expect(loaded.manifest.files).toEqual({ "/index.html": hash });

    await writeFile(manifestPath, JSON.stringify({ ...manifest, manifest: { ...manifest.manifest, files: { "/index.html": "nothash" } } }));
    await expect(loadManifestDocument(manifestPath)).rejects.toThrow("manifest.manifest: ERR_WEBCAT_MANIFEST_FILES_MALFORMED (/index.html)");

    await writeFile(manifestPath, "{]");
    await expect(loadManifestDocument(manifestPath)).rejects.toThrow(
      "is not valid JSON",
    );

    expect(() => parseManifestDocumentObject({})).toThrow(
      "manifest.manifest must be an object",
    );

    await rm(dir, { recursive: true, force: true });
  });
});

describe("policy and bundle parsing", () => {

  it("validates bundle documents", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-bundle-"));
    const bundlePath = path.join(dir, "bundle.json");
    await writeFile(
      bundlePath,
      JSON.stringify({
        enrollment: {
          type: "sigsum",
          policy: real.policy,
          signers: [""],
          threshold: 1,
          max_age: 1_000_000,
          cas_url: "https://example.com",
        },
        manifest: {
          files: {},
          wasm: [],
          extra_csp: {},
          timestamp: "ts",
          app: "a",
          version: "1",
          default_csp: "csp",
          default_index: "index",
          default_fallback: "/error",
        },
        signatures: {},
      }),
    );

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_LOGS_MALFORMED");

    await writeFile(bundlePath, "{}");
    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle.enrollment is required");

    await writeFile(
      bundlePath,
      JSON.stringify({
        enrollment: {
          type: "sigsum",
          policy: real.policy,
          signers: ["abc"],
          threshold: 1,
          max_age: 1_000_000,
          cas_url: "https://example.com",
        },
        signatures: {},
      }),
    );

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle.manifest is required");

    await rm(dir, { recursive: true, force: true });
  });
});

describe("csp hints", () => {
  it("explains each incompatibility and proposes a policy that validates", async () => {
    const { hintCsp } = await import("../src/csp");
    const { validateCSP } = await import("@freedomofpress/webcat/webcat/validators");
    const { groups, suggested, accepted } = hintCsp("default-src 'self'; script-src 'self' https://cdn.example 'unsafe-inline' 'nonce-x'; style-src 'self' https://fonts.example; img-src *");
    expect(groups.map((g) => [g.title, g.items])).toEqual([
      ["Scripts from other origins", ["script-src https://cdn.example"]],
      ["Inline and dynamic scripts", ["script-src 'unsafe-inline'", "script-src 'nonce-x'"]],
      ["Stylesheets from other origins", ["style-src https://fonts.example"]],
      ["Missing directives", ["object-src", "worker-src"]],
    ]);
    expect(groups[0].advice.join(" ")).toContain("sandboxed iframe");
    expect(groups[1].advice.join(" ")).toContain("manifest signature");
    expect(accepted.join(" ")).toContain("img-src");
    expect(() => validateCSP(suggested)).not.toThrow();
    expect(suggested).toContain("img-src *");
    expect(hintCsp("default-src 'none'; script-src 'self'; style-src 'self'").groups).toEqual([]);
    expect(hintCsp("default-src 'none', default-src 'self'").groups[0].title).toBe("Multiple policies");
    // 'none' next to another source is not 'none' for the extension; the verdict comes from its validator.
    const mixed = hintCsp("default-src 'none' 'self'");
    expect(mixed.compatible).toBe(false);
    expect(mixed.groups.map((g) => g.title)).toEqual(["default-src", "Missing directives"]);
  });
});

describe("csp from a site", () => {
  it("returns one policy per response, redirects included, as the extension checks each", async () => {
    const { createServer } = await import("node:http");
    const { fetchSiteCsp } = await import("../src/csp");
    const server = createServer((req, res) => {
      if (req.url === "/old") res.writeHead(301, { location: "/new" });
      else if (req.url === "/moved") res.writeHead(302, { location: "/new", "content-security-policy": "default-src 'self'" });
      else if (req.url === "/away") res.writeHead(302, { location: "https://other.invalid/x", "content-security-policy": "default-src 'none'" });
      else res.writeHead(200, { "content-security-policy": "default-src 'none'" });
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      expect(await fetchSiteCsp(`${base}/new`)).toEqual([{ url: `${base}/new`, csp: "default-src 'none'" }]);
      expect(await fetchSiteCsp(`${base}/old`)).toEqual([
        { url: `${base}/old`, csp: null, location: `${base}/new` },
        { url: `${base}/new`, csp: "default-src 'none'" },
      ]);
      expect((await fetchSiteCsp(`${base}/moved`)).map((h) => h.csp)).toEqual(["default-src 'self'", "default-src 'none'"]);
      // A cross-origin redirect is reported and not followed, as the extension cancels it.
      expect(await fetchSiteCsp(`${base}/away`)).toEqual([{ url: `${base}/away`, csp: "default-src 'none'", location: "https://other.invalid/x" }]);
    } finally {
      server.close();
    }
  });
});

describe("dev server pieces", () => {
  it("writes an enrollment list the extension's own parser reads back", async () => {
    const { canonicalKey, leafValue, mockBlock, mockList } = await import("../src/dev");
    const hash = "ab".repeat(32);
    expect(canonicalKey("app.localhost")).toBe("canonical/.localhost.app");
    expect(leafValue(hash)).toBe(`0a20${hash}`);
    expect(parseListLeaves(JSON.parse(mockList("app.localhost", hash)).leaves)).toEqual(new Map([["app.localhost", hash]]));
    expect(JSON.parse(mockBlock(new Date(0))).signed_header.header).toMatchObject({ chain_id: "webcat-test-02", time: "1970-01-01T00:00:00.000Z" });
  });

  it("trusts the self-signed certificate in the profile and speaks the debugging protocol framing", async () => {
    const { Rdp, certOverrideLines, selfSignedCert, userJs } = await import("../src/dev");
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-dev-"));
    const { cert } = await selfSignedCert(dir, "app.localhost");
    expect(certOverrideLines(cert, ["app.localhost", "127.0.0.1"], 8443)).toMatch(
      /^app\.localhost:8443\tOID\.2\.16\.840\.1\.101\.3\.4\.2\.1\t([0-9A-F]{2}:){31}[0-9A-F]{2}\t[A-Za-z0-9+/=]+\n127\.0\.0\.1:8443\t/,
    );
    expect(userJs({ a: true, b: "x" })).toBe('user_pref("a", true);\nuser_pref("b", "x");\n');
    await rm(dir, { recursive: true, force: true });

    // A fake Firefox: hello on connect, an event to be ignored, then the reply, split across writes.
    const { createServer } = await import("node:net");
    const server = createServer((socket) => {
      const send = (o: object) => socket.write(`${JSON.stringify(o).length}:${JSON.stringify(o)}`);
      send({ from: "root", applicationType: "browser" });
      socket.on("data", () => {
        send({ from: "root", type: "tabListChanged" });
        const reply = JSON.stringify({ from: "root", addonsActor: "server1.conn0.addonsActor2" });
        socket.write(`${reply.length}:${reply.slice(0, 10)}`);
        setTimeout(() => socket.write(reply.slice(10)), 20);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const rdp = new Rdp();
    await rdp.connect((server.address() as { port: number }).port);
    expect((await rdp.request("root", "getRoot")).addonsActor).toBe("server1.conn0.addonsActor2");
    rdp.close();
    server.close();
  });
});

describe("openssh public keys", () => {
  it("extracts the raw ed25519 key from an OpenSSH public key line", async () => {
    const { signerFromOpenSsh } = await import("../src/enrollment");
    expect(signerFromOpenSsh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKTjWh18iv9sSOg18yWXS1IepFJclk9Aq5XRRfPL2Iq0 hw-sim")).toBe(hexToBase64Url("a4e35a1d7c8aff6c48e835f325974b521ea4525c964f40ab95d145f3cbd88ab4"));
    expect(() => signerFromOpenSsh("ssh-rsa AAAA")).toThrow("expected an OpenSSH ed25519 public key line");
  });
});

describe("init", () => {
  it("writes a config, a policy and a valid enrollment from flags alone", async () => {
    const { runInit, CSP_PRESETS } = await import("../src/init");
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-init-"));
    await runInit({ dir, origin: "https://example.org", signer: ["aa".repeat(32)], casUrl: "https://example.org/cas/" });
    const config = JSON.parse(await readFile(path.join(dir, "webcat.config.json"), "utf8"));
    expect(config.app).toBe("https://example.org");
    expect(config.default_csp).toBe(CSP_PRESETS.static.csp);
    const enrollment = await loadEnrollment(path.join(dir, ".well-known/webcat/enrollment.json"));
    expect(enrollment.type).toBe("sigsum");
    expect(await readFile(path.join(dir, "trust_policy"), "utf8")).toContain("quorum");
    await rm(dir, { recursive: true, force: true });
  });
});

describe("trusted root drift", () => {
  it("reports new entries and newly ended ones", async () => {
    const { trustedRootDrift } = await import("../src/sigstore");
    const ca = (leaf: string, uri: string, validFor: any) => ({ uri, certChain: { certificates: [{ rawBytes: leaf }] }, validFor });
    const tlog = (key: string, baseUrl: string, validFor: any) => ({ baseUrl, publicKey: { rawBytes: key, validFor } });
    const pinned = { certificateAuthorities: [ca("A", "https://fulcio", { start: "2022" })], tlogs: [tlog("K1", "https://rekor", { start: "2021" })] };
    const community = {
      certificateAuthorities: [ca("A", "https://fulcio", { start: "2022", end: "2027-01-01" }), ca("B", "https://fulcio", { start: "2026" })],
      tlogs: [tlog("K1", "https://rekor", { start: "2021" }), tlog("K2", "https://log2026-1", { start: "2026" })],
      timestampAuthorities: [ca("T", "https://tsa", { start: "2025" })],
    };
    expect(trustedRootDrift(pinned, pinned)).toEqual([]);
    const { signingBlockedBy } = await import("../src/sigstore");
    expect(signingBlockedBy(pinned, community, { now: new Date("2026-06-01") })).toEqual([]); // CA A still active: additions only
    expect(signingBlockedBy(pinned, community, { now: new Date("2027-06-01") })).toEqual(["no currently valid certificate authority in the community root is in the enrollment's trusted root"]);
    expect(trustedRootDrift(pinned, community, new Date("2030-01-01"))).not.toContain("new certificate authority https://fulcio (valid from 2022) is not in the enrollment's trusted root");
    expect(trustedRootDrift(pinned, community)).toEqual([
      "certificate authority https://fulcio ends on 2027-01-01 in the community root",
      "new certificate authority https://fulcio (valid from 2026) is not in the enrollment's trusted root",
      "new transparency log https://log2026-1 (valid from 2026) is not in the enrollment's trusted root",
      "new timestamp authority https://tsa (valid from 2025) is not in the enrollment's trusted root",
    ]);
  });
});

describe("validity", () => {
  it("warns when a manifest expires within 30 days", async () => {
    const { describeValidity } = await import("../src/bundle");
    const now = Math.floor(Date.now() / 1000);
    expect(describeValidity(now + 100 * 86_400)).toMatch(/^valid until .*, (99|100) days left$/);
    expect(describeValidity(now + 5 * 86_400)).toMatch(/, (4|5) days left, WARNING: re-sign/);
  });
});

describe("site checks", () => {
  it("picks the CSP and file hash the extension would for a path", async () => {
    const { checkHeaders, expectedCsp, acceptableHashes } = await import("../src/site");
    const { effectiveManifest } = await import("../src/manifest");
    const manifest = {
      app: "a", version: "1", default_csp: "default-src 'none'", default_index: "index.html", default_fallback: "/404.html",
      files: { "/index.html": "A", "/404.html": "B", "/app/main.js": "C" }, wasm: [],
      extra_csp: { "/app/": "default-src 'none'; script-src 'self'", "/app/main.js": "default-src 'none'; script-src 'wasm-unsafe-eval'" },
    };
    expect(expectedCsp(manifest, "/")).toBe("default-src 'none'");
    expect(expectedCsp(manifest, "/app/other.js")).toBe("default-src 'none'; script-src 'self'");
    expect(expectedCsp(manifest, "/app/main.js")).toBe("default-src 'none'; script-src 'wasm-unsafe-eval'");
    // A legacy manifest and its 3.2.0 form answer the same: the keyed hash, plus the fallback for documents.
    const modern = { ...manifest, default_index: undefined, default_fallback: undefined, files: { ...manifest.files, "/": "A" }, fallback_hashes: ["B"] };
    for (const m of [effectiveManifest(manifest), modern]) {
      expect(acceptableHashes(m, "/", true)).toEqual(["A", "B"]);
      expect(acceptableHashes(m, "/missing.html", true)).toEqual(["B"]);
      expect(acceptableHashes(m, "/missing.js", false)).toEqual([]);
      expect(acceptableHashes(m, "/app/main.js", false)).toEqual(["C"]);
    }
    const problems = checkHeaders(manifest, "/", new Headers({ "content-security-policy": "default-src *", refresh: "0", "origin-agent-cluster": "?0" }));
    expect(problems).toHaveLength(4);
    expect(checkHeaders(manifest, "/", new Headers({ "content-security-policy": "default-src 'none'" }))).toEqual([]);
  });
});

describe("enrollment chain client", () => {
  it("solves proof of work challenges", () => {
    const challenge = "ca8dc16136a1df96d1c258bafbb23b096f7e1c28d22da0237dccd05d3c739f0e";
    const nonce = solvePow(challenge, 12);
    const digest = createHash("sha256").update(challenge + nonce).digest();
    expect(digest[0]).toBe(0);
    expect(digest[1] >> 4).toBe(0);
  });

  it("verifies a recorded list.json against its block like the extension, and rejects tampering", async () => {
    const list = JSON.parse(await readFile(path.join(__dirname, "fixtures/list.json"), "utf8"));
    const block = JSON.parse(await readFile(path.join(__dirname, "fixtures/block.json"), "utf8"));
    const verified = await verifyList(list, block);
    expect(verified.blockHeight).toBe(Number(block.signed_header.header.height)); // the verified block, one past the list's snapshot
    expect(verified.leaves.get("lsd.cat")).toMatch(/^[0-9a-f]{64}$/);
    const tampered = { ...list, leaves: list.leaves.map((l: string[], i: number) => (i === 0 ? [l[0], "0a20" + "ab".repeat(32)] : l)) };
    await expect(verifyList(tampered, block)).rejects.toThrow("leaves do not prove into the block's app hash");
    await expect(verifyList({ ...list, proof: { ...list.proof, app_hash: "00".repeat(32) } }, block)).rejects.toThrow("app hash does not match");
    const otherChain = JSON.parse(JSON.stringify(block)); otherChain.signed_header.header.chain_id = "other-chain";
    await expect(verifyList(list, otherChain)).rejects.toThrow("Chain ID mismatch");
    const badSig = JSON.parse(JSON.stringify(block)); badSig.signed_header.commit.signatures[0].signature = Buffer.alloc(64).toString("base64");
    await expect(verifyList(list, badSig)).rejects.toThrow("not signed by a quorum");
  });

  it("decodes list.json leaves into domain -> hash", () => {
    const entries = parseListLeaves([["canonical/.cat.lsd", "0a20" + "ab".repeat(32)], ["canonical/.org.endeixis.www", "0a20" + "cd".repeat(32)]]);
    expect(entries.get("lsd.cat")).toBe("ab".repeat(32));
    expect(entries.get("www.endeixis.org")).toBe("cd".repeat(32));
    expect(toFqdn("Example.COM")).toBe("example.com.");
  });
});
