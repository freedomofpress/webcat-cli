import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { Hash, KeyHash, Leaf, Signature } from "@freedomofpress/sigsum/dist/types";
import { buildEnrollmentObject, loadEnrollment, parseEnrollmentObject, parseSignerKey } from "../src/enrollment";
import { loadBundleDocument } from "../src/bundle";
import { parseListLeaves, solvePow, toFqdn } from "../src/chain";
import { writeCasObject } from "../src/cas";
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

describe("enrollment helpers", () => {
  const baseSigner = "aa".repeat(32);
  const secondSigner = "bb".repeat(32);

  it("builds normalized enrollment objects", () => {
    const enrollment = buildEnrollmentObject({
      type: "sigsum",
      policy: "policy-bytes",
      signers: [baseSigner],
      threshold: 1,
      maxAge: 1_000_000,
      casUrl: "https://example.com",
      logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
    });

    expect(enrollment.type).toBe("sigsum");
    if (enrollment.type !== "sigsum") {
      throw new Error("expected sigsum enrollment");
    }
    expect(enrollment.signers).toEqual([hexToBase64Url(baseSigner)]);
    expect(enrollment.threshold).toBe(1);
    expect(enrollment.max_age).toBe(1_000_000);
  });

  it("rejects duplicate or insufficient signer information", () => {
    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_SIGNERS_EMPTY");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner, baseSigner],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment.signers must not contain duplicates");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner, secondSigner],
        threshold: 3,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_THRESHOLD_IMPOSSIBLE");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner],
        threshold: 0,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_THRESHOLD_MALFORMED");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner],
        threshold: 1,
        maxAge: 60 * 60 * 24 * 8,
        casUrl: "http://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment.cas_url must use https://");
  });

  it("builds sigstore enrollment objects", () => {
    const trustedRoot = { fulcio: { root: "data" } };
    const enrollment = buildEnrollmentObject({
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
        policy: "policy",
        signers: [hexToBase64Url(baseSigner)],
        threshold: 1,
        max_age: 1_000_000,
        cas_url: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
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
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_POLICY_LENGTH");

    expect(() =>
      parseEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [hexToBase64Url(baseSigner), hexToBase64Url(baseSigner)],
        threshold: 1,
        max_age: 1_000_000,
        cas_url: "https://example.com",
        logs: { "4jFUdrXpAfvfRSCxhR5nfwQXlT7YjLiQ_v1Iz9ZwYCk": "https://log.example" },
      }),
    ).toThrow("enrollment.signers must not contain duplicates");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: "",
        claims: { "2.5.29.17": "id" },
        max_age: 1_000_000,
      }),
    ).toThrow("enrollment: ERR_WEBCAT_ENROLLMENT_TRUSTED_ROOT_MISSING");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: {},
        claims: { not_oid: "id" },
        max_age: 1_000_000,
      }),
    ).toThrow("enrollment.claims keys must be OIDs");
  });
});

describe("CAS resolution", () => {
  it("resolves from leaf checksum to manifest via CAS", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-cas-"));
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      const canonicalManifest = JSON.stringify({ manifest: { app: "demo" }, signatures: {} });
      const messageHash = createHash("sha256").update(canonicalManifest).digest();
      const checksum = new Hash(createHash("sha256").update(messageHash).digest());
      const signature = new Signature(new Uint8Array(64));
      const keyHash = new KeyHash(new Uint8Array(32));
      const leafBytes = new Leaf(checksum, signature, keyHash).toBytes();

      const { hash: leafHash } = await writeCasObject(leafBytes);
      await writeCasObject(messageHash);
      await writeCasObject(canonicalManifest);

      const storedLeaf = await readFile(path.join(dir, "cas", leafHash));
      const storedChecksum = storedLeaf.subarray(1, 33);
      const checksumHex = Buffer.from(storedChecksum).toString("hex");

      const storedMessageHash = await readFile(path.join(dir, "cas", checksumHex));
      const messageHashHex = Buffer.from(storedMessageHash).toString("hex");

      const storedManifest = await readFile(path.join(dir, "cas", messageHashHex), "utf8");
      expect(storedManifest).toBe(canonicalManifest);
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
    const scan = { files: new Map([["/index.html", hash]]), wasm: new Set<string>() };
    const config = { app: "https://example.com", version: "1", default_csp: "default-src 'none'", default_index: "index.html", default_fallback: "/index.html", wasm: [], extra_csp: {} };
    expect(buildManifest(config, scan).files).toEqual({ "/index.html": hash });
    expect(() => buildManifest({ ...config, default_fallback: "/missing.html" }, scan)).toThrow("config: ERR_WEBCAT_MANIFEST_DEFAULT_FALLBACK_MISSING_FILE");
    expect(() => buildManifest({ ...config, default_csp: "default-src 'self'" }, scan)).toThrow("config.default_csp must be a WEBCAT-compatible CSP");
    expect(() => buildManifest({ ...config, extra_csp: { "/a": "script-src https://cdn.example" } }, scan)).toThrow("config.extra_csp['/a'] must be a WEBCAT-compatible CSP");
    expect(() => buildManifest({ ...config, default_fallback: "/missing.html", default_csp: "default-src 'self'", extra_csp: { "/a": "csp" } }, scan)).toThrow(
      /3 problems:\n  - config: ERR_WEBCAT_MANIFEST_DEFAULT_FALLBACK_MISSING_FILE\n  - config.default_csp must be .*\n  - config.extra_csp\['\/a'\] must be/,
    );
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

    const result = await scanDirectory(dir, { excludePaths: ["/private", "ignore.txt"] });
    expect(result.files.has("/index.html")).toBe(true);
    expect(result.files.has("/ignore.txt")).toBe(false);
    expect(result.files.has("/private/hidden.txt")).toBe(false);

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
          policy: "policy",
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
          policy: "policy",
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
    const { checkHeaders, expectedCsp, expectedHash } = await import("../src/site");
    const manifest = {
      app: "a", version: "1", default_csp: "default-src 'none'", default_index: "index.html", default_fallback: "/404.html",
      files: { "/index.html": "A", "/404.html": "B", "/app/main.js": "C" }, wasm: [],
      extra_csp: { "/app/": "default-src 'none'; script-src 'self'", "/app/main.js": "default-src 'none'; script-src 'wasm-unsafe-eval'" },
    };
    expect(expectedCsp(manifest, "/")).toBe("default-src 'none'");
    expect(expectedCsp(manifest, "/app/other.js")).toBe("default-src 'none'; script-src 'self'");
    expect(expectedCsp(manifest, "/app/main.js")).toBe("default-src 'none'; script-src 'wasm-unsafe-eval'");
    expect(expectedHash(manifest, "/", true)).toBe("A");
    expect(expectedHash(manifest, "/missing.html", true)).toBe("B");
    expect(expectedHash(manifest, "/missing.js", false)).toBeUndefined();
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

  it("decodes list.json leaves into domain -> hash", () => {
    const entries = parseListLeaves({
      block_height: 1,
      leaves: [["canonical/.cat.lsd", "0a20" + "ab".repeat(32)], ["canonical/.org.endeixis.www", "0a20" + "cd".repeat(32)]],
    });
    expect(entries.get("lsd.cat")).toBe("ab".repeat(32));
    expect(entries.get("www.endeixis.org")).toBe("cd".repeat(32));
    expect(toFqdn("Example.COM")).toBe("example.com.");
  });
});
