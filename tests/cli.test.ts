import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { Hash, KeyHash, Leaf, Signature } from "@freedomofpress/sigsum/dist/types";
import {
  buildEnrollmentObject,
  decodeKeyMaterial,
  ensureAbsolutePath,
  ensureNonEmptyString,
  ensureRecordOfStrings,
  hexToBase64Url,
  loadBundleDocument,
  loadEnrollment,
  loadManifestConfig,
  loadManifestDocument,
  parseEnrollmentObject,
  parseInteger,
  parseManifestDocumentObject,
  parseSignerKey,
  scanDirectory,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "../src/test-exports";
import { writeCasObject } from "../src/cas";

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
      /key must be 32 bytes/,
    );
    expect(() => decodeKeyMaterial("00".repeat(8), "key")).toThrow(
      "key must be 32 bytes",
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
    expect(() => parseInteger(-1, "value")).toThrow("value must be a positive integer");
    expect(() => parseInteger("oops", "value")).toThrow("value must be a positive integer");
    expect(parseInteger(5, "value")).toBe(5);
  });

  it("enforces max-age bounds", () => {
    expect(() => validateMaxAge(60 * 60 * 24 * 7)).toThrow(
      "max-age must be larger than one week",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 365)).toThrow(
      "max-age must be smaller than one year",
    );
    expect(() => validateMaxAge(60 * 60 * 24 * 30)).not.toThrow();
  });

  it("validates CAS URLs", () => {
    expect(() => validateCasUrl("notaurl")).toThrow("invalid CAS URL");
    expect(() => validateCasUrl("http://example.com")).toThrow("CAS URL must use https://");
    expect(() => validateCasUrl("https://")).toThrow("invalid CAS URL");
    expect(() => validateCasUrl("https://example.com")).not.toThrow();
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
      }),
    ).toThrow("at least one signer must be provided");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner, baseSigner],
        threshold: 1,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("duplicate signer keys detected");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner, secondSigner],
        threshold: 3,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("threshold cannot exceed number of signers");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner],
        threshold: 0,
        maxAge: 1_000_000,
        casUrl: "https://example.com",
      }),
    ).toThrow("threshold must be at least 1");

    expect(() =>
      buildEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: [baseSigner],
        threshold: 1,
        maxAge: 60 * 60 * 24 * 8,
        casUrl: "http://example.com",
      }),
    ).toThrow("CAS URL must use https://");
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
      }),
    );

    const loaded = await loadEnrollment(file);
    if (loaded.type !== "sigsum") {
      throw new Error("expected sigsum enrollment");
    }
    expect(loaded.signers).toEqual([hexToBase64Url(baseSigner)]);
    expect(loaded.type).toBe("sigsum");

    await writeFile(file, "not json");
    await expect(loadEnrollment(file)).rejects.toThrow("failed to parse enrollment JSON");

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
      }),
    ).toThrow("enrollment.policy must be a base64url string");

    expect(() =>
      parseEnrollmentObject({
        type: "sigsum",
        policy: "policy",
        signers: ["a", "a"],
        threshold: 1,
        max_age: 1,
        cas_url: "https://example.com",
      }),
    ).toThrow("duplicate signer keys detected in enrollment");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: "",
        claims: { "2.5.29.17": "id" },
        max_age: 1_000_000,
      }),
    ).toThrow("enrollment.trusted_root must be an object");

    expect(() =>
      parseEnrollmentObject({
        type: "sigstore",
        trusted_root: {},
        claims: { not_oid: "id" },
        max_age: 1_000_000,
      }),
    ).toThrow("enrollment.claims keys must be valid OID strings");
  });
});

describe("string and path validation", () => {
  it("ensures non-empty strings", () => {
    expect(() => ensureNonEmptyString("", "field")).toThrow("field must be a non-empty string");
    expect(ensureNonEmptyString(" value ", "field")).toBe("value");
  });

  it("ensures absolute paths", () => {
    expect(() => ensureAbsolutePath("relative", "p")).toThrow("p must start with '/'");
    expect(ensureAbsolutePath("/absolute", "p")).toBe("/absolute");
  });

  it("ensures records of strings", () => {
    expect(() => ensureRecordOfStrings([], "record")).toThrow("record must be an object");
    expect(() => ensureRecordOfStrings({ key: "" }, "record")).toThrow(
      "record entries must be non-empty strings",
    );
    expect(ensureRecordOfStrings({ a: "x" }, "record")).toEqual({ a: "x" });
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
      "failed to parse manifest config JSON",
    );

    await writeFile(
      configPath,
      JSON.stringify({
        app: "https://example.com",
        version: "1.0.0",
        default_csp: "csp",
        default_index: "index.html",
        default_fallback: "relative.html",
      }),
    );

    await expect(loadManifestConfig(configPath)).rejects.toThrow(
      "config.default_fallback must start with '/'",
    );

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

    const manifest = {
      manifest: {
        files: {},
        wasm: [],
        extra_csp: {},
        timestamp: "2024-01-01T00:00:00Z",
        app: "app",
        version: "1",
        default_csp: "csp",
        default_index: "index.html",
        default_fallback: "/error.html",
      },
      signatures: {},
    };

    await writeFile(manifestPath, JSON.stringify(manifest));
    const loaded = await loadManifestDocument(manifestPath);
    expect(Object.keys(loaded.manifest.files)).toHaveLength(0);

    await writeFile(manifestPath, "{]");
    await expect(loadManifestDocument(manifestPath)).rejects.toThrow(
      "failed to parse manifest JSON",
    );

    expect(() => parseManifestDocumentObject({})).toThrow(
      "manifest file must include a 'manifest' object",
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

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow(
      "each signer must be a non-empty string",
    );

    await writeFile(bundlePath, "{}");
    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle is missing 'enrollment'");

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

    await expect(loadBundleDocument(bundlePath)).rejects.toThrow("bundle is missing 'manifest'");

    await rm(dir, { recursive: true, force: true });
  });
});
