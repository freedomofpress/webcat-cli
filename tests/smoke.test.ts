// Runs the real command line (not the helpers) over the examples: the layer unit tests cannot see.
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

function webcat(...args: string[]): { stdout: string; code: number } {
  try {
    return { stdout: execFileSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), code: 0 };
  } catch (err: any) {
    return { stdout: `${err.stdout ?? ""}${err.stderr ?? ""}`, code: err.status };
  }
}

describe("command line", () => {
  it("hashes and canonicalizes the examples, including legacy flag spellings", () => {
    expect(webcat("manifest", "hash", "-i", "examples/manifest.json").stdout.trim()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(webcat("manifest", "hash", "-m", "examples/manifest.json").stdout).toBe(webcat("manifest", "hash", "-i", "examples/manifest.json").stdout);
    expect(webcat("enrollment", "canonicalize", "-e", "examples/enrollment.json").stdout).toMatch(/^\{"cas_url":/);
    expect(webcat("enrollment", "hash", "-i", "examples/enrollment.json").code).toBe(0);
  });

  it("verifies the example bundle with the extension's verifier", () => {
    const { stdout, code } = webcat("manifest", "verify", "examples/bundle.json");
    // The fixture ages: a verified window today, an expiry code once it is a year old.
    expect([0, 1]).toContain(code);
    expect(stdout).toMatch(code === 0 ? /^Enrollment policy hash: .*\nVERIFIED: valid until .* days left\n$/ : /FAILED: ERR_WEBCAT_MANIFEST_EXPIRED/);
  });

  it("answers csp check with exit codes", () => {
    expect(webcat("csp", "check", "default-src 'none'; script-src 'self'")).toEqual({ stdout: "OK: WEBCAT-compatible\n", code: 0 });
    expect(webcat("csp", "check", "default-src *").code).toBe(1);
  });

  it("generates a manifest from a config and a directory", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "webcat-smoke-"));
    await writeFile(path.join(dir, "index.html"), "<h1>hi</h1>");
    const config = path.join(await mkdtemp(path.join(tmpdir(), "webcat-smoke-cfg-")), "webcat.config.json"); // outside the scanned dir
    await writeFile(config, JSON.stringify({ app: "https://example.org", version: "1.0.0", default_csp: "default-src 'none'", default_index: "index.html", default_fallback: "/index.html" }));
    const { stdout, code } = webcat("manifest", "generate", "--type", "sigstore", "-c", config, "-d", dir);
    expect(code).toBe(0);
    const manifest = JSON.parse(stdout).manifest;
    expect(Object.keys(manifest.files)).toEqual(["/", "/index.html"]);
    expect(manifest.manifest_schema).toBe(1);
    expect(manifest.fallback_hashes).toEqual([manifest.files["/index.html"]]);
  });

  it("reports every missing flag at once with exit 2", () => {
    const { stdout, code } = webcat("enrollment", "create", "-p", "/nonexistent");
    expect(code).toBe(2);
    expect(stdout).toContain("--signer is required");
    expect(stdout).toContain("--threshold is required");
  });

  it("maps usage errors to exit 2 and prints a version", () => {
    expect(webcat("manifest", "sign", "--type", "nope").code).toBe(2);
    expect(webcat("--version").stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
