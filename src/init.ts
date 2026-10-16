// `webcat init`: the few answers a site needs, written as the files the other commands expect,
// then the next steps printed. Every answer can be given as a flag, so CI never prompts.
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { buildEnrollmentObject } from "./enrollment.js";
import { generateSigsumKeys, sigsumEnrollmentFromPolicy } from "./sigsum.js";
import { ISSUER_V2_OID, SAN_OID, fetchCommunityTrustedRoot } from "./sigstore.js";
import { causeOf, invalid, log, validateAll } from "./utils.js";

export const CSP_PRESETS: Record<string, { title: string; csp: string }> = {
  static: {
    title: "Static site: no WebAssembly, no framing",
    csp: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  },
  wasm: {
    title: "Web app with WebAssembly and workers",
    csp: "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  },
};

// ponytail: snapshot of the Sigsum test policy from the WEBCAT docs; replace with a fetched canonical policy once one is published.
export const SIGSUM_TEST_POLICY = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`;

export const DEFAULT_MAX_AGE = 180 * 24 * 60 * 60; // the docs' example: six months

export interface InitOptions {
  origin?: string;
  version?: string;
  type?: "sigsum" | "sigstore";
  csp?: string;
  maxAge?: string | number;
  signer?: string[];
  keys?: string | number; // generate this many Sigsum keys instead of passing --signer
  threshold?: string | number;
  casUrl?: string;
  identity?: string;
  issuer?: string;
  dir: string;
}

type Ask = (flag: string, label: string, fallback?: string) => Promise<string>;

async function answers(options: InitOptions): Promise<Required<Pick<InitOptions, "origin" | "version" | "type" | "csp" | "maxAge">> & InitOptions> {
  const rl = stdin.isTTY ? createInterface({ input: stdin, output: stdout }) : null;
  // Without a terminal, defaults apply silently and anything without a default must be a flag.
  const ask: Ask = async (flag, label, fallback) => {
    if (!rl) {
      if (fallback === undefined) {
        throw invalid(`--${flag} is required when not running in a terminal`);
      }
      return fallback;
    }
    const reply = (await rl.question(fallback ? `${label} [${fallback}]: ` : `${label}: `)).trim();
    return reply || fallback || "";
  };
  const choose = async (flag: string, choices: Array<[key: string, title: string]>, fallback: string): Promise<string> => {
    if (rl) {
      choices.forEach(([key, title], i) => stdout.write(`  ${i + 1}) ${title} (${key})\n`));
    }
    const reply = await ask(flag, flag, fallback);
    const picked = choices.find(([key], i) => key === reply || String(i + 1) === reply);
    if (!picked) {
      throw invalid(`--${flag} must be one of ${choices.map(([key]) => key).join(", ")}`);
    }
    return picked[0];
  };
  try {
    const origin = options.origin ?? (await ask("origin", "origin (https://example.org)"));
    const version = options.version ?? (await ask("app-version", "version of this release", "1.0.0"));
    const type = (options.type ?? (await choose("type", [["sigsum", "Sigsum: you hold the signing keys"], ["sigstore", "Sigstore: sign from CI with an OIDC identity"]], "sigsum"))) as "sigsum" | "sigstore";
    let csp = options.csp;
    if (!csp) {
      const presets = Object.entries(CSP_PRESETS).map(([key, p]) => [key, p.title] as [string, string]);
      const preset = await choose("csp", [...presets, ["custom", "Type your own policy"]], "static");
      csp = preset === "custom" ? await ask("csp", "csp") : CSP_PRESETS[preset].csp;
    }
    const maxAge = options.maxAge ?? (await ask("max-age", "max-age (seconds a signed manifest stays valid)", String(DEFAULT_MAX_AGE)));
    const rest: InitOptions = { ...options };
    if (type === "sigsum") {
      if (!rest.signer && rest.keys === undefined) {
        rest.keys = await ask("keys", "how many signing keys to generate now with sigsum-key (0 to use existing public keys)", "2");
      }
      if (!rest.signer && Number(rest.keys) === 0) {
        rest.signer = (await ask("signer", "signer public keys, hex or base64, comma separated")).split(",").map((s) => s.trim()).filter(Boolean);
      }
      rest.threshold ??= await ask("threshold", "threshold (signatures required)", "1");
      rest.casUrl ??= await ask("cas-url", "cas-url (where Sigsum proofs are published)", `${origin.replace(/\/+$/, "")}/cas/`);
    } else {
      rest.identity ??= await ask("identity", "identity (signing identity, e.g. an email or a GitHub workflow URL)");
      rest.issuer ??= await ask("issuer", "issuer (OIDC issuer)", "https://token.actions.githubusercontent.com");
    }
    return { ...rest, origin, version, type, csp, maxAge };
  } finally {
    rl?.close();
  }
}

export async function runInit(options: InitOptions): Promise<void> {
  const a = await answers(options);
  validateAll([
    () => {
      try {
        if (new URL(a.origin).protocol !== "https:") throw new Error("must use https://");
      } catch (err) {
        throw invalid(`--origin must be an https URL: ${causeOf(err)}`);
      }
    },
    () => {
      try {
        validateCSP(a.csp);
      } catch (err) {
        throw invalid(`--csp must be a WEBCAT-compatible CSP: ${causeOf(err)}`);
      }
    },
  ]);
  let signers = a.signer ?? [];
  let keyPaths: string[] = [];
  if (a.type === "sigsum" && Number(a.keys) > 0) {
    ({ signers, paths: keyPaths } = await generateSigsumKeys(a.dir, Number(a.keys)));
    keyPaths = keyPaths.map((p) => path.relative(process.cwd(), p));
    keyPaths.forEach((p) => log(`wrote ${p} (private key, keep it out of the repo)`));
    const gitignore = await readFile(`${a.dir}/.gitignore`, "utf8").catch(() => "");
    if (!/^keys\/?$/m.test(gitignore)) {
      await appendFile(`${a.dir}/.gitignore`, `${gitignore && !gitignore.endsWith("\n") ? "\n" : ""}keys/\n`);
      log("added keys/ to .gitignore");
    }
  }
  const enrollment =
    a.type === "sigsum"
      ? buildEnrollmentObject({
          type: "sigsum",
          ...(await sigsumEnrollmentFromPolicy(SIGSUM_TEST_POLICY)),
          signers,
          threshold: a.threshold ?? 1,
          maxAge: a.maxAge,
          casUrl: a.casUrl ?? "",
        })
      : buildEnrollmentObject({
          type: "sigstore",
          trustedRoot: await fetchCommunityTrustedRoot(),
          claims: { [SAN_OID]: a.identity ?? "", [ISSUER_V2_OID]: a.issuer ?? "" },
          maxAge: a.maxAge,
        });

  const config = { app: a.origin, version: a.version, default_csp: a.csp, default_index: "index.html", default_fallback: "/index.html", wasm: [], extra_csp: {} };
  const files: Array<[string, string]> = [
    ["webcat.config.json", JSON.stringify(config, null, 2) + "\n"],
    ...(a.type === "sigsum" ? [["trust_policy", SIGSUM_TEST_POLICY] as [string, string]] : []),
    [".well-known/webcat/enrollment.json", JSON.stringify(enrollment, null, 2) + "\n"],
  ];
  await mkdir(`${a.dir}/.well-known/webcat`, { recursive: true });
  for (const [name, contents] of files) {
    await writeFile(`${a.dir}/${name}`, contents);
    log(`wrote ${name}`);
  }
  const host = new URL(a.origin).host;
  const key = keyPaths[0] ?? "<private key>";
  const sign =
    a.type === "sigsum"
      ? `webcat manifest sign -k ${key} -o manifest.signed.json      # repeat with each key up to the threshold`
      : "webcat manifest sign --type sigstore -o manifest.signed.json  # in CI with the identity above, or --interactive";
  stdout.write(`
Next steps
  1. Serve the .well-known/webcat/ directory at ${a.origin}/.well-known/webcat/
  2. Send this header on every response, byte for byte:
       Content-Security-Policy: ${a.csp}
  3. Build the site, then generate, sign and bundle the manifest:
       webcat manifest generate${a.type === "sigsum" ? "" : " --type sigstore"} -d <build dir> -o manifest.json
       ${sign}
       webcat bundle create -o .well-known/webcat/bundle.json
  4. Deploy, then check what visitors will see:   webcat site check ${host}
  5. Ask the oracles to record the enrollment:    webcat enrollment submit ${host}
  6. Follow promotion on the chain:               webcat enrollment status ${host}
`);
}
