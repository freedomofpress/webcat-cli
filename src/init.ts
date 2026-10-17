// `webcat init`: the few answers a site needs, written as the files the other commands expect,
// then the next steps printed. Every answer can be given as a flag, so CI never prompts.
import { access, appendFile, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { buildEnrollmentObject } from "./enrollment.js";
import { builtinPolicyText, deriveSignerKeyFromPrivateKey, generateSigsumKey, generateSigsumKeys, sigsumEnrollmentFromPolicy } from "./sigsum.js";
import { ISSUER_V2_OID, SAN_OID, fetchCommunityTrustedRoot } from "./sigstore.js";
import { gitRemote, gitRoot, gitStage, gitTagAtHead } from "./git.js";
import { WELL_KNOWN_DIR, publishEnrollment } from "./history.js";
import { causeOf, invalid, log, readText, validateAll } from "./utils.js";

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

// Policies built into the Sigsum tools. Production logs rate-limit by domain, so signing needs a DNS token key.
export const SIGSUM_POLICIES: Record<string, { name: string; title: string; rateLimited: boolean }> = {
  test: { name: "sigsum-test-2025-3", title: "Sigsum test logs, no rate limiting, for trying things out", rateLimited: false },
  production: { name: "sigsum-generic-2025-1", title: "Sigsum production logs vetted by the Sigsum project (2-of-3 witnesses), rate-limited per domain", rateLimited: true },
};

// ponytail: offline copy of the test policy for when sigsum-policy is not installed; production always comes from the tool.
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
  policy?: string; // test, production, or a path to a policy file
  keys?: string | number; // generate this many Sigsum keys instead of passing --signer
  threshold?: string | number;
  source?: string; // git repository URL; "" for closed source
  directory?: string; // where the built site lives
  artifact?: string; // release archive URL template with ${version}
  git?: boolean; // stage written files (default when inside a repository)
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
    // git answers first: the remote is the source, the tag at HEAD is the version.
    const remote = (await gitRemote(options.dir)) ?? "";
    const source = options.source ?? (await ask("source", "source repository (git URL for reproducible builds, empty for closed source)", remote));
    const artifact = options.artifact ?? (await ask("artifact", "artifact (release archive URL template with ${version}, empty if none)", ""));
    const version = options.version ?? (await ask("app-version", "version of this release (a git tag when source is set)", (await gitTagAtHead(options.dir)) ?? "1.0.0"));
    let found = "dist";
    for (const candidate of ["dist", "public", "build", "out", "_site"]) {
      if (await access(`${options.dir}/${candidate}`).then(() => true, () => false)) {
        found = candidate;
        break;
      }
    }
    const directory = options.directory ?? (await ask("directory", "directory with the built site", found));
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
      rest.policy ??= await choose("policy", [...Object.entries(SIGSUM_POLICIES).map(([k, p]) => [k, p.title] as [string, string]), ["file", "Path to your own policy file"]], "test");
      if (rest.policy === "file") {
        rest.policy = await ask("policy", "policy file path");
      }
      if (!rest.signer && rest.keys === undefined) {
        rest.keys = await ask("keys", "how many signing keys to generate now with sigsum-key (0 to use existing public keys)", "2");
      }
      if (!rest.signer && Number(rest.keys) === 0) {
        rest.signer = (await ask("signer", "signer public keys: hex, base64 or OpenSSH .pub paths (hardware keys via ssh-agent), comma separated"))
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }
      rest.threshold ??= await ask("threshold", "threshold (signatures required)", "1");
    } else {
      rest.identity ??= await ask("identity", "identity (signing identity, e.g. an email or a GitHub workflow URL)");
      rest.issuer ??= await ask("issuer", "issuer (OIDC issuer)", "https://token.actions.githubusercontent.com");
    }
    return { ...rest, origin, version, type, csp, maxAge, source, artifact, directory };
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
  const chosen = SIGSUM_POLICIES[a.policy ?? "test"];
  const policyText =
    a.type !== "sigsum"
      ? ""
      : chosen
        ? await builtinPolicyText(chosen.name).catch((err) => {
            if (chosen === SIGSUM_POLICIES.test) return SIGSUM_TEST_POLICY;
            throw invalid(`the ${a.policy} policy needs the sigsum-policy tool (go install sigsum.org/sigsum-go/cmd/sigsum-policy@latest): ${causeOf(err)}`);
          })
        : await readText(a.policy!, "policy");
  let signers = a.signer ?? [];
  let keyPaths: string[] = [];
  const touched: string[] = []; // files changed besides the ones written below, staged together with them
  if (a.type === "sigsum" && Number(a.keys) > 0) {
    ({ signers, paths: keyPaths } = await generateSigsumKeys(a.dir, Number(a.keys)));
    keyPaths = keyPaths.map((p) => path.relative(process.cwd(), p));
    keyPaths.forEach((p) => log(`wrote ${p} (private key, keep it out of the repo)`));
    const gitignore = await readFile(`${a.dir}/.gitignore`, "utf8").catch(() => "");
    if (!/^keys\/?$/m.test(gitignore)) {
      await appendFile(`${a.dir}/.gitignore`, `${gitignore && !gitignore.endsWith("\n") ? "\n" : ""}keys/\n`);
      log("added keys/ to .gitignore");
      touched.push(`${a.dir}/.gitignore`);
    }
  }
  // Production logs only accept submissions carrying a token signed by a key published in the domain's DNS.
  let tokenHex: string | undefined;
  if (a.type === "sigsum" && chosen?.rateLimited) {
    const tokenPath = `${a.dir}/keys/token`;
    await generateSigsumKey(tokenPath).catch(() => undefined); // keep an existing token key
    tokenHex = Buffer.from(await deriveSignerKeyFromPrivateKey(tokenPath), "base64url").toString("hex");
    log(`wrote ${path.relative(process.cwd(), tokenPath)} (rate-limit token key, keep it out of the repo)`);
  }
  const enrollment =
    a.type === "sigsum"
      ? await buildEnrollmentObject({
          type: "sigsum",
          ...(await sigsumEnrollmentFromPolicy(policyText)),
          signers,
          threshold: a.threshold ?? 1,
          maxAge: a.maxAge,
        })
      : await buildEnrollmentObject({
          type: "sigstore",
          trustedRoot: await fetchCommunityTrustedRoot(),
          claims: { [SAN_OID]: a.identity ?? "", [ISSUER_V2_OID]: a.issuer ?? "" },
          maxAge: a.maxAge,
        });

  // With a source repository the release tag is the version, so the config does not pin one unless asked to.
  const config = {
    ...(a.source ? { source: a.source } : {}),
    ...(a.artifact ? { artifact: a.artifact } : {}),
    ...(!a.source || options.version !== undefined ? { version: a.version } : {}),
    directory: a.directory,
    default_csp: a.csp,
    default_index: "index.html",
    default_fallback: "/index.html",
    wasm: [],
    extra_csp: {},
  };
  if (!a.source && !a.artifact) log("Warning: without source or artifact, auditors cannot reproduce or fetch this site's releases");
  const files: Array<[string, string]> = [
    ["webcat.config.json", JSON.stringify(config, null, 2) + "\n"],
    ...(a.type === "sigsum" ? [["trust_policy", policyText] as [string, string]] : []),
  ];
  const written: string[] = [...touched];
  for (const [name, contents] of files) {
    await writeFile(`${a.dir}/${name}`, contents);
    written.push(`${a.dir}/${name}`);
    log(`wrote ${name}`);
  }
  for (const file of await publishEnrollment(`${a.dir}/${WELL_KNOWN_DIR}`, enrollment)) {
    written.push(file);
    log(`wrote ${path.relative(a.dir, file)}`);
  }
  if (a.git !== false && (await gitRoot(a.dir))) {
    await gitStage(written.map((f) => path.resolve(f)), undefined, a.dir);
    log("staged in git; commit them with your release");
  }
  const host = new URL(a.origin).host;
  const key = keyPaths[0] ?? (a.signer ?? []).find((s) => s.endsWith(".pub")) ?? "<private key, or .pub for ssh-agent>";
  const token = tokenHex ? ` --token-signing-key keys/token --token-domain ${host}` : "";
  const release =
    a.type === "sigsum"
      ? `webcat release -k ${key}${token}${Number(a.threshold ?? 1) > 1 ? " -k <next key>" : ""}`
      : "webcat release --type sigstore          # in CI with the identity above, or add --interactive";
  const dns = tokenHex
    ? `
  0. Publish this DNS record so the production logs accept your submissions:
       _sigsum_v1.${host}. IN TXT "${tokenHex}"`
    : "";
  stdout.write(`
Next steps${dns}
  1. Serve ${WELL_KNOWN_DIR}/ at ${a.origin}/${WELL_KNOWN_DIR}/
  2. Send this header on every response, byte for byte:
       Content-Security-Policy: ${a.csp}
  3. Commit ${WELL_KNOWN_DIR}/: it is the site's history, and every file in it must stay published
  4. Build the site into ${a.directory}/, tag the release, then publish it in one step:
       ${release}
     (generates, signs, writes bundle.json and manifest.<type>.<hash>.json${a.artifact ? ", the release archive" : ""}, and commits)
  5. Deploy with ${WELL_KNOWN_DIR}/ copied into the web root, then check what visitors and auditors will see:
       webcat site check ${host}
  6. Ask the oracles to record the enrollment:    webcat enrollment submit ${host}
  7. Follow promotion on the chain:               webcat enrollment status ${host}
`);
}
