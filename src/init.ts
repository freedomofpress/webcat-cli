// `webcat init`: the few answers a site needs, written as the files the other commands expect,
// then the next steps printed. Every answer can be given as a flag, so CI never prompts.
import { access, appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { buildEnrollmentObject, signerFromValue } from "./enrollment.js";
import { builtinPolicyText, deriveSignerKeyFromPrivateKey, generateSigsumKey, generateSigsumKeys, sigsumEnrollmentFromPolicy } from "./sigsum.js";
import { forgeOf, releaseWorkflow, verifyWorkflow, workflowDir } from "./ci.js";
import { gitRemote, gitTagAtHead } from "./git.js";
import { WELL_KNOWN_DIR, publishEnrollment } from "./history.js";
import { fetchCommunityTrustedRoot, ISSUER_V2_OID, SAN_OID, withoutRekorV1 } from "./sigstore.js";
import { causeOf, invalid, log, readText, validateAll } from "./utils.js";

export const CSP_PRESETS: Record<string, { title: string; csp: string }> = {
  static: {
    title: "a static site, no WebAssembly, no framing",
    csp: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  },
  wasm: {
    title: "a web app with WebAssembly and workers",
    csp: "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  },
};

// Policies built into the Sigsum tools. Production logs rate-limit by domain, so signing needs a DNS token key.
export const SIGSUM_POLICIES: Record<string, { name: string; title: string; rateLimited: boolean }> = {
  test: { name: "sigsum-test-2025-3", title: "the Sigsum test logs, no rate limiting, for trying things out", rateLimited: false },
  production: { name: "sigsum-generic-2025-1", title: "the Sigsum production logs vetted by the Sigsum project, 2-of-3 witnesses, rate-limited per domain", rateLimited: true },
};

// Offline copy of the test policy for when sigsum-policy is not installed; production always comes from the tool.
export const SIGSUM_TEST_POLICY = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
`;

// An identity that names a ref prefix (ending in @refs/tags/ or @refs/heads/) is meant as one: claim it with ^.
export const tagPrefixIdentity = (identity: string): string => (/@refs\/(tags|heads)\/$/.test(identity) && !identity.startsWith("^") ? `^${identity}` : identity);

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
  identity?: string;
  issuer?: string;
  keepRekorV1?: boolean; // leave rekor.sigstore.dev in the Sigstore trusted root
  source?: string; // git repository URL; "" for closed source
  artifact?: string; // release archive URL template with ${version}
  directory?: string; // where the built site lives
  workflows?: boolean; // write the CI jobs for the forge of source (default: yes)
  dir: string;
}

// Validators shared by the prompts (re-ask on failure) and the flags (fail at the end).
const httpsOrigin = (value: string): void => {
  try {
    if (new URL(value).protocol !== "https:") throw new Error("must use https://");
  } catch (err) {
    throw invalid(`--origin must be an https URL: ${causeOf(err)}`);
  }
};
const compatibleCsp = (value: string): void => {
  try {
    validateCSP(value);
  } catch (err) {
    throw invalid(`--csp must be a WEBCAT-compatible CSP: ${causeOf(err)}`);
  }
};
const wholeNumber = (flag: string) => (value: string): void => {
  if (!/^\d+$/.test(value)) throw invalid(`--${flag} must be a whole number`);
};
const httpsUrl = (flag: string) => (value: string): void => {
  try {
    if (new URL(value).protocol !== "https:") throw new Error("must use https://");
  } catch (err) {
    throw invalid(`--${flag} must be an https URL: ${causeOf(err)}`);
  }
};
const readableFile = (flag: string) => (value: string): Promise<void> =>
  access(value).catch(() => {
    throw invalid(`--${flag}: cannot read ${value}`);
  });
const signerKeys = async (value: string): Promise<void> => {
  for (const v of value.split(",").map((s) => s.trim()).filter(Boolean)) await signerFromValue(v);
};
const atMost = (flag: string, count: number) => (value: string): void => {
  wholeNumber(flag)(value);
  if (Number(value) < 1 || Number(value) > count) throw invalid(`--${flag} must be between 1 and ${count}, the number of signing keys`);
};

type Ask = (flag: string, question: string, fallback?: string, validate?: (value: string) => void | Promise<void>) => Promise<string>;

async function answers(options: InitOptions): Promise<Required<Pick<InitOptions, "origin" | "version" | "type" | "csp" | "maxAge">> & InitOptions> {
  const rl = stdin.isTTY ? createInterface({ input: stdin, output: stdout }) : null;
  // Each prompt is a question, then "flag [default]: ". A rejected answer is explained and asked again.
  // Without a terminal, defaults apply silently and anything without a default must be a flag.
  const ask: Ask = async (flag, question, fallback, validate) => {
    if (!rl) {
      if (fallback === undefined) {
        throw invalid(`--${flag} is required when not running in a terminal`);
      }
      return fallback;
    }
    stdout.write(`${question}\n`);
    for (;;) {
      const reply = (await rl.question(fallback ? `${flag} [${fallback}]: ` : `${flag}: `)).trim() || fallback || "";
      try {
        if (!reply) throw invalid(`${flag} is required`);
        await validate?.(reply);
        stdout.write("\n");
        return reply;
      } catch (err) {
        stdout.write(`${causeOf(err)}\n`);
      }
    }
  };
  const choose = async (flag: string, question: string, choices: Array<[key: string, title: string]>, fallback: string): Promise<string> => {
    const keys = choices.map(([key]) => key);
    const pick = (reply: string) => choices.find(([key], i) => key === reply || String(i + 1) === reply)?.[0];
    const reply = await ask(flag, [question, ...choices.map(([key, title], i) => `  ${i + 1}. ${key}: ${title}`)].join("\n"), fallback, (value) => {
      if (!pick(value)) throw invalid(`--${flag} must be one of ${keys.join(", ")}`);
    });
    return pick(reply)!;
  };
  try {
    const origin = options.origin ?? (await ask("origin", "What is the public URL of your site? Give the origin, in the form https://example.org", undefined, httpsOrigin));
    // git answers first: the remote is the source, the tag at HEAD is the version.
    const source = options.source ?? (await ask("source", "Which git repository is the site built from? Auditors rebuild from it; leave empty for closed source", (await gitRemote(options.dir)) ?? ""));
    const artifact = options.artifact ?? (await ask("artifact", "Where will each release archive live? A URL template with ${version}; leave empty for none", ""));
    const version = options.version ?? (await ask("app-version", "Which version of your site are you publishing? A git tag when source is set", (await gitTagAtHead(options.dir)) ?? "1.0.0"));
    const directory = options.directory ?? (await ask("directory", "Which directory does your build write the site into?", "dist"));
    const type = (options.type ??
      (await choose("type", "Which signing mechanism do you want to use?", [["sigsum", "you hold the signing keys"], ["sigstore", "sign from CI with an OIDC identity"]], "sigsum"))) as "sigsum" | "sigstore";
    let csp = options.csp;
    if (!csp) {
      const presets = Object.entries(CSP_PRESETS).map(([key, p]) => [key, p.title] as [string, string]);
      const preset = await choose("csp", "What is the Content Security Policy of your site? Choose a preset or type your own", [...presets, ["custom", "type your own policy"]], "static");
      csp = preset === "custom" ? await ask("csp", "Type the policy. `webcat csp hint` explains what WEBCAT rejects in one", undefined, compatibleCsp) : CSP_PRESETS[preset].csp;
    }
    const maxAge = options.maxAge ?? (await ask("max-age", "How many seconds should a signed manifest stay valid? Visitors need a fresh one after that", String(DEFAULT_MAX_AGE), wholeNumber("max-age")));
    const rest: InitOptions = { ...options };
    if (type === "sigsum") {
      rest.policy ??= await choose("policy", "Which Sigsum policy should accept your signatures?", [...Object.entries(SIGSUM_POLICIES).map(([k, p]) => [k, p.title] as [string, string]), ["file", "the path to your own policy file"]], "test");
      if (rest.policy === "file") {
        rest.policy = await ask("policy", "Where is your policy file?", undefined, readableFile("policy"));
      }
      if (!rest.signer && rest.keys === undefined) {
        rest.keys = await ask("keys", "How many signing keys should be generated now with sigsum-key? 0 to use public keys you already have", "2", wholeNumber("keys"));
      }
      if (!rest.signer && Number(rest.keys) === 0) {
        rest.signer = (await ask("signer", "Which public keys will sign your manifests? Hex, base64 or OpenSSH .pub paths, comma separated. Hardware keys sign through ssh-agent", undefined, signerKeys))
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }
      rest.threshold ??= await ask("threshold", "How many of those signatures must a manifest carry?", "1", atMost("threshold", rest.signer?.length || Number(rest.keys)));
    } else {
      // The release workflow on any tag: a ^ prefix claim, so a release does not need a new enrollment.
      const workflowIdentity = forgeOf(source) === "github" ? `^${source.replace(/\.git$/, "")}/.github/workflows/webcat-release.yml@refs/tags/` : undefined;
      rest.identity ??= tagPrefixIdentity(
        await ask("identity", "Which identity signs your releases? An email, or a workflow URL; a ^ prefix matches every ref it starts with (release tags)", workflowIdentity),
      );
      rest.issuer ??= await ask("issuer", "Which OIDC issuer vouches for that identity?", "https://token.actions.githubusercontent.com", httpsUrl("issuer"));
    }
    return { ...rest, origin, version, type, csp, maxAge, source, artifact, directory };
  } finally {
    rl?.close();
  }
}

export async function runInit(options: InitOptions): Promise<void> {
  const a = await answers(options);
  // Flags skip the prompts, so their values are checked here.
  validateAll([() => httpsOrigin(a.origin), () => compatibleCsp(a.csp), () => wholeNumber("max-age")(String(a.maxAge))]);
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
          trustedRoot: await fetchCommunityTrustedRoot().then((root) => (a.keepRekorV1 ? root : withoutRekorV1(root))),
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
    fallbacks: ["/index.html"],
    wasm: [],
    extra_csp: {},
  };
  if (!a.source && !a.artifact) log("Warning: without source or artifact, auditors cannot reproduce or fetch this site's releases");
  const files: Array<[string, string]> = [
    ["webcat.config.json", JSON.stringify(config, null, 2) + "\n"],
    ...(a.type === "sigsum" ? [["trust_policy", policyText] as [string, string]] : []),
  ];
  for (const [name, contents] of files) {
    await writeFile(`${a.dir}/${name}`, contents);
    log(`wrote ${name}`);
  }
  for (const file of await publishEnrollment(`${a.dir}/${WELL_KNOWN_DIR}`, enrollment)) {
    log(`wrote ${path.relative(a.dir, file)}`);
  }
  const host = new URL(a.origin).host;
  // The CI jobs, for the site's own repository: the signing identity is then the site's workflow, nothing of ours.
  const forge = forgeOf(a.source);
  const workflows: string[] = [];
  if (forge && a.workflows !== false) {
    const jobs: Array<[string, string | null]> = [
      ["webcat-release.yml", releaseWorkflow({ forge, type: a.type, host, directory: a.directory ?? "dist", tokenKey: Boolean(tokenHex), artifact: Boolean(a.artifact) })],
      ["webcat-verify.yml", verifyWorkflow({ forge, host })],
    ];
    await mkdir(`${a.dir}/${workflowDir(forge)}`, { recursive: true });
    for (const [name, text] of jobs) {
      const file = `${workflowDir(forge)}/${name}`;
      if (text === null) log(`Warning: Forgejo Actions issue no OIDC identity, so no ${file}: sign with --interactive, or release from GitHub Actions`);
      else if (await access(`${a.dir}/${file}`).then(() => true, () => false)) log(`kept ${file} (exists)`);
      else {
        await writeFile(`${a.dir}/${file}`, text);
        workflows.push(file);
        log(`wrote ${file}`);
      }
    }
  }
  const secrets = a.type === "sigsum" ? (tokenHex ? ", and add the keys as the secrets SIGSUM_KEY and SIGSUM_TOKEN_KEY" : ", and add the key as the secret SIGSUM_KEY") : "";
  const ciStep = workflows.length ? `\n     ${workflows.join(" and ")} do this on every tag push and check the live site on a schedule: commit them${secrets}` : "";
  const key = keyPaths[0] ?? (a.signer ?? []).find((s) => s.endsWith(".pub")) ?? "<private key, or .pub for ssh-agent>";
  const token = tokenHex ? ` --token-signing-key keys/token --token-domain ${host}` : "";
  const release =
    a.type === "sigsum"
      ? `webcat release -k ${key}${token}      # repeat -k for each key up to the threshold`
      : "webcat release --type sigstore         # in CI with the identity above, or --interactive";
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
  3. Build the site into ${a.directory}/, tag the release, then publish it in one step:
       ${release}
     (generates, signs, writes bundle.json and manifest.<type>.<hash>.json${a.artifact ? ", the release archive" : ""}; the history is kept in the archive of each release)${ciStep}
  4. Deploy with ${WELL_KNOWN_DIR}/ copied into the web root, then check what visitors and auditors will see:
       webcat site check ${host}
  5. Ask the oracles to record the enrollment:    webcat enrollment submit ${host}
  6. Follow promotion on the chain:               webcat enrollment status ${host}
`);
}
