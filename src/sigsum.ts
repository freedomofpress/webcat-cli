import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parsePolicyText } from "@freedomofpress/sigsum/dist/config.js";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler.js";
import { witnessTimestampsFromCosignedTreeHead } from "@freedomofpress/webcat/webcat/validators";
import type { SigsumEnrollment } from "./enrollment.js";
import { ManifestDocument, canonicalizeManifestBody } from "./manifest.js";
import { causeOf, external, fetchOk, hexToBase64Url, invalid, readText, toBase64Url, validateAll } from "./utils.js";

export interface SigsumSignOptions {
  policyFile: string;
  key: string;
  enrollment?: SigsumEnrollment; // when given, refuse to submit anything the enrollment would not accept
  tokenSigningKey?: string;
  tokenDomain?: string;
}

function runSigsum(binary: string, args: string[], stdio: "pipe" | "inherit"): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { stdio: stdio === "pipe" ? ["ignore", "pipe", "pipe"] : "inherit" });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => (stdout += d.toString()));
    child.stderr?.on("data", (d) => (stderr += d.toString()));
    child.on("error", (err: NodeJS.ErrnoException) => {
      reject(
        external(
          err.code === "ENOENT"
            ? `failed to run ${binary}: not installed (go install sigsum.org/sigsum-go/cmd/${binary}@latest)`
            : `failed to run ${binary}: ${err.message}`,
        ),
      );
    });
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(external(`failed to run ${binary}: ${signal ? `killed by ${signal}` : `exit code ${code}`}${stderr ? `: ${stderr.trim()}` : ""}`));
      }
    });
  });
}

// Text of a policy built into the Sigsum tools (sigsum-policy list), e.g. sigsum-generic-2025-1 for production.
export const builtinPolicyText = (name: string): Promise<string> => runSigsum("sigsum-policy", ["show", name], "pipe").then((t) => t + "\n");

export async function generateSigsumKey(keyPath: string): Promise<void> {
  await mkdir(path.dirname(keyPath), { recursive: true });
  await runSigsum("sigsum-key", ["generate", "-o", keyPath], "pipe");
}

// Generates keys/key1..keyN with sigsum-key and returns their public keys as enrollment signers.
export async function generateSigsumKeys(dir: string, count: number): Promise<{ paths: string[]; signers: string[] }> {
  const paths = Array.from({ length: count }, (_, i) => path.join(dir, "keys", `key${i + 1}`));
  for (const keyPath of paths) {
    await generateSigsumKey(keyPath);
  }
  return { paths, signers: await Promise.all(paths.map(deriveSignerKeyFromPrivateKey)) };
}

// A key file for sigsum-submit: a private key, or a public key whose private part lives in ssh-agent (hardware tokens).
export async function deriveSignerKeyFromPrivateKey(keyPath: string): Promise<string> {
  const pubPath = keyPath.endsWith(".pub") ? keyPath : `${keyPath}.pub`;
  const hex = await runSigsum("sigsum-key", ["to-hex", "-k", pubPath], "pipe");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw external(`failed to run sigsum-key: expected a hex public key for ${pubPath}, got '${hex}'`);
  }
  return hexToBase64Url(hex);
}

const parsePolicy = (policyText: string) =>
  Promise.all([compilePolicy(policyText), parsePolicyText(policyText)]).catch((err) => {
    throw invalid(`policy file must be a valid Sigsum policy: ${causeOf(err)}`);
  });

// Compiles a Sigsum policy into the enrollment payload plus the log key -> URL map.
export async function sigsumEnrollmentFromPolicy(policyText: string): Promise<{ policy: string; logs: Record<string, string> }> {
  const [compiled, parsed] = await parsePolicy(policyText);
  const entries = await Promise.all(
    Array.from(parsed.logs.values()).map(async (entity) => {
      const rawKey = await crypto.subtle.exportKey("raw", entity.publicKey.key);
      return [toBase64Url(new Uint8Array(rawKey)), entity.url ?? ""] as const;
    }),
  );
  entries.sort(([a], [b]) => a.localeCompare(b));
  return { policy: toBase64Url(compiled), logs: Object.fromEntries(entries) };
}

// Runs sigsum-submit on the canonical manifest and attaches the proof to it under the signer's key.
export async function signManifestWithSigsum(document: ManifestDocument, options: SigsumSignOptions): Promise<void> {
  if (Array.isArray(document.signatures)) {
    throw invalid("manifest.signatures already contains Sigstore bundles, sigsum proofs cannot be mixed in");
  }
  const signerKey = await deriveSignerKeyFromPrivateKey(options.key);
  if (document.signatures?.[signerKey]) {
    throw invalid(`manifest.signatures already contains a proof for signer ${signerKey}`);
  }
  if (options.enrollment) {
    const [compiled] = await parsePolicy(await readText(options.policyFile, "policy"));
    validateAll([
      () => {
        if (!options.enrollment!.signers.includes(signerKey)) {
          throw invalid(`--key ${options.key} is signer ${signerKey}, which is not in enrollment.signers`);
        }
      },
      () => {
        if (toBase64Url(compiled) !== options.enrollment!.policy) {
          throw invalid(`--policy-file ${options.policyFile} does not compile to enrollment.policy; browsers verify against the enrollment`);
        }
      },
    ]);
  }
  const tempDir = await mkdtemp(path.join(tmpdir(), "webcat-manifest-"));
  const payloadPath = path.join(tempDir, "manifest.json");
  try {
    await writeFile(payloadPath, canonicalizeManifestBody(document));
    const rateLimit = options.tokenDomain && options.tokenSigningKey ? ["-a", options.tokenSigningKey, "-d", options.tokenDomain] : [];
    await runSigsum("sigsum-submit", ["-p", options.policyFile, "-k", options.key, ...rateLimit, payloadPath], "inherit");
    const proofText = (await readFile(`${payloadPath}.proof`, "utf8").catch((err) => {
      throw external(`failed to read the proof written by sigsum-submit: ${causeOf(err)}`);
    })).trim();
    if (!proofText) {
      throw external("failed to read the proof written by sigsum-submit: file is empty");
    }
    document.signatures = { ...document.signatures, [signerKey]: proofText };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}


// Fetches a cosigned tree head from one of the policy's logs and returns it verbatim once the
// extension's validator accepts it (signed by the log, cosigned by a witness quorum).
export async function fetchTimestampFromPolicy(policyText: string): Promise<string> {
  const [compiled, policy] = await parsePolicy(policyText);
  const logs = Array.from(policy.logs.values()).filter((entity) => entity.url);
  if (logs.length === 0) {
    throw invalid("policy file must list at least one log with a URL to fetch a timestamp from");
  }
  const log = logs[Math.floor(Math.random() * logs.length)];
  const requestUrl = `${log.url!.replace(/\/+$/, "")}/get-tree-head`;
  const text = (await (await fetchOk(requestUrl)).text()).trim();
  await witnessTimestampsFromCosignedTreeHead(compiled, text).catch((err) => {
    throw external(`failed to verify timestamp from ${requestUrl}: ${causeOf(err)}`);
  });
  return text;
}
