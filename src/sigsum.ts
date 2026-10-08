import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parsePolicyText } from "@freedomofpress/sigsum/dist/config.js";
import { hashKey, verifyCosignedTreeHead, verifySignedTreeHead } from "@freedomofpress/sigsum/dist/crypto.js";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler.js";
import { SigsumProof, parseCosignedTreeHead } from "@freedomofpress/sigsum/dist/proof.js";
import { Base64KeyHash, Hash, Leaf, RawPublicKey } from "@freedomofpress/sigsum/dist/types.js";
import { verifyHashWithCompiledPolicy } from "@freedomofpress/sigsum/dist/verify.js";
import type { SigsumEnrollmentInput } from "./enrollment.js";
import { ManifestDocument, canonicalizeManifestBody, manifestHash } from "./manifest.js";
import { causeOf, decodeKeyMaterial, decodePolicyBytes, external, hexToBase64Url, invalid, sha256, toBase64Url } from "./utils.js";

export interface SigsumSignOptions {
  policyFile: string;
  key: string;
  tokenSigningKey?: string;
  tokenDomain?: string;
}

export interface SignerVerification {
  signer: string;
  ok: boolean;
  message?: string;
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

export async function deriveSignerKeyFromPrivateKey(privKeyPath: string): Promise<string> {
  const pubPath = `${privKeyPath}.pub`;
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

// Runs sigsum-submit on the canonical manifest, attaches the proof under the signer's key, and returns it.
export async function signManifestWithSigsum(document: ManifestDocument, options: SigsumSignOptions): Promise<string> {
  if (Array.isArray(document.signatures)) {
    throw invalid("manifest.signatures already contains Sigstore bundles, sigsum proofs cannot be mixed in");
  }
  const signerKey = await deriveSignerKeyFromPrivateKey(options.key);
  if (document.signatures?.[signerKey]) {
    throw invalid(`manifest.signatures already contains a proof for signer ${signerKey}`);
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
    return proofText;
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function verifySigsumManifest(
  enrollment: SigsumEnrollmentInput,
  document: ManifestDocument,
): Promise<SignerVerification[]> {
  const hash = new Uint8Array(manifestHash(document));
  const compiledPolicy = decodePolicyBytes(enrollment.policy, "enrollment.policy");
  if (Array.isArray(document.signatures)) {
    throw invalid("manifest.signatures contains Sigstore bundles but enrollment.type is sigsum");
  }
  const proofs = document.signatures ?? {};
  return Promise.all(
    enrollment.signers.map(async (signer): Promise<SignerVerification> => {
      const proofText = proofs[signer];
      if (!proofText) {
        return { signer, ok: false, message: "no proof in manifest.signatures" };
      }
      try {
        const key = new RawPublicKey(new Uint8Array(decodeKeyMaterial(signer, "enrollment signer")));
        const ok = await verifyHashWithCompiledPolicy(hash, key, compiledPolicy, proofText);
        return ok ? { signer, ok } : { signer, ok, message: "invalid proof" };
      } catch (err) {
        return { signer, ok: false, message: causeOf(err) };
      }
    }),
  );
}

// Rebuilds the raw Sigsum leaf (checksum = sha256(sha256(manifest))) so monitors can match log entries.
export async function buildLeafBytesFromProof(canonicalManifest: string, proofText: string): Promise<Uint8Array> {
  const proof = await SigsumProof.fromAscii(proofText);
  const checksum = new Hash(sha256(sha256(canonicalManifest)));
  return new Leaf(checksum, proof.leaf.Signature, proof.leaf.KeyHash).toBytes();
}

// Fetches a cosigned tree head from one of the policy's logs and returns it verbatim once it
// is signed by the log and cosigned by a witness quorum.
export async function fetchTimestampFromPolicy(policyText: string): Promise<string> {
  const [, policy] = await parsePolicy(policyText);
  const logs = Array.from(policy.logs.values()).filter((entity) => entity.url);
  if (logs.length === 0) {
    throw invalid("policy file must list at least one log with a URL to fetch a timestamp from");
  }
  const log = logs[Math.floor(Math.random() * logs.length)];
  const requestUrl = `${log.url!.replace(/\/+$/, "")}/get-tree-head`;
  const response = await fetch(requestUrl).catch((err) => {
    throw external(`failed to fetch timestamp from ${requestUrl}: ${causeOf(err)}`);
  });
  if (!response.ok) {
    throw external(`failed to fetch timestamp from ${requestUrl}: HTTP ${response.status} ${response.statusText}`);
  }
  const text = (await response.text()).trim();
  const treeHead = parseCosignedTreeHead(text.split(/\r?\n/));
  const logKeyHash = await hashKey(log.publicKey);
  if (!(await verifySignedTreeHead(treeHead.SignedTreeHead, log.publicKey, logKeyHash))) {
    throw external(`failed to verify timestamp from ${requestUrl}: tree head signature is invalid`);
  }
  const present = new Set<Base64KeyHash>();
  for (const [keyHash, witness] of policy.witnesses) {
    const cosig = Base64KeyHash.lookup(treeHead.Cosignatures, keyHash);
    if (cosig && (await verifyCosignedTreeHead(treeHead.SignedTreeHead.TreeHead, witness.publicKey, logKeyHash, cosig))) {
      present.add(keyHash);
      if (policy.quorum.isQuorum(present)) {
        return text;
      }
    }
  }
  throw external(`failed to verify timestamp from ${requestUrl}: witness quorum not met`);
}
