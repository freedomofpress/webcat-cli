import { spawn } from "node:child_process";
import { Base64KeyHash, Hash, Signature } from "@freedomofpress/sigsum/dist/types.js";
import { parsePolicyText } from "@freedomofpress/sigsum/dist/config.js";
import {
  hashKey,
  verifyCosignedTreeHead,
  verifySignedTreeHead,
} from "@freedomofpress/sigsum/dist/crypto.js";
import { hexToBase64, hexToUint8Array } from "@freedomofpress/sigsum/dist/encoding.js";
import { hexToBase64Url } from "./utils.js";

function formatSigsumBinaryError(binary: string, err: NodeJS.ErrnoException): string {
  if (err.code === "ENOENT") {
    return `${binary} is not installed; install it via Go: go install sigsum.org/sigsum-go/cmd/${binary}@latest`;
  }
  return `failed to launch ${binary}: ${err.message}`;
}

function runSigsumKeyToHex(pubKeyPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("sigsum-key", ["to-hex", "-k", pubKeyPath], { stdio: ["ignore", "pipe", "pipe"] });

    let output = "";
    let errout = "";

    child.stdout.on("data", (d) => output += d.toString());
    child.stderr.on("data", (d) => errout += d.toString());

    child.on("error", (err: NodeJS.ErrnoException) => {
      reject(new Error(formatSigsumBinaryError("sigsum-key", err)));
    });

    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve(output.trim());
      } else if (signal) {
        reject(new Error(`sigsum-key terminated via signal ${signal}`));
      } else {
        reject(new Error(`sigsum-key exited with code ${code}: ${errout.trim()}`));
      }
    });
  });
}

export async function deriveSignerKeyFromPrivateKey(privKeyPath: string): Promise<string> {
  const pubPath = `${privKeyPath}.pub`;

  const hex = await runSigsumKeyToHex(pubPath);

  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`sigsum-key returned invalid hex for ${pubPath}: ${hex}`);
  }

  return hexToBase64Url(hex);
}

export async function runSigsumSubmit(
  policyPath: string,
  keyPath: string,
  payloadPath: string,
  tokenSigningKey?: string,
  tokenDomain?: string,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("sigsum-submit", [
      "-p", policyPath, "-k", keyPath,
      ...(tokenDomain && tokenSigningKey ? [
        "-a", tokenSigningKey,
        "-d", tokenDomain,
      ] : []),
      payloadPath,
    ], {
      stdio: "inherit",
    });
    child.on("error", (err: NodeJS.ErrnoException) => {
      reject(new Error(formatSigsumBinaryError("sigsum-submit", err)));
    });
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      if (signal) {
        reject(new Error(`sigsum-submit terminated via signal ${signal}`));
      } else {
        reject(new Error(`sigsum-submit exited with code ${code ?? 1}`));
      }
    });
  });
}

function parseCosignedTreeHead(text: string) {
  const signedTreeHead: any = {};
  const treeHead: any = {};
  const cosignatures = new Map<Base64KeyHash, { Timestamp: number; Signature: Signature }>();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }
    if (line.startsWith("cosignature=")) {
      const [, rest] = line.split("=", 2);
      const parts = rest.trim().split(/\s+/);
      if (parts.length !== 3) {
        throw new Error("invalid cosignature format in timestamp");
      }
      const [keyHashHex, timestampStr, signatureHex] = parts;
      const timestamp = Number(timestampStr);
      if (!Number.isFinite(timestamp) || timestamp <= 0) {
        throw new Error("invalid cosignature timestamp");
      }
      const signature = new Signature(hexToUint8Array(signatureHex));
      cosignatures.set(new Base64KeyHash(hexToBase64(keyHashHex)), {
        Timestamp: timestamp,
        Signature: signature,
      });
      continue;
    }
    const [key, value] = line.split("=");
    if (!key || value === undefined) {
      continue;
    }
    if (key === "size" || key === "tree_size") {
      const size = Number(value);
      if (!Number.isFinite(size) || size <= 0) {
        throw new Error("invalid tree size in timestamp");
      }
      treeHead.Size = size;
      continue;
    }
    if (key === "root_hash") {
      treeHead.RootHash = new Hash(hexToUint8Array(value));
      continue;
    }
    if (key === "signature") {
      signedTreeHead.Signature = new Signature(hexToUint8Array(value));
      continue;
    }
  }
  if (!treeHead.Size || !treeHead.RootHash) {
    throw new Error("timestamp missing tree head fields");
  }
  if (!signedTreeHead.Signature) {
    throw new Error("timestamp missing log signature");
  }
  signedTreeHead.TreeHead = treeHead;
  return {
    SignedTreeHead: signedTreeHead,
    Cosignatures: cosignatures,
  };
}

export async function fetchTimestampFromPolicy(policyText: string): Promise<string> {
  const policy = await parsePolicyText(policyText);
  const availableLogs = Array.from(policy.logs.entries()).filter(([, entity]) => typeof entity.url === "string" && entity.url.length > 0);
  if (availableLogs.length === 0) {
    throw new Error("policy does not list any logs with URLs for timestamp retrieval");
  }
  const selected = availableLogs[Math.floor(Math.random() * availableLogs.length)];
  const [, logEntity] = selected;
  const baseUrl = (logEntity.url as string).replace(/\/+$/, "");
  const requestUrl = `${baseUrl}/get-tree-head`;
  let response: Response;
  try {
    response = await fetch(requestUrl);
  } catch (err: any) {
    throw new Error(`failed to fetch timestamp from ${requestUrl}: ${err.message}`);
  }
  if (!response.ok) {
    throw new Error(`timestamp request failed (${response.status} ${response.statusText})`);
  }
  const body = await response.text();
  const trimmed = body.trim();
  const treeHead = parseCosignedTreeHead(trimmed);
  const logKeyHash = await hashKey(logEntity.publicKey);
  if (!(await verifySignedTreeHead(treeHead.SignedTreeHead, logEntity.publicKey, logKeyHash))) {
    throw new Error("timestamp tree head signature is invalid");
  }
  const present = new Set<Base64KeyHash>();
  for (const [keyHash, entity] of policy.witnesses) {
    const cosig = Base64KeyHash.lookup(treeHead.Cosignatures, keyHash);
    if (!cosig) {
      continue;
    }
    if (await verifyCosignedTreeHead(treeHead.SignedTreeHead.TreeHead, entity.publicKey, logKeyHash, cosig)) {
      present.add(keyHash);
      if (policy.quorum.isQuorum(present)) {
        return trimmed;
      }
    }
  }
  throw new Error("timestamp does not satisfy witness quorum");
}
