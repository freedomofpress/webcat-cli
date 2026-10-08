import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { buildLeafBytesFromProof } from "./sigsum.js";
import { causeOf, external, invalid, sha256 } from "./utils.js";

export interface CasWriteResult {
  hash: string;
  filePath: string;
}

type Uploader = { client: S3Client; bucket: string };

// Read only when publishing, so unrelated commands never fail on a half-configured environment.
function uploaderFromEnv(): Uploader | null {
  const { WEBCAT_CAS_S3_ENDPOINT: endpoint, WEBCAT_CAS_S3_BUCKET: bucket, WEBCAT_CAS_S3_TOKEN: token } = process.env;
  if (!endpoint && !bucket && !token) {
    return null;
  }
  if (!endpoint || !bucket || !token) {
    throw invalid("WEBCAT_CAS_S3_ENDPOINT, WEBCAT_CAS_S3_BUCKET and WEBCAT_CAS_S3_TOKEN must all be set to upload to the CAS");
  }
  const client = new S3Client({
    endpoint,
    region: process.env.WEBCAT_CAS_S3_REGION ?? "us-east-1",
    credentials: { accessKeyId: token, secretAccessKey: token },
    forcePathStyle: true,
  });
  return { client, bucket };
}

// Stores `data` under ./cas/<hex sha256> and, when an uploader is given, in S3 too.
export async function writeCasObject(data: Uint8Array | string, uploader: Uploader | null = null): Promise<CasWriteResult> {
  const bytes = Buffer.from(data as any);
  const hash = sha256(bytes).toString("hex");
  const filePath = path.resolve("cas", hash);
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, bytes);
  if (uploader) {
    await uploader.client.send(new PutObjectCommand({ Bucket: uploader.bucket, Key: hash, Body: bytes })).catch((err) => {
      throw external(`failed to upload ${hash} to the CAS bucket: ${causeOf(err)}`);
    });
  }
  return { hash, filePath };
}

// Publishes the objects a monitor needs to walk from a Sigsum leaf back to the manifest:
// the raw leaf, the checksum preimage (sha256 of the manifest), and the canonical manifest.
export async function publishSigsumProofToCas(
  canonicalManifest: string,
  proofText: string,
): Promise<{ leaf: CasWriteResult; checksum: CasWriteResult; manifest: CasWriteResult }> {
  const uploader = uploaderFromEnv();
  const leaf = await writeCasObject(await buildLeafBytesFromProof(canonicalManifest, proofText), uploader);
  const checksum = await writeCasObject(sha256(canonicalManifest), uploader);
  const manifest = await writeCasObject(canonicalManifest, uploader);
  return { leaf, checksum, manifest };
}
