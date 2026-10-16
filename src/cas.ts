import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
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

// Publishes what an auditor needs to walk from a Sigsum log entry back to the manifest. The leaf itself is in the
// log; its checksum is sha256(message) and names the message object, whose hex names the canonical manifest.
export async function publishManifestToCas(canonicalManifest: string): Promise<{ checksum: CasWriteResult; manifest: CasWriteResult }> {
  const uploader = uploaderFromEnv();
  const checksum = await writeCasObject(sha256(canonicalManifest), uploader);
  const manifest = await writeCasObject(canonicalManifest, uploader);
  return { checksum, manifest };
}
