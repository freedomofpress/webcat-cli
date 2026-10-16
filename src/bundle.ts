import { type Enrollment, parseEnrollmentObject } from "./enrollment.js";
import { ManifestDocument, parseManifestDocumentObject } from "./manifest.js";
import { ensureObject, invalid, readJson, validateAll } from "./utils.js";

export interface BundleDocument {
  enrollment: Enrollment;
  manifest: ManifestDocument;
}

export async function loadBundleDocument(bundlePath: string): Promise<BundleDocument> {
  const parsed = ensureObject(await readJson(bundlePath, "bundle"), "bundle");
  validateAll(
    ["enrollment", "manifest", "signatures"].map((key) => () => {
      if (!parsed[key]) {
        throw invalid(`bundle.${key} is required`);
      }
    }),
  );
  return {
    enrollment: parseEnrollmentObject(parsed.enrollment),
    manifest: parseManifestDocumentObject({ manifest: parsed.manifest, signatures: parsed.signatures }),
  };
}
