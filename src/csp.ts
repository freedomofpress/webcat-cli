// Explains what WEBCAT would reject in a CSP, grouped by what to do about it, following
// docs.webcat.tech/webapp-developers/CSP.html, then proposes the nearest policy that passes the extension's validator.
import { parseContentSecurityPolicy } from "@freedomofpress/webcat/webcat/parsers";
import { validateCSP } from "@freedomofpress/webcat/webcat/validators";
import { causeOf, fetchOk } from "./utils.js";

export const CSP_DOCS = "https://docs.webcat.tech/webapp-developers/CSP.html";

export interface CspGroup {
  title: string;
  items: string[]; // "directive source", or "directive" when the directive itself is the problem
  advice: string[];
  docs?: string; // which section of the CSP docs to read
}

export interface CspReport {
  compatible: boolean; // the extension's validateCSP on the policy as given
  groups: CspGroup[]; // what must change, empty when compatible
  accepted: string[]; // accepted as is, with the docs' advice
  suggested: string;
}

const HASH = /^'sha(256|384|512)-[A-Za-z0-9+/_-]+={0,2}'$/i;
const SCRIPT_OK = ["'none'", "'self'", "'wasm-unsafe-eval'"];
const STYLE_OK = ["'none'", "'self'", "'unsafe-inline'", "'unsafe-hashes'"];
const RESTRICTED = ["default-src", "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "object-src", "worker-src"];

const GROUPS: Record<string, Omit<CspGroup, "items">> = {
  scriptOrigins: {
    title: "Scripts from other origins",
    advice: [
      "Vendor them into your build and keep script-src 'self'. Scripts from any other origin are not supported, enrolled or not.",
      "Cannot vendor it (captchas, payments, players, embeds)? Load it in a sandboxed iframe from its own origin: frame-src is not restricted. Use sandbox=\"allow-scripts\" without allow-same-origin, exchange data with postMessage and check event.origin.",
    ],
    docs: "script-src and frame-src",
  },
  scriptInline: {
    title: "Inline and dynamic scripts",
    advice: [
      "'unsafe-inline': move inline scripts to files, or allow each one with a 'sha256-…' hash.",
      "Nonces are not accepted: their value cannot be covered by the manifest signature. Use a hash.",
      "'unsafe-eval', 'strict-dynamic', 'unsafe-hashes': not supported for scripts. For WebAssembly use 'wasm-unsafe-eval'.",
      "Inline event handlers (onclick=…): attach listeners from a script file and set script-src-attr 'none'.",
    ],
    docs: "script-src",
  },
  styleOrigins: { title: "Stylesheets from other origins", advice: ["Vendor them into your build and keep style-src 'self'."], docs: "style-src" },
  workerOrigins: { title: "Workers from other origins", advice: ["Serve workers from your origin: worker-src 'self' (or 'none')."], docs: "worker-src" },
  plugins: { title: "Plugins", advice: ["object-src must be 'none'; plugins are not supported."], docs: "object-src" },
  defaultSrc: {
    title: "default-src",
    advice: [
      "Only 'none' or 'self' is accepted. Prefer default-src 'none' and allow-list each directive explicitly; move other sources to the directive that needs them, if WEBCAT allows it there.",
      "'none' only counts on its own: next to other sources browsers ignore it, so default-src 'none' 'self' means 'self', and WEBCAT then requires script-src, style-src, object-src and worker-src.",
    ],
    docs: "default-src",
  },
  missing: {
    title: "Missing directives",
    advice: [
      "With default-src other than 'none', script-src, style-src, object-src 'none' and worker-src are required.",
      "worker-src 'self' (or 'none') is recommended in every case: without it browsers fall back to child-src, which WEBCAT does not restrict.",
    ],
    docs: "default-src and worker-src",
  },
  policies: { title: "Multiple policies", advice: ["A comma means several policies in one header. WEBCAT compares only the first and rejects the header: send exactly one policy."] },
  other: { title: "Other", advice: ["Rejected by the extension's CSP validator."], docs: "the directive named above" },
};

export function hintCsp(csp: string): CspReport {
  const items: Record<string, string[]> = {};
  const add = (group: keyof typeof GROUPS, item: string) => (items[group] ??= []).push(item);
  const accepted: string[] = [];
  if (csp.includes(",")) add("policies", "policy");
  const d = parseContentSecurityPolicy(csp.split(",")[0].trim());
  const out = new Map<string, string[]>();
  const keep = (dir: string, ok: (s: string) => boolean, group: (s: string) => keyof typeof GROUPS): string[] => {
    const kept: string[] = [];
    for (const src of d.get(dir) ?? []) {
      if (ok(src)) kept.push(src);
      else add(group(src), `${dir} ${src}`);
    }
    return kept;
  };

  const def = d.get("default-src");
  if (!def) {
    add("missing", "default-src");
    out.set("default-src", ["'none'"]);
  } else {
    const kept = keep("default-src", (s) => s === "'none'" || s === "'self'", () => "defaultSrc");
    if (def.includes("'none'") && def.length > 1) add("defaultSrc", `default-src ${def.join(" ")}`);
    out.set("default-src", kept.length === 0 || (kept.includes("'none'") && kept.length > 1) ? ["'none'"] : kept);
  }
  // As the extension reads it: 'none' only counts when it is the sole source.
  const strict = def?.length === 1 && def[0] === "'none'";

  for (const dir of ["script-src", "script-src-elem"]) {
    if (d.has(dir)) {
      const kept = keep(dir, (s) => SCRIPT_OK.includes(s.toLowerCase()) || HASH.test(s), (s) => (s.startsWith("'") ? "scriptInline" : "scriptOrigins"));
      out.set(dir, kept.length ? kept : ["'self'"]);
    }
  }
  if (!d.has("script-src") && !strict) {
    add("missing", "script-src");
    out.set("script-src", ["'self'"]);
  }
  if (d.has("script-src-attr")) {
    const kept = keep("script-src-attr", (s) => s === "'none'", () => "scriptInline");
    out.set("script-src-attr", kept.length ? kept : ["'none'"]);
  }

  for (const dir of ["style-src", "style-src-elem", "style-src-attr"]) {
    if (d.has(dir)) {
      const kept = keep(dir, (s) => STYLE_OK.includes(s.toLowerCase()) || HASH.test(s), () => "styleOrigins");
      out.set(dir, kept.length ? kept : ["'self'"]);
      for (const s of kept.filter((s) => s === "'unsafe-inline'" || s === "'unsafe-hashes'")) {
        accepted.push(
          `${dir} ${s}: accepted today but discouraged, and may be dropped in a future WEBCAT version. Prefer stylesheets served from your origin, or 'sha256-…' hashes for inline styles; keep it only while your framework injects inline styles you cannot avoid.`,
        );
      }
    }
  }
  if (!d.has("style-src") && !strict) {
    add("missing", "style-src");
    out.set("style-src", ["'self'"]);
  }

  if (d.has("object-src")) keep("object-src", (s) => s === "'none'", () => "plugins");
  else if (!strict) add("missing", "object-src");
  out.set("object-src", ["'none'"]);
  if (d.has("worker-src")) {
    const kept = keep("worker-src", (s) => s === "'none'" || s === "'self'", () => "workerOrigins");
    out.set("worker-src", kept.length ? kept : ["'self'"]);
  } else if (!strict || d.has("child-src")) {
    add("missing", "worker-src");
    out.set("worker-src", ["'self'"]);
  }

  const unrestricted: string[] = [];
  for (const [dir, sources] of d) {
    if (!RESTRICTED.includes(dir)) {
      out.set(dir, sources);
      if (sources.some((s) => !s.startsWith("'"))) unrestricted.push(dir);
    }
  }
  if (unrestricted.length) {
    accepted.push(
      `${unrestricted.join(", ")}: not restricted by WEBCAT, external sources here do not fail verification. The recommended practice is still to vendor everything you can and keep every directive on 'self': whatever loads from elsewhere is outside what WEBCAT verifies.`,
    );
  }

  const suggested = [...out].map(([dir, sources]) => `${dir} ${sources.join(" ")}`).join("; ");
  try {
    validateCSP(suggested);
  } catch (err) {
    accepted.push(`the suggested policy still fails the validator (${causeOf(err)}); please report this.`);
  }
  // Fixed order (scripts first), and inline-script advice only for the sources that are actually present.
  const inlineAdvice = (list: string[]): string[] =>
    GROUPS.scriptInline.advice.filter((line, i) =>
      [
        list.some((s) => s.includes("'unsafe-inline'")),
        list.some((s) => s.includes("'nonce-")),
        list.some((s) => /'unsafe-eval'|'strict-dynamic'|'unsafe-hashes'/.test(s)),
        list.some((s) => s.startsWith("script-src-attr")),
      ][i],
    );
  // The verdict is the extension's own validator on the policy as given; the groups only explain it.
  let compatible = true;
  try {
    validateCSP(csp);
  } catch (err) {
    compatible = false;
    if (Object.keys(items).length === 0) add("other", causeOf(err));
  }
  const groups = compatible ? [] : Object.keys(GROUPS)
    .filter((key) => items[key])
    .map((key) => ({ ...GROUPS[key], items: items[key], advice: key === "scriptInline" ? inlineAdvice(items[key]) : GROUPS[key].advice }));
  return { compatible, groups, accepted, suggested };
}

export function formatCspReport(report: CspReport): string {
  const lines: string[] = [];
  if (report.compatible) {
    lines.push("OK: WEBCAT-compatible as is");
  } else {
    const total = report.groups.reduce((n, g) => n + g.items.length, 0);
    lines.push(`Must change (${total})`);
    for (const g of report.groups) {
      lines.push("", `  ${g.title} (${g.items.length})`);
      g.items.forEach((item) => lines.push(`    ${item}`));
      g.advice.forEach((a) => lines.push(`    > ${a}`));
      if (g.docs) lines.push(`    > See ${g.docs} at ${CSP_DOCS}`);
    }
  }
  if (report.accepted.length) {
    lines.push("", "Accepted, with advice");
    report.accepted.forEach((a) => lines.push(`  ${a}`));
  }
  if (report.groups.length) {
    lines.push("", "Nearest compatible policy (dropped sources must be vendored or framed)", `  ${report.suggested}`);
  }
  return lines.join("\n") + "\n";
}

// The policy a site sends in its header: the only place the extension reads one.
export const fetchSiteCsp = async (url: string): Promise<string | null> =>
  (await fetchOk(url, { redirect: "follow" })).headers.get("content-security-policy");
