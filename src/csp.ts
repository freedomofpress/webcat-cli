// Explains what WEBCAT would reject in a CSP, grouped by what to do about it, following
// docs.webcat.tech/webapp-developers/CSP.html, then proposes the nearest policy that passes the extension's validator.
import { parseContentSecurityPolicy } from "@freedomofpress/webcat/webcat/parsers";
import { CspDirective, type CspError, cspErrors, RESTRICTED_DIRECTIVES } from "@freedomofpress/webcat/webcat/validators";
import { causeOf, external } from "./utils.js";

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
};

// Where a rejection from the extension's validator goes: by directive, and for scripts by keyword or origin.
function groupOf(e: CspError): keyof typeof GROUPS {
  if (!e.directive) return "policies";
  if (!e.source) return "missing";
  switch (e.directive) {
    case CspDirective.DefaultSrc:
      return "defaultSrc";
    case CspDirective.ObjectSrc:
      return "plugins";
    case CspDirective.WorkerSrc:
      return "workerOrigins";
    case CspDirective.ScriptSrcAttr:
      return "scriptInline";
    case CspDirective.ScriptSrc:
    case CspDirective.ScriptSrcElem:
      return e.source.startsWith("'") ? "scriptInline" : "scriptOrigins";
    default:
      return "styleOrigins";
  }
}

// What to propose for a directive the validator left empty or missing; 'self' otherwise.
const FILL: Partial<Record<string, string>> = { "default-src": "'none'", "object-src": "'none'", "script-src-attr": "'none'" };

export function hintCsp(csp: string): CspReport {
  const items: Partial<Record<keyof typeof GROUPS, string[]>> = {};
  const add = (group: keyof typeof GROUPS, item: string) => (items[group] ??= []).push(item);
  const accepted: string[] = [];
  const d = parseContentSecurityPolicy(csp.split(",")[0].trim());

  // Nearest policy: the given one minus every rejected source, plus every directive the validator asked for.
  const out = new Map(d);
  const errors = cspErrors(csp);
  for (const e of errors) {
    add(groupOf(e), e.directive ? (e.source ? `${e.directive} ${e.source}` : e.directive) : "policy");
    if (e.directive) out.set(e.directive, (out.get(e.directive) ?? []).filter((s) => s !== e.source));
  }
  // Advice beyond the validator: default-src is best explicit, and 'none' next to other sources is ignored by browsers.
  const def = d.get("default-src");
  if (!def) {
    add("missing", "default-src");
    out.set("default-src", []);
  } else if (def.includes("'none'") && def.length > 1) {
    add("defaultSrc", `default-src ${def.join(" ")}`);
    out.set("default-src", ["'none'"]);
  }
  out.set("object-src", ["'none'"]);
  for (const [dir, sources] of out) if (!sources.length) out.set(dir, [FILL[dir] ?? "'self'"]);

  for (const dir of ["style-src", "style-src-elem", "style-src-attr"]) {
    for (const s of (out.get(dir) ?? []).filter((s) => s === "'unsafe-inline'" || s === "'unsafe-hashes'")) {
      accepted.push(
        `${dir} ${s}: accepted today but discouraged, and may be dropped in a future WEBCAT version. Prefer stylesheets served from your origin, or 'sha256-…' hashes for inline styles; keep it only while your framework injects inline styles you cannot avoid.`,
      );
    }
  }
  const unrestricted = [...d].filter(([dir, sources]) => !RESTRICTED_DIRECTIVES.includes(dir as CspDirective) && sources.some((s) => !s.startsWith("'"))).map(([dir]) => dir);
  if (unrestricted.length) {
    accepted.push(
      `${unrestricted.join(", ")}: not restricted by WEBCAT, external sources here do not fail verification. The recommended practice is still to vendor everything you can and keep every directive on 'self': whatever loads from elsewhere is outside what WEBCAT verifies.`,
    );
  }

  // Directives in the documented order, unrestricted ones last.
  const order = (dir: string) => (RESTRICTED_DIRECTIVES.includes(dir as CspDirective) ? RESTRICTED_DIRECTIVES.indexOf(dir as CspDirective) : RESTRICTED_DIRECTIVES.length);
  items.missing?.sort((a, b) => order(a) - order(b));
  const suggested = [...out].sort(([a], [b]) => order(a) - order(b)).map(([dir, sources]) => `${dir} ${sources.join(" ")}`).join("; ");
  const [suggestedError] = cspErrors(suggested);
  if (suggestedError) accepted.push(`the suggested policy still fails the validator (${suggestedError.message}); please report this.`);
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
  const compatible = errors.length === 0;
  const groups = compatible ? [] : (Object.keys(GROUPS) as (keyof typeof GROUPS)[])
    .filter((key) => items[key])
    .map((key) => ({ ...GROUPS[key], items: items[key]!, advice: key === "scriptInline" ? inlineAdvice(items[key]!) : GROUPS[key].advice }));
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

export interface CspHop {
  url: string;
  csp: string | null;
  location?: string; // the redirect target, absolute; the extension cancels when it is cross-origin
}

// The responses the extension validates for a page: each one needs a policy, redirects included, and a
// redirect is followed only within the origin. The header is the only place the extension reads a policy from.
export async function fetchSiteCsp(url: string): Promise<CspHop[]> {
  const hops: CspHop[] = [];
  while (hops.length < 10) {
    const response = await fetch(url, { redirect: "manual" }).catch((err) => {
      throw external(`failed to fetch ${url}: ${causeOf(err)}`);
    });
    const location = response.status >= 300 && response.status < 400 ? response.headers.get("location") : null;
    if (!response.ok && !location) {
      throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
    }
    const hop: CspHop = { url, csp: response.headers.get("content-security-policy") };
    hops.push(hop);
    if (!location) return hops;
    hop.location = new URL(location, url).href;
    if (new URL(hop.location).origin !== new URL(url).origin) return hops;
    url = hop.location;
  }
  throw external(`${hops[0].url}: too many redirects`);
}
