// One key per strategy, whatever way it was written. Port of probe/Detour.NetProbe/Tune/StrategyKey.cs;
// shared cases in spec/strategy-cases.json. The collector never trusts a client's key: it normalizes the args
// itself, and only an allowlist of desync options gets into the database (and from there into other people's bypass).

export const ENGINES = ["winws", "byedpi"] as const;
export type Engine = (typeof ENGINES)[number];

export const MAX_TOKENS = 24;
export const MAX_KEY_LENGTH = 600;
const BIN = "%BIN%";

export type NormalizeResult = { key: string; error?: undefined } | { key?: undefined; error: "engine" | "option" | "value" | "empty" | "too_long" };

/** Splits on whitespace; double quotes group and are removed. */
export function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let quoted = false;
  let any = false;
  for (const ch of line) {
    if (ch === '"') {
      quoted = !quoted;
      any = true;
    } else if (/\s/.test(ch) && !quoted) {
      if (any || cur.length > 0) tokens.push(cur);
      cur = "";
      any = false;
    } else {
      cur += ch;
    }
  }
  if (any || cur.length > 0) tokens.push(cur);
  return tokens;
}

export function normalize(engine: string, args: string | string[]): NormalizeResult {
  const tokens = (typeof args === "string" ? tokenize(args) : args).filter((t) => t.length > 0);
  let out: string[] | string;
  if (engine === "winws") out = normalizeWinws(tokens);
  else if (engine === "byedpi") out = normalizeByeDpi(tokens);
  else return { error: "engine" };
  if (typeof out === "string") return { error: out as "option" | "value" };
  if (out.length === 0) return { error: "empty" };
  const key = `${engine}:${out.join(" ")}`;
  return out.length > MAX_TOKENS || key.length > MAX_KEY_LENGTH ? { error: "too_long" } : { key };
}

/** 12 hex chars of SHA-256 of the key. */
export async function strategyId(key: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}

// ---- winws / nfqws ----

const WINWS_CONTEXT = ["--filter-", "--hostlist", "--ipset", "--wf-", "--new", "--skip", "--comment"];
const WINWS_OPTION = /^--(dpi-desync(-[a-z0-9]+)*|ip-id|dup(-[a-z0-9]+)*|orig(-[a-z0-9]+)*)$/;
const WINWS_VALUE = /^[A-Za-z0-9_.,:+\-=!]*$/;
const BIN_FILE = /^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*\.bin$/;

function isFile(v: string): boolean {
  return v.includes(BIN) || v.includes("\\") || v.includes("/") || v.toLowerCase().endsWith(".bin");
}

function normalizeWinws(tokens: string[]): string[] | string {
  const kept: { name: string; token: string; i: number }[] = [];
  for (const token of tokens) {
    const eq = token.indexOf("=");
    const name = (eq < 0 ? token : token.slice(0, eq)).toLowerCase();
    let value = eq < 0 ? null : token.slice(eq + 1);
    if (WINWS_CONTEXT.some((p) => name.startsWith(p))) continue;
    if (!WINWS_OPTION.test(name)) return "option";
    if (value === null) {
      kept.push({ name, token: name, i: kept.length });
      continue;
    }
    value = value.replaceAll("^", "");
    if (isFile(value)) {
      const cut = Math.max(value.lastIndexOf("\\"), value.lastIndexOf("/"), value.lastIndexOf("%"));
      const file = value.slice(cut + 1);
      if (!BIN_FILE.test(file)) return "value";
      value = BIN + file;
    } else if (value.length > 120 || !WINWS_VALUE.test(value)) {
      return "value";
    }
    kept.push({ name, token: `${name}=${value}`, i: kept.length });
  }
  // Ordinal sort by name, stable (repeated options keep their order), same as C#'s OrderBy with StringComparer.Ordinal.
  kept.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.i - b.i));
  return kept.map((k) => k.token);
}

// ---- ByeDPI (ciadpi) ----

const BYE_LONG: Record<string, string> = {
  split: "s", disorder: "d", oob: "o", disoob: "q", fake: "f", ttl: "t", tlsrec: "r", "mod-http": "M", "fake-sni": "n", md5sig: "S",
  ip: "i", port: "p", "conn-ip": "I", "max-conn": "c", pidfile: "w", "buf-size": "b", debug: "x", daemon: "D", "no-udp": "U",
};
const DESYNC_WITH_VALUE = "sdoqftrMn";
const DESYNC_FLAGS = "S";
const CONTEXT_WITH_VALUE = "ipIcwbx";
const CONTEXT_FLAGS = "DU";
const BYE_VALUE = /^[A-Za-z0-9_.,:+\-]+$/;

function normalizeByeDpi(tokens: string[]): string[] | string {
  if (tokens.length > 0) {
    const base = tokens[0]!.replaceAll("\\", "/").split("/").pop()!.replace(/\.[^.]*$/, "");
    if (base.toLowerCase() === "ciadpi") tokens = tokens.slice(1);
  }
  const kept: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!;
    let opt: string | undefined;
    let value: string | null;
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      const name = eq < 0 ? token.slice(2) : token.slice(2, eq);
      opt = Object.hasOwn(BYE_LONG, name) ? BYE_LONG[name] : undefined;
      if (!opt) return "option";
      value = eq < 0 ? null : token.slice(eq + 1);
    } else if (token.length >= 2 && token[0] === "-" && /[A-Za-z]/.test(token[1]!)) {
      opt = token[1]!;
      value = token.length > 2 ? token.slice(2) : null;
    } else {
      return "option";
    }
    const needsValue = DESYNC_WITH_VALUE.includes(opt) || CONTEXT_WITH_VALUE.includes(opt);
    const isFlag = DESYNC_FLAGS.includes(opt) || CONTEXT_FLAGS.includes(opt);
    if (!needsValue && !isFlag) return "option";
    if (needsValue && value === null) {
      if (i + 1 >= tokens.length) return "value";
      value = tokens[++i]!;
    }
    if (isFlag && value !== null) return "value";
    if (CONTEXT_WITH_VALUE.includes(opt) || CONTEXT_FLAGS.includes(opt)) continue;
    if (value !== null && (value.length > 60 || !BYE_VALUE.test(value))) return "value";
    kept.push(`-${opt}${value ?? ""}`);
  }
  return kept;
}
