// VPN transports by ISP: clients (Detour, opt-in) report how their VPN connection fared per transport, the map
// shows which transports work on which ISP, and clients use it to pick the next transport when one freezes.
// A report names only the transport kind from a fixed list: never a server address, name or provider.
import type { Origin } from "./ingest";
import { dailySalt, pseudonym, utcDay, utcHour, addDays } from "./privacy";
import { QueryError } from "./api";

/** The transport kinds; shared with probe/Detour.NetProbe/Tune/TransportReport.cs (spec/transports.json). */
export const TRANSPORTS = [
  "vless-reality",
  "vless-reality-xhttp",
  "vless-tls",
  "vless-xhttp",
  "vless-ws",
  "vless-grpc",
  "vmess",
  "trojan",
  "shadowsocks",
  "hysteria2",
  "tuic",
  "wireguard",
  "amneziawg",
  "warp",
  "other",
] as const;
export type Transport = (typeof TRANSPORTS)[number];

export const MAX_TRANSPORT_RESULTS = TRANSPORTS.length;
const MAX_CHECKS = 200;
const CLIENT_RE = /^detour\/\d{1,4}(\.\d{1,6}){0,3}$/;

class TransportError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 422 = 400,
  ) {
    super(message);
  }
}

export interface TransportResult {
  transport: Transport;
  ok: number;
  frozen: number;
  fail: number;
}

export interface TransportReport {
  v: 1;
  client: string;
  net: "home" | "mobile";
  results: TransportResult[];
}

const isCount = (x: unknown): x is number => Number.isInteger(x) && (x as number) >= 0 && (x as number) <= MAX_CHECKS;

/** Strict: unknown transports, numbers out of range, a DPI bypass on the VPN path are refused. */
export function parseTransportReport(body: unknown): TransportReport {
  if (typeof body !== "object" || body === null) throw new TransportError("not an object");
  const b = body as Record<string, unknown>;
  if (b.v !== 1) throw new TransportError("unsupported version");
  if (typeof b.client !== "string" || !CLIENT_RE.test(b.client)) throw new TransportError("bad client");
  if (b.net !== "home" && b.net !== "mobile") throw new TransportError("bad net");
  const env = b.env as Record<string, unknown> | undefined;
  if (typeof env !== "object" || env === null || typeof env.dpi_bypass !== "boolean") throw new TransportError("bad env");
  // zapret tricks on the VPN server's packets change the result: that measures the trick, not the ISP.
  if (env.dpi_bypass) throw new TransportError("untrusted: a DPI bypass shaped the VPN traffic", 422);
  if (!Array.isArray(b.results) || b.results.length === 0 || b.results.length > MAX_TRANSPORT_RESULTS) throw new TransportError("bad results");

  const seen = new Set<string>();
  const results: TransportResult[] = [];
  for (const raw of b.results) {
    const r = raw as Record<string, unknown>;
    if (typeof r !== "object" || r === null || typeof r.transport !== "string" || !(TRANSPORTS as readonly string[]).includes(r.transport)) {
      throw new TransportError("unknown transport");
    }
    if (!isCount(r.ok) || !isCount(r.frozen) || !isCount(r.fail) || r.ok + r.frozen + r.fail === 0) throw new TransportError("bad counts");
    if (seen.has(r.transport)) throw new TransportError("duplicate transport");
    seen.add(r.transport);
    results.push({ transport: r.transport as Transport, ok: r.ok, frozen: r.frozen, fail: r.fail });
  }
  return { v: 1, client: b.client, net: b.net, results };
}

export type TransportIngestResult =
  | { status: 202; body: { accepted: true; stored: number } }
  | { status: 400 | 422 | 429; body: { accepted: false; error: string } };

export async function ingestTransports(env: Env, body: unknown, origin: Origin, now = new Date()): Promise<TransportIngestResult> {
  let report;
  try {
    report = parseTransportReport(body);
  } catch (e) {
    if (e instanceof TransportError) return { status: e.status, body: { accepted: false, error: e.message } };
    throw e;
  }
  const day = utcDay(now);
  const hour = utcHour(now);
  const pseudo = await pseudonym(await dailySalt(env.DB, day), origin.ip);
  const limit = Number(env.RATE_LIMIT_PER_HOUR) || 6;
  const seen = await env.DB.prepare("SELECT COUNT(*) AS n FROM transport_reports WHERE pseudo = ?1 AND received_hour = ?2")
    .bind(pseudo, hour)
    .first<{ n: number }>();
  if ((seen?.n ?? 0) >= limit) return { status: 429, body: { accepted: false, error: "rate limited" } };

  await env.DB.prepare(
    `INSERT INTO transport_reports (received_hour, day, pseudo, asn, as_org, country, region, net, client, results)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
  )
    .bind(hour, day, pseudo, origin.asn, origin.asOrg.slice(0, 200), origin.country, origin.region, report.net, report.client,
      JSON.stringify(report.results))
    .run();
  return { status: 202, body: { accepted: true, stored: report.results.length } };
}

/** The cron's part for transports; runs in the same batch as the map's aggregates. */
export function transportMaintenance(db: D1Database, today: string, yesterday: string, rawRetentionDays: number): D1PreparedStatement[] {
  const v = (f: string) => `json_extract(j.value, '$.${f}')`;
  return [
    db.prepare("DELETE FROM transport_daily WHERE day IN (?1, ?2)").bind(today, yesterday),
    db.prepare(
      `INSERT INTO transport_daily (day, transport, asn, as_org, country, net, reporters, ok, frozen, fail, checks, ok_checks, frozen_checks)
       SELECT r.day, ${v("transport")}, r.asn, MAX(r.as_org), r.country, r.net,
              COUNT(DISTINCT r.pseudo),
              COUNT(DISTINCT CASE WHEN ${v("ok")} > 0 THEN r.pseudo END),
              COUNT(DISTINCT CASE WHEN ${v("frozen")} > 0 THEN r.pseudo END),
              COUNT(DISTINCT CASE WHEN ${v("fail")} > 0 THEN r.pseudo END),
              SUM(${v("ok")} + ${v("frozen")} + ${v("fail")}),
              SUM(${v("ok")}),
              SUM(${v("frozen")})
       FROM transport_reports r, json_each(r.results) j
       WHERE r.day IN (?1, ?2) AND r.pseudo IS NOT NULL
       GROUP BY r.day, ${v("transport")}, r.asn, r.country, r.net`,
    ).bind(today, yesterday),
    db.prepare("UPDATE transport_reports SET pseudo = NULL WHERE day < ?1 AND pseudo IS NOT NULL").bind(yesterday),
    db.prepare("DELETE FROM transport_reports WHERE day < ?1").bind(addDays(today, -rawRetentionDays)),
  ];
}

export interface TransportRow {
  transport: string;
  reporters: number;
  /** Share of checks that passed cleanly / froze. */
  ok: number;
  frozen: number;
  checks: number;
}

interface Row {
  transport: string;
  reporters: number;
  checks: number;
  ok_checks: number;
  frozen_checks: number;
}

const round = (x: number) => Math.round(x * 1000) / 1000;
const toRow = (r: Row): TransportRow => ({
  transport: r.transport,
  reporters: r.reporters,
  checks: r.checks,
  ok: r.checks > 0 ? round(r.ok_checks / r.checks) : 0,
  frozen: r.checks > 0 ? round(r.frozen_checks / r.checks) : 0,
});

const SUMS = "SUM(reporters) AS reporters, SUM(checks) AS checks, SUM(ok_checks) AS ok_checks, SUM(frozen_checks) AS frozen_checks";

function period(url: URL, now: Date, defaultDays: number) {
  const days = Number(url.searchParams.get("days") || defaultDays);
  if (!Number.isInteger(days) || days < 1 || days > 90) throw new QueryError("days must be 1..90");
  const net = url.searchParams.get("net") || null;
  if (net !== null && net !== "home" && net !== "mobile") throw new QueryError("bad net");
  const country = url.searchParams.get("country") || "RU";
  if (!/^[A-Z]{2}$/.test(country)) throw new QueryError("bad country");
  const to = utcDay(now);
  return { from: addDays(to, -(days - 1)), to, net, country };
}

/**
 * GET /v1/transports?asn=12389[&days=2][&net=home]: every transport with enough reporters on one ISP, best first.
 * Without asn the asking connection's ISP (see index.ts).
 */
export async function transportsApi(url: URL, env: Env, now: Date): Promise<unknown> {
  const asnText = url.searchParams.get("asn");
  if (!asnText || !/^\d{1,10}$/.test(asnText)) throw new QueryError("bad asn");
  const p = period(url, now, 2);
  const min = Number(env.MIN_REPORTERS) || 3;
  const { results } = await env.DB.prepare(
    `SELECT transport, MAX(as_org) AS as_org, ${SUMS} FROM transport_daily
     WHERE asn = ?1 AND country = ?2 AND day >= ?3 AND day <= ?4 AND (?5 IS NULL OR net = ?5)
     GROUP BY transport HAVING SUM(reporters) >= ?6
     ORDER BY CAST(SUM(ok_checks) AS REAL) / SUM(checks) DESC`,
  )
    .bind(Number(asnText), p.country, p.from, p.to, p.net, min)
    .all<Row & { as_org: string }>();
  return { asn: Number(asnText), as_org: results[0]?.as_org ?? null, net: p.net, from: p.from, to: p.to, transports: results.map(toRow) };
}

/** GET /v1/transport-isps[?days=2][&net=home]: the table for the map, ISPs with the most checks first. */
export async function transportIspsApi(url: URL, env: Env, now: Date): Promise<unknown> {
  const p = period(url, now, 2);
  const min = Number(env.MIN_REPORTERS) || 3;
  const { results } = await env.DB.prepare(
    `SELECT asn, MAX(as_org) AS as_org, transport, ${SUMS} FROM transport_daily
     WHERE country = ?1 AND day >= ?2 AND day <= ?3 AND (?4 IS NULL OR net = ?4)
     GROUP BY asn, transport HAVING SUM(reporters) >= ?5`,
  )
    .bind(p.country, p.from, p.to, p.net, min)
    .all<Row & { asn: number; as_org: string }>();
  const byAsn = new Map<number, { asn: number; as_org: string; checks: number; transports: TransportRow[] }>();
  for (const r of results) {
    const isp = byAsn.get(r.asn) ?? { asn: r.asn, as_org: r.as_org, checks: 0, transports: [] };
    isp.checks += r.checks;
    isp.transports.push(toRow(r));
    byAsn.set(r.asn, isp);
  }
  const isps = [...byAsn.values()].sort((a, b) => b.checks - a.checks).slice(0, 30);
  for (const isp of isps) isp.transports.sort((a, b) => b.ok - a.ok);
  return { net: p.net, from: p.from, to: p.to, transports: TRANSPORTS, isps };
}
