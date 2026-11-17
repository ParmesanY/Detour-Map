// Registry (M8): tune results in, "what works for this ISP" out.
// A client tries every hint locally before using it, so a poisoned entry only slows tuning down; on top of that
// a strategy shows up only with MIN_REPORTERS distinct reporters and more of them for whom it worked than not.
import type { Origin } from "./ingest";
import { dailySalt, pseudonym, utcDay, utcHour, addDays } from "./privacy";
import { ENGINES, normalize, strategyId, type Engine } from "./strategy";
import { TARGET_BY_ID } from "./targets";
import { QueryError } from "./api";

export interface StrategyResultIn {
  args: string;
  passed: number;
  total: number;
  ms?: number;
}

export interface StrategyReport {
  v: 1;
  client: string;
  engine: Engine;
  net: "home" | "mobile";
  target: string;
  baseline: { passed: number; total: number };
  results: { key: string; passed: number; total: number; ms: number }[];
}

export const MAX_STRATEGY_RESULTS = 40;
const CLIENT_RE = /^(detour|detour-tune)\/\d{1,4}(\.\d{1,6}){0,3}$/;

class StrategyError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 422 = 400,
  ) {
    super(message);
  }
}

const isInt = (x: unknown, min: number, max: number): x is number => Number.isInteger(x) && (x as number) >= min && (x as number) <= max;

/** Strict: unknown engines, targets, options or numbers out of range are refused. */
export function parseStrategyReport(body: unknown): { report: StrategyReport; rejected: { index: number; error: string }[] } {
  if (typeof body !== "object" || body === null) throw new StrategyError("not an object");
  const b = body as Record<string, unknown>;
  if (b.v !== 1) throw new StrategyError("unsupported version");
  if (typeof b.client !== "string" || !CLIENT_RE.test(b.client)) throw new StrategyError("bad client");
  if (typeof b.engine !== "string" || !(ENGINES as readonly string[]).includes(b.engine)) throw new StrategyError("bad engine");
  if (b.net !== "home" && b.net !== "mobile") throw new StrategyError("bad net");
  const target = b.target === undefined || b.target === null ? "" : b.target;
  if (typeof target !== "string" || (target !== "" && !TARGET_BY_ID.has(target))) throw new StrategyError("unknown target");

  const env = b.env as Record<string, unknown> | undefined;
  if (typeof env !== "object" || env === null || typeof env.dpi_bypass !== "boolean") throw new StrategyError("bad env");
  if (env.dpi_bypass) throw new StrategyError("untrusted: another DPI bypass was running", 422);

  const base = b.baseline as Record<string, unknown> | undefined;
  if (typeof base !== "object" || base === null || !isInt(base.total, 1, 10) || !isInt(base.passed, 0, base.total as number)) {
    throw new StrategyError("bad baseline");
  }
  if (base.passed === base.total) throw new StrategyError("not blocked: the site opened without a bypass", 422);

  if (!Array.isArray(b.results) || b.results.length === 0 || b.results.length > MAX_STRATEGY_RESULTS) throw new StrategyError("bad results");
  const results: StrategyReport["results"] = [];
  const rejected: { index: number; error: string }[] = [];
  const seen = new Set<string>();
  b.results.forEach((raw: unknown, index: number) => {
    const r = raw as Record<string, unknown>;
    if (typeof r !== "object" || r === null || typeof r.args !== "string" || r.args.length > 1000
        || !isInt(r.total, 1, 10) || !isInt(r.passed, 0, r.total as number) || (r.ms !== undefined && r.ms !== null && !isInt(r.ms, 0, 120_000))) {
      rejected.push({ index, error: "bad result" });
      return;
    }
    const n = normalize(b.engine as string, r.args);
    if (n.error) {
      rejected.push({ index, error: n.error });
      return;
    }
    if (seen.has(n.key)) return;
    seen.add(n.key);
    results.push({ key: n.key, passed: r.passed as number, total: r.total as number, ms: (r.ms as number | undefined) ?? 0 });
  });
  if (results.length === 0) throw new StrategyError("no valid strategies");

  return {
    report: {
      v: 1,
      client: b.client,
      engine: b.engine as Engine,
      net: b.net,
      target,
      baseline: { passed: base.passed as number, total: base.total as number },
      results,
    },
    rejected,
  };
}

export type StrategyIngestResult =
  | { status: 202; body: { accepted: true; stored: number; rejected: { index: number; error: string }[] } }
  | { status: 400 | 422 | 429; body: { accepted: false; error: string } };

export async function ingestStrategies(env: Env, body: unknown, origin: Origin, now = new Date()): Promise<StrategyIngestResult> {
  let parsed;
  try {
    parsed = parseStrategyReport(body);
  } catch (e) {
    if (e instanceof StrategyError) return { status: e.status, body: { accepted: false, error: e.message } };
    throw e;
  }
  const { report, rejected } = parsed;
  const day = utcDay(now);
  const hour = utcHour(now);
  const pseudo = await pseudonym(await dailySalt(env.DB, day), origin.ip);
  const limit = Number(env.RATE_LIMIT_PER_HOUR) || 6;
  const seen = await env.DB.prepare("SELECT COUNT(*) AS n FROM strategy_reports WHERE pseudo = ?1 AND received_hour = ?2")
    .bind(pseudo, hour)
    .first<{ n: number }>();
  if ((seen?.n ?? 0) >= limit) return { status: 429, body: { accepted: false, error: "rate limited" } };

  await env.DB.prepare(
    `INSERT INTO strategy_reports (received_hour, day, pseudo, asn, as_org, country, region, net, client, engine, target, results)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
  )
    .bind(hour, day, pseudo, origin.asn, origin.asOrg.slice(0, 200), origin.country, origin.region, report.net, report.client,
      report.engine, report.target, JSON.stringify(report.results))
    .run();
  return { status: 202, body: { accepted: true, stored: report.results.length, rejected } };
}

/** The cron's part for the registry; runs in the same batch as the map's aggregates. */
export function strategyMaintenance(db: D1Database, today: string, yesterday: string, rawRetentionDays: number): D1PreparedStatement[] {
  const passed = "json_extract(j.value, '$.passed')";
  const total = "json_extract(j.value, '$.total')";
  return [
    db.prepare("DELETE FROM strategy_daily WHERE day IN (?1, ?2)").bind(today, yesterday),
    db.prepare(
      `INSERT INTO strategy_daily (day, engine, key, target, asn, as_org, country, net, reporters, works, fails, ms)
       SELECT r.day, r.engine, json_extract(j.value, '$.key'), r.target, r.asn, MAX(r.as_org), r.country, r.net,
              COUNT(DISTINCT r.pseudo),
              COUNT(DISTINCT CASE WHEN ${passed} = ${total} THEN r.pseudo END),
              COUNT(DISTINCT CASE WHEN ${passed} = 0 THEN r.pseudo END),
              CAST(AVG(CASE WHEN ${passed} > 0 THEN json_extract(j.value, '$.ms') END) AS INTEGER)
       FROM strategy_reports r, json_each(r.results) j
       WHERE r.day IN (?1, ?2) AND r.pseudo IS NOT NULL
       GROUP BY r.day, r.engine, json_extract(j.value, '$.key'), r.target, r.asn, r.country, r.net`,
    ).bind(today, yesterday),
    db.prepare("UPDATE strategy_reports SET pseudo = NULL WHERE day < ?1 AND pseudo IS NOT NULL").bind(yesterday),
    db.prepare("DELETE FROM strategy_reports WHERE day < ?1").bind(addDays(today, -rawRetentionDays)),
  ];
}

export interface StrategyHint {
  id: string;
  key: string;
  args: string;
  reporters: number;
  works: number;
  fails: number;
  /** Share of reporters for whom it worked. */
  score: number;
  ms: number | null;
}

/**
 * GET /v1/strategies?engine=winws&asn=12389[&target=rutracker][&net=home][&country=RU][&days=30]
 * Best strategies for one ISP: enough distinct reporters, worked for more than failed, best share first.
 */
export async function strategiesApi(url: URL, env: Env, now: Date): Promise<unknown> {
  const engine = url.searchParams.get("engine") ?? "winws";
  if (!(ENGINES as readonly string[]).includes(engine)) throw new QueryError("bad engine");
  const asnText = url.searchParams.get("asn");
  if (!asnText || !/^\d{1,10}$/.test(asnText)) throw new QueryError("bad asn");
  const target = url.searchParams.get("target") || null;
  if (target !== null && !TARGET_BY_ID.has(target)) throw new QueryError("unknown target");
  const net = url.searchParams.get("net") || null;
  if (net !== null && net !== "home" && net !== "mobile") throw new QueryError("bad net");
  const country = url.searchParams.get("country") || "RU";
  if (!/^[A-Z]{2}$/.test(country)) throw new QueryError("bad country");
  const days = Number(url.searchParams.get("days") || 30);
  if (!Number.isInteger(days) || days < 1 || days > 90) throw new QueryError("days must be 1..90");
  const to = utcDay(now);
  const from = addDays(to, -(days - 1));
  const min = Number(env.MIN_REPORTERS) || 3;

  const { results } = await env.DB.prepare(
    `SELECT key, MAX(as_org) AS as_org, SUM(reporters) AS reporters, SUM(works) AS works, SUM(fails) AS fails,
            CAST(SUM(ms * works) / NULLIF(SUM(CASE WHEN ms IS NOT NULL THEN works END), 0) AS INTEGER) AS ms
     FROM strategy_daily
     WHERE engine = ?1 AND asn = ?2 AND country = ?3 AND day >= ?4 AND day <= ?5
       AND (?6 IS NULL OR target = ?6) AND (?7 IS NULL OR net = ?7)
     GROUP BY key
     HAVING SUM(reporters) >= ?8 AND SUM(works) > SUM(fails)
     ORDER BY CAST(SUM(works) AS REAL) / SUM(reporters) DESC, SUM(works) DESC, ms ASC
     LIMIT 10`,
  )
    .bind(engine, Number(asnText), country, from, to, target, net, min)
    .all<{ key: string; as_org: string; reporters: number; works: number; fails: number; ms: number | null }>();

  const strategies: StrategyHint[] = [];
  for (const r of results) {
    strategies.push({
      id: await strategyId(r.key),
      key: r.key,
      args: r.key.slice(r.key.indexOf(":") + 1),
      reporters: r.reporters,
      works: r.works,
      fails: r.fails,
      score: Math.round((r.works / r.reporters) * 1000) / 1000,
      ms: r.ms,
    });
  }
  return { engine, asn: Number(asnText), as_org: results[0]?.as_org ?? null, target, net, from, to, strategies };
}
