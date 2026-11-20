// Read API for the map site. Everything comes from agg_daily; a group is shown only when it has at least
// MIN_REPORTERS reporters, so a single probe (or a single person in a small town) never shows up alone.
import { addDays, utcDay } from "./privacy";
import { TARGETS, TARGET_BY_ID, TARGETS_VERSION, WHITELIST_TARGET } from "./targets";
import { strategiesApi } from "./strategies";
import { transportIspsApi, transportsApi } from "./transports";

export class QueryError extends Error {}

const METHODS = ["dns", "ip", "sni", "freeze", "stall", "throttle"] as const;
type Method = (typeof METHODS)[number];

interface Sums {
  reporters: number;
  probes: number;
  blocked: number;
  ok: number;
  dns: number;
  ip: number;
  sni: number;
  freeze: number;
  stall: number;
  throttle: number;
  quic: number;
}

const SUMS = `SUM(reporters) AS reporters, SUM(probes) AS probes, SUM(blocked) AS blocked, SUM(ok) AS ok,
  SUM(dns) AS dns, SUM(ip) AS ip, SUM(sni) AS sni, SUM(freeze) AS freeze, SUM(stall) AS stall,
  SUM(throttle) AS throttle, SUM(quic) AS quic`;

const round = (x: number) => Math.round(x * 1000) / 1000;

/** Counts → shares of probes, and the most common blocking method. */
export function summarize(s: Sums) {
  const share = (n: number) => (s.probes > 0 ? round(n / s.probes) : 0);
  const methods = Object.fromEntries(METHODS.map((m) => [m, share(s[m])])) as Record<Method, number>;
  let main: Method | null = null;
  for (const m of METHODS) {
    if (s[m] > 0 && (main === null || s[m] > s[main])) {
      main = m;
    }
  }
  return {
    reporters: s.reporters,
    probes: s.probes,
    blocked: share(s.blocked),
    ok: share(s.ok),
    quic: share(s.quic),
    methods,
    main,
  };
}

interface Filter {
  from: string;
  to: string;
  days: number;
  country: string;
  net: "home" | "mobile" | null;
}

function param(url: URL, name: string, re: RegExp): string | null {
  const v = url.searchParams.get(name);
  if (v === null || v === "") {
    return null;
  }
  if (!re.test(v)) {
    throw new QueryError(`bad ${name}`);
  }
  return v;
}

function target(url: URL): string {
  const t = url.searchParams.get("target");
  if (!t || (t !== WHITELIST_TARGET && !TARGET_BY_ID.has(t))) {
    throw new QueryError("unknown target");
  }
  return t;
}

function filter(url: URL, now: Date, defaultDays: number): Filter {
  const days = Number(param(url, "days", /^\d{1,2}$/) ?? defaultDays);
  if (days < 1 || days > 90) {
    throw new QueryError("days must be 1..90");
  }
  const to = utcDay(now);
  return {
    from: addDays(to, -(days - 1)),
    to,
    days,
    country: param(url, "country", /^[A-Z]{2}$/) ?? "RU",
    net: param(url, "net", /^(home|mobile)$/) as Filter["net"],
  };
}

function where(f: Filter, extra: string[] = []): string {
  return ["day >= ?1", "day <= ?2", "country = ?3", f.net ? "net = ?4" : "?4 IS NULL", ...extra].join(" AND ");
}

const base = (f: Filter) => [f.from, f.to, f.country, f.net] as const;

const minReporters = (env: Env) => Number(env.MIN_REPORTERS) || 3;

export async function handleApi(url: URL, env: Env, now = new Date()): Promise<unknown> {
  const db = env.DB;
  const min = minReporters(env);
  switch (url.pathname) {
    case "/v1/targets":
      return { version: TARGETS_VERSION, targets: TARGETS.map(({ id, name, kind, host }) => ({ id, name, kind, host })) };

    case "/v1/summary": {
      // Every target, whole country: the list beside the map.
      const f = filter(url, now, 1);
      const { results } = await db
        .prepare(`SELECT target, ${SUMS} FROM agg_daily WHERE ${where(f)} GROUP BY target HAVING SUM(reporters) >= ?5`)
        .bind(...base(f), min)
        .all<Sums & { target: string }>();
      return {
        from: f.from,
        to: f.to,
        targets: results.map(({ target, ...s }) => ({ target, name: TARGET_BY_ID.get(target)?.name ?? target, ...summarize(s) })),
      };
    }

    case "/v1/map": {
      // One target, by region.
      const t = target(url);
      const f = filter(url, now, 1);
      const { results } = await db
        .prepare(`SELECT region, ${SUMS} FROM agg_daily WHERE ${where(f, ["target = ?5"])} GROUP BY region HAVING SUM(reporters) >= ?6`)
        .bind(...base(f), t, min)
        .all<Sums & { region: string }>();
      return { target: t, from: f.from, to: f.to, regions: results.map(({ region, ...s }) => ({ region, ...summarize(s) })) };
    }

    case "/v1/isps": {
      // One target, by ISP; optionally in one region.
      const t = target(url);
      const f = filter(url, now, 1);
      const region = param(url, "region", /^[A-Z0-9]{1,3}$/);
      const { results } = await db
        .prepare(
          `SELECT asn, MAX(as_org) AS as_org, ${SUMS} FROM agg_daily
           WHERE ${where(f, ["target = ?5", "(?6 IS NULL OR region = ?6)"])}
           GROUP BY asn HAVING SUM(reporters) >= ?7 ORDER BY SUM(probes) DESC`,
        )
        .bind(...base(f), t, region, min)
        .all<Sums & { asn: number; as_org: string }>();
      return {
        target: t,
        region,
        from: f.from,
        to: f.to,
        isps: results.map(({ asn, as_org, ...s }) => ({ asn, as_org, ...summarize(s) })),
      };
    }

    case "/v1/history": {
      // One target, by day; optionally for one ISP and/or region.
      const t = target(url);
      const f = filter(url, now, 30);
      const region = param(url, "region", /^[A-Z0-9]{1,3}$/);
      const asnText = param(url, "asn", /^\d{1,10}$/);
      const { results } = await db
        .prepare(
          `SELECT day, ${SUMS} FROM agg_daily
           WHERE ${where(f, ["target = ?5", "(?6 IS NULL OR region = ?6)", "(?7 IS NULL OR asn = ?7)"])}
           GROUP BY day HAVING SUM(reporters) >= ?8 ORDER BY day`,
        )
        .bind(...base(f), t, region, asnText === null ? null : Number(asnText), min)
        .all<Sums & { day: string }>();
      return { target: t, region, asn: asnText === null ? null : Number(asnText), days: results.map(({ day, ...s }) => ({ day, ...summarize(s) })) };
    }

    case "/v1/strategies":
      return strategiesApi(url, env, now);

    case "/v1/transports":
      return transportsApi(url, env, now);

    case "/v1/transport-isps":
      return transportIspsApi(url, env, now);

    default:
      return undefined;
  }
}
