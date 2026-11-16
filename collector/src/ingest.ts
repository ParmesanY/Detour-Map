import { parseReport, ReportError } from "./report";
import { classify, reportFlags, ReportFlag } from "./verdicts";
import { dailySalt, pseudonym, utcDay, utcHour } from "./privacy";

/** What Cloudflare tells about the connection a report arrived on. The IP itself goes no further than here. */
export interface Origin {
  ip: string;
  asn: number;
  asOrg: string;
  country: string;
  region: string;
}

export type IngestResult =
  | { status: 202; body: { accepted: true; flags: string[]; verdicts: Record<string, string[]> } }
  | { status: 400 | 422 | 429; body: { accepted: false; error: string } };

export async function ingest(env: Env, body: unknown, origin: Origin, now = new Date()): Promise<IngestResult> {
  let report;
  try {
    report = parseReport(body);
  } catch (e) {
    if (e instanceof ReportError) {
      return { status: 400, body: { accepted: false, error: e.message } };
    }
    throw e;
  }

  const flags = reportFlags(report);
  if (flags.includes(ReportFlag.Untrusted)) {
    return { status: 422, body: { accepted: false, error: "untrusted: a DPI bypass ran, or a VPN carried the probe" } };
  }
  if (flags.includes(ReportFlag.NoNetwork)) {
    return { status: 422, body: { accepted: false, error: "no_network: the control sites failed" } };
  }

  const day = utcDay(now);
  const hour = utcHour(now);
  const pseudo = await pseudonym(await dailySalt(env.DB, day), origin.ip);

  const limit = Number(env.RATE_LIMIT_PER_HOUR) || 6;
  const seen = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE pseudo = ?1 AND received_hour = ?2")
    .bind(pseudo, hour)
    .first<{ n: number }>();
  if ((seen?.n ?? 0) >= limit) {
    return { status: 429, body: { accepted: false, error: "rate limited" } };
  }

  const verdicts: Record<string, string[]> = {};
  for (const r of report.results) {
    verdicts[r.t] = classify(r);
  }
  const stored = Object.fromEntries(Object.entries(verdicts).map(([t, v]) => [t, v.join(",")]));

  await env.DB.prepare(
    `INSERT INTO reports (received_hour, day, pseudo, asn, as_org, country, region, net, client, targets_ver, whitelist, verdicts, results)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
  )
    .bind(
      hour,
      day,
      pseudo,
      origin.asn,
      origin.asOrg.slice(0, 200),
      origin.country,
      origin.region,
      report.net,
      report.client,
      report.targets_ver,
      flags.includes(ReportFlag.Whitelist) ? 1 : 0,
      JSON.stringify(stored),
      JSON.stringify(report.results),
    )
    .run();

  return { status: 202, body: { accepted: true, flags, verdicts } };
}

/** Origin from a request: CF-Connecting-IP and request.cf. Null outside Cloudflare's network data. */
export function originOf(request: Request): Origin | null {
  const cf = request.cf as IncomingRequestCfProperties | undefined;
  const ip = request.headers.get("CF-Connecting-IP");
  if (!cf?.asn || !ip) {
    return null;
  }
  return {
    ip,
    asn: cf.asn,
    asOrg: cf.asOrganization ?? "",
    country: cf.country ?? "",
    region: cf.regionCode ?? "",
  };
}
