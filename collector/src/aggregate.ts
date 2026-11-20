import { addDays, utcDay } from "./privacy";
import { WHITELIST_TARGET } from "./targets";
import { BLOCKING } from "./verdicts";
import { strategyMaintenance } from "./strategies";
import { transportMaintenance } from "./transports";

/** Raw reports are kept this long (to recompute verdicts when rules change); aggregates forever. */
export const RAW_RETENTION_DAYS = 30;

// `verdicts` holds {"target": "dns,sni"}; ','||value||',' GLOB '*,sni,*' tests for one verdict.
const has = (v: string) => `((',' || j.value || ',') GLOB '*,${v},*')`;
const count = (v: string) => `SUM(${has(v)})`;

const REBUILD_TARGETS = `
INSERT INTO agg_daily (day, target, asn, as_org, country, region, net, reporters, probes, blocked, ok, dns, ip, sni, freeze, stall, throttle, quic)
SELECT r.day, j.key, r.asn, MAX(r.as_org), r.country, r.region, r.net,
       COUNT(DISTINCT r.pseudo), COUNT(*),
       SUM(${BLOCKING.map(has).join(" OR ")}),
       SUM(j.value = 'ok'),
       ${count("dns")}, ${count("ip")}, ${count("sni")}, ${count("freeze16k")}, ${count("stall")}, ${count("throttle")}, ${count("quic")}
FROM reports r, json_each(r.verdicts) j
WHERE r.day IN (?1, ?2)
GROUP BY r.day, j.key, r.asn, r.country, r.region, r.net`;

const REBUILD_WHITELIST = `
INSERT INTO agg_daily (day, target, asn, as_org, country, region, net, reporters, probes, blocked, ok, dns, ip, sni, freeze, stall, throttle, quic)
SELECT day, '${WHITELIST_TARGET}', asn, MAX(as_org), country, region, net,
       COUNT(DISTINCT pseudo), COUNT(*), SUM(whitelist), SUM(1 - whitelist), 0, 0, 0, 0, 0, 0, 0
FROM reports
WHERE day IN (?1, ?2)
GROUP BY day, asn, country, region, net`;

/**
 * The cron job: rebuild today's and yesterday's aggregates from raw reports, then forget what's no longer
 * needed: pseudonyms older than yesterday, salts of past days, raw reports past retention.
 */
export async function runMaintenance(db: D1Database, now = new Date()): Promise<void> {
  const today = utcDay(now);
  const yesterday = addDays(today, -1);
  await db.batch([
    db.prepare("DELETE FROM agg_daily WHERE day IN (?1, ?2)").bind(today, yesterday),
    db.prepare(REBUILD_TARGETS).bind(today, yesterday),
    db.prepare(REBUILD_WHITELIST).bind(today, yesterday),
    db.prepare("UPDATE reports SET pseudo = NULL WHERE day < ?1 AND pseudo IS NOT NULL").bind(yesterday),
    db.prepare("DELETE FROM salts WHERE day < ?1").bind(today),
    db.prepare("DELETE FROM reports WHERE day < ?1").bind(addDays(today, -RAW_RETENTION_DAYS)),
    ...strategyMaintenance(db, today, yesterday, RAW_RETENTION_DAYS),
    ...transportMaintenance(db, today, yesterday, RAW_RETENTION_DAYS),
  ]);
}
