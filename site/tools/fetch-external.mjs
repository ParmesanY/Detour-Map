// Builds site/public/data/external.json: what other open sources say about each target.
//   - OONI: Web Connectivity measurements from Russia for the target's domain, last 7 days, by ISP (ASN).
//     OONI data is CC BY-NC-SA 4.0 (https://github.com/ooni/license), shown as a separate, attributed layer.
//   - The RKN register as exported by antifilter.download (domains.lst), and antifilter's community list of
//     domains that need a bypass without being in the register (or are geo-blocked by the service itself).
//   - The hand-curated event timeline in spec/events.json.
// Run: node site/tools/fetch-external.mjs   (Node 20+; the GitHub Pages workflow runs it daily.)
// Each source is optional: if one is down, the others are still written and that part keeps "error".
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const out = join(root, "site", "public", "data", "external.json");
const UA = "detour-map-external/0.1 (+https://github.com/ParmesanY/Detour-Map)";
const OONI_DAYS = 7;

const { targets } = JSON.parse(await readFile(join(root, "spec", "targets.json"), "utf8"));
const { events } = JSON.parse(await readFile(join(root, "spec", "events.json"), "utf8"));
const withHost = targets.filter((t) => t.host && (t.kind ?? "site") !== "control");

const day = (d) => d.toISOString().slice(0, 10);
const until = new Date();
const since = new Date(until.getTime() - OONI_DAYS * 86400_000);
const HISTORY_DAYS = 30;
const historySince = new Date(until.getTime() - (HISTORY_DAYS - 1) * 86400_000);

async function get(url, timeoutMs = 60_000) {
  const res = await fetch(url, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}

// ---- OONI ----

async function ooniFor(domain) {
  const q = new URLSearchParams({
    probe_cc: "RU",
    test_name: "web_connectivity",
    domain,
    since: day(since),
    until: day(until),
    axis_x: "probe_asn",
  });
  const body = await (await get(`https://api.ooni.io/api/v1/aggregation?${q}`)).json();
  const rows = body.result ?? [];
  const sum = (k) => rows.reduce((a, r) => a + (r[k] ?? 0), 0);
  return {
    domain,
    measurements: sum("measurement_count"),
    anomaly: sum("anomaly_count"),
    confirmed: sum("confirmed_count"),
    failure: sum("failure_count"),
    ok: sum("ok_count"),
    asns: rows
      .filter((r) => r.measurement_count > 0)
      .sort((a, b) => b.measurement_count - a.measurement_count)
      .slice(0, 8)
      .map((r) => ({
        asn: Number(String(r.probe_asn).replace(/^AS/i, "")),
        measurements: r.measurement_count,
        anomaly: r.anomaly_count,
        confirmed: r.confirmed_count,
        ok: r.ok_count,
      })),
  };
}

/** The whole country, by day, for the last HISTORY_DAYS: the second series on the site's history chart. */
async function ooniDaily(domain) {
  const q = new URLSearchParams({
    probe_cc: "RU",
    test_name: "web_connectivity",
    domain,
    since: day(historySince),
    until: day(until),
    axis_x: "measurement_start_day",
    time_grain: "day",
  });
  const body = await (await get(`https://api.ooni.io/api/v1/aggregation?${q}`)).json();
  return (body.result ?? [])
    .filter((r) => r.measurement_count > 0)
    .map((r) => ({
      day: String(r.measurement_start_day).slice(0, 10),
      measurements: r.measurement_count,
      anomaly: r.anomaly_count,
      confirmed: r.confirmed_count,
      ok: r.ok_count,
    }));
}

/** ISP names for ASNs from RIPEstat ("ROSTELECOM-AS PJSC Rostelecom" → "PJSC Rostelecom"). Missing names stay missing. */
async function asnNames(asns) {
  const names = {};
  for (const asn of [...new Set(asns)].sort((a, b) => a - b)) {
    try {
      const body = await (await get(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`, 20_000)).json();
      const holder = String(body?.data?.holder ?? "").trim();
      if (!holder) continue;
      const parts = holder.split(/\s+/);
      names[asn] = parts.length > 1 && /^[A-Z0-9-]+$/.test(parts[0]) ? parts.slice(1).join(" ") : holder;
    } catch {
      // a name is a nicety
    }
  }
  return names;
}

async function ooni() {
  const result = { source: "OONI Explorer / API", url: "https://explorer.ooni.org/", license: "CC BY-NC-SA 4.0", since: day(since), until: day(until), targets: {} };
  for (const t of withHost) {
    try {
      // OONI's test lists mostly use the bare domain; try what we probe first, then the other form.
      const bare = t.host.replace(/^www\./, "");
      let r = await ooniFor(t.host);
      if (r.measurements === 0 && bare !== t.host) r = await ooniFor(bare);
      if (r.measurements === 0 && bare === t.host) {
        const www = await ooniFor(`www.${bare}`);
        if (www.measurements > 0) r = www;
      }
      if (r.measurements > 0) r.days = await ooniDaily(r.domain);
      result.targets[t.id] = r;
    } catch (e) {
      result.targets[t.id] = { error: String(e.message ?? e) };
    }
  }
  result.asn_names = await asnNames(Object.values(result.targets).flatMap((t) => (t.asns ?? []).map((a) => a.asn)));
  return result;
}

// ---- RKN register (antifilter) ----

async function lines(url) {
  const text = await (await get(url, 180_000)).text();
  const set = new Set();
  for (const raw of text.split("\n")) {
    const s = raw.trim().replace(/^"+|"+$/g, "").replace(/^\*\./, "").toLowerCase();
    if (s && !s.startsWith("#")) set.add(s);
  }
  return set;
}

/** The domain itself or the closest listed parent ("redirector.googlevideo.com" → "googlevideo.com"). */
function match(set, host) {
  const parts = host.toLowerCase().split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const d = parts.slice(i).join(".");
    if (set.has(d)) return d;
  }
  return null;
}

async function rkn() {
  const result = {
    source: "antifilter.download (выгрузка реестра Роскомнадзора)",
    url: "https://antifilter.download/",
    community_url: "https://community.antifilter.download/",
    updated: day(new Date()),
    targets: {},
  };
  const [register, community] = await Promise.all([
    lines("https://antifilter.download/list/domains.lst"),
    lines("https://community.antifilter.download/list/domains.lst"),
  ]);
  if (register.size < 10_000) throw new Error(`register list looks truncated: ${register.size} domains`);
  result.size = register.size;
  for (const t of withHost) {
    result.targets[t.id] = { register: match(register, t.host), community: match(community, t.host) };
  }
  return result;
}

// ---- write ----

const settle = async (fn) => {
  try {
    return await fn();
  } catch (e) {
    return { error: String(e.message ?? e) };
  }
};

const data = { generated: new Date().toISOString(), ooni: await settle(ooni), rkn: await settle(rkn), events };
await mkdir(dirname(out), { recursive: true });
await writeFile(out, JSON.stringify(data));
const ok = (x) => (x.error ? `error: ${x.error}` : "ok");
console.log(`external.json: ooni ${ok(data.ooni)}, rkn ${ok(data.rkn)}, ${events.length} events`);
