// DEMO data for local development of the map site: writes .wrangler/demo-seed.sql with made-up aggregates
// (30 days × targets × regions × ISPs), applied with `npm run seed:local` to the LOCAL database only.
// Never run it against the deployed database: the numbers are invented.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const spec = JSON.parse(readFileSync(fileURLToPath(new URL("../../spec/targets.json", import.meta.url)), "utf8"));

let seed = 42;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);

const REGIONS = ["MOW", "SPE", "MOS", "LEN", "KDA", "SVE", "NVS", "TA", "BA", "NIZ", "SAM", "ROS", "CHE", "KYA", "PER",
  "VGG", "VOR", "IRK", "PRI", "KHA", "OMS", "TYU", "SAR", "KGD", "DA", "STA", "ALT", "YAR", "UD", "SA", "MUR", "ARK"];
const ISPS = [
  [12389, "Rostelecom", "home"], [8402, "Beeline (Vimpelcom)", "home"], [31213, "MegaFon", "mobile"],
  [8359, "MTS PJSC", "mobile"], [42610, "Rostelecom Northwest", "home"], [15774, "Tele2 Russia", "mobile"],
];

// Typical picture per target: [share blocked, main method, secondary method or null].
const PROFILE = {
  yandex: [0, null], vk: [0, null], cloudflare: [0.05, "freeze"], hetzner: [0.75, "sni", "freeze"],
  ovh: [0.7, "ip", "freeze"], vultr: [0.8, "freeze"], linode: [0.65, "ip"], google: [0.02, null],
  youtube: [0.92, "sni", "throttle"], googlevideo: [0.9, "sni", "throttle"], discord: [0.95, "sni", "dns"],
  "discord-gateway": [0.95, "sni"], "discord-media": [0.9, "sni"], telegram: [0.35, "ip"], "telegram-web": [0.4, "ip"],
  whatsapp: [0.55, "ip", "sni"], signal: [0.85, "freeze", "sni"], instagram: [0.98, "ip", "dns"], facebook: [0.98, "sni", "dns"],
  x: [0.97, "sni", "dns"], linkedin: [0.96, "sni"], tiktok: [0.1, "sni"], twitch: [0.08, "throttle"], soundcloud: [0.6, "sni"],
  patreon: [0.9, "sni"], medium: [0.88, "sni"], github: [0.03, null], chatgpt: [0.05, null], proton: [0.9, "sni"],
  torproject: [0.97, "sni", "dns"], rutracker: [0.93, "sni", "dns"], nnmclub: [0.85, "sni"], meduza: [0.97, "sni", "dns"],
  bbc: [0.96, "sni"], dw: [0.95, "sni"], "telegram-dc2": [0.3, "ip"], "telegram-dc4": [0.3, "ip"], "cloudflare-dns": [0.05, "ip"],
};

const today = new Date();
const days = [];
for (let i = 29; i >= 0; i--) {
  days.push(new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i)).toISOString().slice(0, 10));
}

const rows = [];
const cols = ["dns", "ip", "sni", "freeze", "stall", "throttle"];
for (const [d, day] of days.entries()) {
  for (const region of REGIONS) {
    const regionBias = (rnd() - 0.5) * 0.2;
    for (const [asn, org, net] of ISPS.filter(() => rnd() < 0.5)) {
      const reporters = 3 + Math.floor(rnd() * 12);
      const probes = reporters + Math.floor(rnd() * reporters);
      // Mobile whitelists in some regions, more often lately.
      const whitelist = net === "mobile" && rnd() < 0.15 + d / 120 ? Math.round(probes * (0.3 + rnd() * 0.5)) : 0;
      rows.push([day, "_whitelist", asn, org, "RU", region, net, reporters, probes, whitelist, probes - whitelist, 0, 0, 0, 0, 0, 0, 0]);
      for (const t of spec.targets) {
        const [share, main, second] = PROFILE[t.id] ?? [0, null];
        // YouTube slows down over the month.
        const s = Math.min(1, Math.max(0, share + regionBias + (t.id === "youtube" ? (d - 15) / 100 : 0) + (rnd() - 0.5) * 0.15));
        const blocked = Math.round(probes * s);
        const m = Object.fromEntries(cols.map((c) => [c, 0]));
        if (main) m[main] = blocked;
        if (second) m[second] = Math.round(blocked * (0.2 + rnd() * 0.4));
        const quic = t.quic ? Math.round(probes * 0.6) : 0;
        rows.push([day, t.id, asn, org, "RU", region, net, reporters, probes, blocked, probes - blocked, m.dns, m.ip, m.sni, m.freeze, m.stall, m.throttle, quic]);
      }
    }
  }
}

const q = (v) => (typeof v === "number" ? v : `'${String(v).replace(/'/g, "''")}'`);
let sql = "DELETE FROM agg_daily;\n";
for (let i = 0; i < rows.length; i += 400) {
  sql +=
    "INSERT INTO agg_daily (day,target,asn,as_org,country,region,net,reporters,probes,blocked,ok,dns,ip,sni,freeze,stall,throttle,quic) VALUES\n" +
    rows.slice(i, i + 400).map((r) => `(${r.map(q).join(",")})`).join(",\n") +
    ";\n";
}
const dir = fileURLToPath(new URL("../.wrangler/", import.meta.url));
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}demo-seed.sql`, sql);
console.log(`${rows.length} demo aggregate rows → .wrangler/demo-seed.sql`);
