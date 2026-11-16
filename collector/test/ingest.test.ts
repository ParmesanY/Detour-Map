import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { ingest } from "../src/ingest";
import { runMaintenance } from "../src/aggregate";
import { handleApi } from "../src/api";
import { makeReport, origin, SNI_BLOCK } from "./helpers";

const NOW = new Date("2026-11-16T14:30:00Z");
const api = (path: string, now = NOW) => handleApi(new URL(`https://map.test${path}`), env, now) as Promise<any>;

describe("ingest", () => {
  it("stores a report with verdicts and no IP address", async () => {
    const res = await ingest(env, makeReport({ x: SNI_BLOCK }), origin(1), NOW);
    expect(res.status).toBe(202);
    if (res.status !== 202) return;
    expect(res.body.verdicts.x).toEqual(["sni"]);
    expect(res.body.verdicts.youtube).toEqual(["ok"]);

    const rows = await env.DB.prepare("SELECT * FROM reports").all();
    expect(rows.results).toHaveLength(1);
    const row = rows.results[0] as Record<string, unknown>;
    expect(row.asn).toBe(12389);
    expect(row.region).toBe("MOW");
    expect(row.received_hour).toBe("2026-11-16T14");
    expect(JSON.parse(row.verdicts as string).x).toBe("sni");
    // The address appears nowhere: not as is, not in any column.
    for (const table of ["reports", "salts", "agg_daily"]) {
      const all = await env.DB.prepare(`SELECT * FROM ${table}`).all();
      expect(JSON.stringify(all.results)).not.toContain("203.0.113.1");
    }
  });

  it("rejects untrusted and no-network reports", async () => {
    const dpi = await ingest(env, makeReport({}, { env: { vpn_adapter: false, dpi_bypass: true, nic: true } }), origin(1), NOW);
    expect(dpi.status).toBe(422);
    const dead = { tcp: "timeout", tls: undefined, http: undefined };
    const offline = await ingest(env, makeReport({ yandex: dead, vk: dead }), origin(1), NOW);
    expect(offline.status).toBe(422);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first<{ n: number }>();
    expect(count?.n).toBe(0);
  });

  it("rate-limits one address per hour, not different addresses", async () => {
    for (let i = 0; i < 6; i++) {
      expect((await ingest(env, makeReport(), origin(1), NOW)).status).toBe(202);
    }
    expect((await ingest(env, makeReport(), origin(1), NOW)).status).toBe(429);
    expect((await ingest(env, makeReport(), origin(2), NOW)).status).toBe(202);
    // Next hour the address may report again.
    expect((await ingest(env, makeReport(), origin(1), new Date("2026-11-16T15:01:00Z"))).status).toBe(202);
  });

  it("same address, same day → same pseudonym; next day → a different one", async () => {
    await ingest(env, makeReport(), origin(1), NOW);
    await ingest(env, makeReport(), origin(1), new Date("2026-11-16T20:00:00Z"));
    await ingest(env, makeReport(), origin(1), new Date("2026-11-17T09:00:00Z"));
    const rows = await env.DB.prepare("SELECT day, pseudo FROM reports ORDER BY id").all<{ day: string; pseudo: string }>();
    const [a, b, c] = rows.results;
    expect(a!.pseudo).toBe(b!.pseudo);
    expect(c!.pseudo).not.toBe(a!.pseudo);
  });
});

describe("aggregation and the read API", () => {
  async function seed() {
    // Moscow, Rostelecom: 3 people see X blocked by SNI. One also has a DNS stub.
    await ingest(env, makeReport({ x: SNI_BLOCK }), origin(1), NOW);
    await ingest(env, makeReport({ x: SNI_BLOCK }), origin(2), NOW);
    await ingest(env, makeReport({ x: { ...SNI_BLOCK, dns: "stub", dns_ip: "10.0.0.1" } }), origin(3), NOW);
    // St Petersburg, MTS: only 2 people: below the threshold, must stay hidden.
    await ingest(env, makeReport({ x: SNI_BLOCK }), origin(4, { region: "SPE", asn: 8359, asOrg: "MTS" }), NOW);
    await ingest(env, makeReport({ x: SNI_BLOCK }), origin(5, { region: "SPE", asn: 8359, asOrg: "MTS" }), NOW);
    await runMaintenance(env.DB, NOW);
  }

  it("map shows regions with enough reporters only", async () => {
    await seed();
    const map = await api("/v1/map?target=x");
    expect(map.regions).toHaveLength(1);
    const moscow = map.regions[0];
    expect(moscow.region).toBe("MOW");
    expect(moscow.reporters).toBe(3);
    expect(moscow.blocked).toBe(1);
    expect(moscow.main).toBe("sni");
    expect(moscow.methods.dns).toBeCloseTo(0.333, 3);
  });

  it("a site open everywhere shows as open", async () => {
    await seed();
    const map = await api("/v1/map?target=youtube");
    expect(map.regions[0].blocked).toBe(0);
    expect(map.regions[0].ok).toBe(1);
    expect(map.regions[0].main).toBeNull();
  });

  it("isps, summary and history", async () => {
    await seed();
    const isps = await api("/v1/isps?target=x");
    expect(isps.isps.map((i: any) => i.as_org)).toEqual(["Rostelecom"]);

    const summary = await api("/v1/summary");
    const x = summary.targets.find((t: any) => t.target === "x");
    expect(x.name).toBe("X (Twitter)");
    expect(x.reporters).toBe(5);
    expect(x.blocked).toBe(1);

    const history = await api("/v1/history?target=x&region=MOW");
    expect(history.days).toEqual([expect.objectContaining({ day: "2026-11-16", reporters: 3 })]);
  });

  it("whitelist reports are counted under _whitelist", async () => {
    const dead = { tcp: "timeout", tls: undefined, http: undefined };
    const wl = { cloudflare: dead, hetzner: dead, ovh: dead, vultr: dead, linode: dead, "telegram-dc2": dead, "telegram-dc4": dead, "cloudflare-dns": dead };
    for (let i = 1; i <= 3; i++) {
      const res = await ingest(env, makeReport(wl, { net: "mobile" }), origin(i, { asn: 25159, asOrg: "MegaFon" }), NOW);
      expect(res.status === 202 && res.body.flags).toEqual(["whitelist"]);
    }
    await runMaintenance(env.DB, NOW);
    const map = await api("/v1/map?target=_whitelist&net=mobile");
    expect(map.regions[0].blocked).toBe(1);
    expect((await api("/v1/map?target=_whitelist&net=home")).regions).toHaveLength(0);
  });

  it("maintenance forgets pseudonyms after two days, old salts and old reports", async () => {
    await ingest(env, makeReport(), origin(1), new Date("2026-10-01T10:00:00Z"));
    await ingest(env, makeReport(), origin(1), new Date("2026-11-14T10:00:00Z"));
    await ingest(env, makeReport(), origin(1), new Date("2026-11-15T10:00:00Z"));
    await ingest(env, makeReport(), origin(1), NOW);
    await runMaintenance(env.DB, NOW);

    const rows = await env.DB.prepare("SELECT day, pseudo FROM reports ORDER BY day").all<{ day: string; pseudo: string | null }>();
    expect(rows.results.map((r) => [r.day, r.pseudo !== null])).toEqual([
      ["2026-11-14", false],
      ["2026-11-15", true],
      ["2026-11-16", true],
    ]);
    const salts = await env.DB.prepare("SELECT day FROM salts").all<{ day: string }>();
    expect(salts.results.map((s) => s.day)).toEqual(["2026-11-16"]);
  });

  it("rejects bad queries", async () => {
    await expect(api("/v1/map?target=nope")).rejects.toThrow("unknown target");
    await expect(api("/v1/map?target=x&days=500")).rejects.toThrow();
    await expect(api("/v1/isps?target=x&region=';--")).rejects.toThrow("bad region");
  });
});
