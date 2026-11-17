import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import cases from "../../spec/strategy-cases.json";
import { normalize, strategyId } from "../src/strategy";
import { ingestStrategies, parseStrategyReport } from "../src/strategies";
import { runMaintenance } from "../src/aggregate";
import { handleApi } from "../src/api";
import { origin } from "./helpers";

const NOW = new Date("2026-11-17T14:30:00Z");
const api = (path: string) => handleApi(new URL(`https://map.test${path}`), env, NOW) as Promise<any>;

const FAKE_TS = "--filter-tcp=443 --hostlist-domains=rutracker.org --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"%BIN%tls_clienthello_www_google_com.bin\"";
const SPLIT = "--dpi-desync=multisplit --dpi-desync-split-pos=1";

function tune(results: { args: string; passed: number; total?: number; ms?: number }[], patch: Record<string, unknown> = {}) {
  return {
    v: 1,
    client: "detour-tune/0.1.0",
    engine: "winws",
    net: "home",
    target: "rutracker",
    env: { vpn_adapter: false, dpi_bypass: false, nic: true },
    baseline: { passed: 0, total: 2 },
    results: results.map((r) => ({ total: 2, ms: 600, ...r })),
    ...patch,
  };
}

describe("strategy keys (shared with C#)", () => {
  for (const c of cases.cases) {
    it(c.name, () => {
      const r = normalize(c.engine, c.args);
      if ("key" in c && c.key) expect(r.key).toBe(c.key);
      else expect(r.error).toBe((c as { error: string }).error);
    });
  }

  it("id is 12 hex chars and stable", async () => {
    const id = await strategyId("winws:--dpi-desync=fake");
    expect(id).toMatch(/^[0-9a-f]{12}$/);
    expect(await strategyId("winws:--dpi-desync=fake")).toBe(id);
  });
});

describe("strategy reports", () => {
  it("normalizes args itself and drops bad ones", () => {
    const { report, rejected } = parseStrategyReport(tune([{ args: FAKE_TS, passed: 2 }, { args: "--debug=@x", passed: 2 }, { args: SPLIT, passed: 0 }]));
    expect(report.results.map((r) => r.key)).toEqual([
      "winws:--dpi-desync=fake --dpi-desync-fake-tls=%BIN%tls_clienthello_www_google_com.bin --dpi-desync-fooling=ts --dpi-desync-repeats=6",
      "winws:--dpi-desync=multisplit --dpi-desync-split-pos=1",
    ]);
    expect(rejected).toEqual([{ index: 1, error: "option" }]);
  });

  it("refuses an open site, a running bypass, unknown targets", async () => {
    expect((await ingestStrategies(env, tune([{ args: SPLIT, passed: 2 }], { baseline: { passed: 2, total: 2 } }), origin(1), NOW)).status).toBe(422);
    expect((await ingestStrategies(env, tune([{ args: SPLIT, passed: 2 }], { env: { dpi_bypass: true } }), origin(1), NOW)).status).toBe(422);
    expect((await ingestStrategies(env, tune([{ args: SPLIT, passed: 2 }], { target: "secret-site.example" }), origin(1), NOW)).status).toBe(400);
    expect((await ingestStrategies(env, tune([{ args: "--debug=1", passed: 2 }]), origin(1), NOW)).status).toBe(400);
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM strategy_reports").first<{ n: number }>();
    expect(n?.n).toBe(0);
  });

  it("stores no IP and no site name", async () => {
    expect((await ingestStrategies(env, tune([{ args: FAKE_TS, passed: 2 }], { target: null }), origin(1), NOW)).status).toBe(202);
    const rows = await env.DB.prepare("SELECT * FROM strategy_reports").all();
    expect(rows.results).toHaveLength(1);
    const text = JSON.stringify(rows.results);
    expect(text).not.toContain("203.0.113.1");
    expect(text).not.toContain("rutracker.org");
    expect((rows.results[0] as { target: string }).target).toBe("");
  });

  it("rate-limits one address per hour", async () => {
    for (let i = 0; i < 6; i++) {
      expect((await ingestStrategies(env, tune([{ args: SPLIT, passed: 2 }]), origin(1), NOW)).status).toBe(202);
    }
    expect((await ingestStrategies(env, tune([{ args: SPLIT, passed: 2 }]), origin(1), NOW)).status).toBe(429);
  });
});

describe("/v1/strategies", () => {
  async function report(n: number, results: { args: string; passed: number }[], patch: Record<string, unknown> = {}, asn = 12389) {
    const res = await ingestStrategies(env, tune(results, patch), origin(n, { asn }), NOW);
    expect(res.status).toBe(202);
  }

  it("shows a strategy only with 3 reporters and a majority for it", async () => {
    await report(1, [{ args: FAKE_TS, passed: 2 }, { args: SPLIT, passed: 0 }]);
    await report(2, [{ args: FAKE_TS, passed: 2 }, { args: SPLIT, passed: 2 }]);
    await runMaintenance(env.DB, NOW);
    expect((await api("/v1/strategies?engine=winws&asn=12389")).strategies).toEqual([]);

    await report(3, [{ args: FAKE_TS, passed: 2 }, { args: SPLIT, passed: 0 }]);
    // The same person twice still counts once.
    await report(3, [{ args: SPLIT, passed: 2 }]);
    await runMaintenance(env.DB, NOW);
    const res = await api("/v1/strategies?engine=winws&asn=12389");
    expect(res.as_org).toBe("Rostelecom");
    expect(res.strategies).toHaveLength(1);
    const best = res.strategies[0];
    expect(best.args).toBe("--dpi-desync=fake --dpi-desync-fake-tls=%BIN%tls_clienthello_www_google_com.bin --dpi-desync-fooling=ts --dpi-desync-repeats=6");
    expect(best).toMatchObject({ reporters: 3, works: 3, fails: 0, score: 1, ms: 600 });
    expect(best.id).toMatch(/^[0-9a-f]{12}$/);
  });

  it("keeps ISPs, engines and targets apart", async () => {
    for (const n of [1, 2, 3]) await report(n, [{ args: FAKE_TS, passed: 2 }]);
    await runMaintenance(env.DB, NOW);
    expect((await api("/v1/strategies?engine=winws&asn=8359")).strategies).toEqual([]);
    expect((await api("/v1/strategies?engine=byedpi&asn=12389")).strategies).toEqual([]);
    expect((await api("/v1/strategies?engine=winws&asn=12389&target=youtube")).strategies).toEqual([]);
    expect((await api("/v1/strategies?engine=winws&asn=12389&target=rutracker")).strategies).toHaveLength(1);
  });

  it("validates the query", async () => {
    await expect(api("/v1/strategies?engine=winws&asn=abc")).rejects.toThrow("bad asn");
    await expect(api("/v1/strategies?engine=goodbye&asn=1")).rejects.toThrow("bad engine");
  });
});
