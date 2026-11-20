import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import spec from "../../spec/transports.json";
import { ingestTransports, parseTransportReport, TRANSPORTS } from "../src/transports";
import { runMaintenance } from "../src/aggregate";
import { handleApi } from "../src/api";
import { origin } from "./helpers";

const NOW = new Date("2026-11-20T14:30:00Z");
const api = (path: string) => handleApi(new URL(`https://map.test${path}`), env, NOW) as Promise<any>;

function report(results: { transport: string; ok?: number; frozen?: number; fail?: number }[], patch: Record<string, unknown> = {}) {
  return {
    v: 1,
    client: "detour/0.4.1",
    net: "home",
    env: { dpi_bypass: false },
    results: results.map((r) => ({ ok: 0, frozen: 0, fail: 0, ...r })),
    ...patch,
  };
}

describe("transport reports", () => {
  it("the list matches the shared spec", () => {
    expect([...TRANSPORTS]).toEqual(spec.transports);
  });

  it("refuses unknown transports, empty counts, a bypass on the VPN path", async () => {
    expect(() => parseTransportReport(report([{ transport: "vpn.example.com", ok: 1 }]))).toThrow();
    expect(() => parseTransportReport(report([{ transport: "hysteria2" }]))).toThrow();
    expect(() => parseTransportReport(report([{ transport: "hysteria2", ok: 1 }, { transport: "hysteria2", ok: 1 }]))).toThrow();
    expect((await ingestTransports(env, report([{ transport: "hysteria2", ok: 1 }], { env: { dpi_bypass: true } }), origin(1), NOW)).status).toBe(422);
    expect((await ingestTransports(env, report([{ transport: "hysteria2", ok: 1 }], { client: "evil/1" }), origin(1), NOW)).status).toBe(400);
  });

  it("aggregates per ISP and hides thin groups", async () => {
    for (let i = 1; i <= 3; i++) {
      const r = await ingestTransports(env, report([
        { transport: "vless-reality", ok: 1, frozen: 3 },
        { transport: "hysteria2", ok: 4 },
      ]), origin(i), NOW);
      expect(r.status).toBe(202);
    }
    // only two reporters on another ISP: below MIN_REPORTERS
    for (let i = 4; i <= 5; i++) {
      await ingestTransports(env, report([{ transport: "vless-xhttp", ok: 2 }]), origin(i, { asn: 8359, asOrg: "MTS" }), NOW);
    }
    await runMaintenance(env.DB, NOW);

    const one = await api("/v1/transports?asn=12389");
    expect(one.transports.map((t: any) => t.transport)).toEqual(["hysteria2", "vless-reality"]);
    expect(one.transports[1]).toMatchObject({ reporters: 3, checks: 12, ok: 0.25, frozen: 0.75 });

    const all = await api("/v1/transport-isps");
    expect(all.isps.map((i: any) => i.asn)).toEqual([12389]);
    expect(await api("/v1/transports?asn=8359")).toMatchObject({ transports: [] });
  });

  it("rate limits per hour", async () => {
    let last = 0;
    for (let i = 0; i < 8; i++) {
      last = (await ingestTransports(env, report([{ transport: "trojan", ok: 1 }]), origin(42), NOW)).status;
    }
    expect(last).toBe(429);
  });
});
