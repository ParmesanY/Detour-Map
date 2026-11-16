import { describe, expect, it } from "vitest";
import cases from "../../spec/verdict-cases.json";
import { classify, reportFlags } from "../src/verdicts";
import type { TargetResult } from "../src/report";
import { makeReport } from "./helpers";

describe("shared verdict cases (same file as the C# tests)", () => {
  it.each(cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    expect(classify(c.result as TargetResult)).toEqual(c.expect);
  });
});

describe("report flags", () => {
  const dead = { tcp: "timeout", tls: undefined, http: undefined };

  it("whitelist when only domestic sites work", () => {
    const report = makeReport({
      cloudflare: dead, hetzner: dead, ovh: dead, vultr: dead, linode: dead,
      "telegram-dc2": dead, "telegram-dc4": dead, "cloudflare-dns": dead,
    });
    expect(reportFlags(report)).toEqual(["whitelist"]);
  });

  it("no network when the control sites fail", () => {
    expect(reportFlags(makeReport({ yandex: dead, vk: dead }))).toEqual(["no_network"]);
  });

  it("untrusted with a DPI bypass, or a VPN the probe couldn't bypass", () => {
    expect(reportFlags(makeReport({}, { env: { vpn_adapter: false, dpi_bypass: true, nic: true } }))).toContain("untrusted");
    expect(reportFlags(makeReport({}, { env: { vpn_adapter: true, dpi_bypass: false, nic: false } }))).toContain("untrusted");
    expect(reportFlags(makeReport({}, { env: { vpn_adapter: true, dpi_bypass: false, nic: true } }))).toEqual([]);
  });
});
