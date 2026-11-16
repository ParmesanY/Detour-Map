import { describe, expect, it } from "vitest";
import { parseReport, ReportError } from "../src/report";
import { makeReport } from "./helpers";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe("report validation", () => {
  it("accepts what the probe sends", () => {
    const parsed = parseReport(clone(makeReport()));
    expect(parsed.results.length).toBeGreaterThan(30);
  });

  it("drops unknown targets and unknown fields", () => {
    const body = clone(makeReport()) as any;
    body.results.push({ t: "not-a-target", tcp: "ok" });
    body.results[0].comment = "free text";
    body.hostname = "my-pc";
    const parsed = parseReport(body) as any;
    expect(parsed.results.some((r: any) => r.t === "not-a-target")).toBe(false);
    expect(parsed.results[0].comment).toBeUndefined();
    expect(parsed.hostname).toBeUndefined();
  });

  it.each([
    ["outcome outside the vocabulary", (b: any) => (b.results[0].tcp = "<script>")],
    ["dns_ip that isn't an IPv4", (b: any) => (b.results[0].dns_ip = "example.com")],
    ["bad client", (b: any) => (b.client = "curl/8")],
    ["bad net", (b: any) => (b.net = "satellite")],
    ["bad ts", (b: any) => (b.ts = "yesterday")],
    ["future version", (b: any) => (b.v = 2)],
    ["duplicate target", (b: any) => b.results.push(clone(b.results[0]))],
    ["huge byte count", (b: any) => (b.results[0].http.bytes = 1e9)],
    ["no results", (b: any) => (b.results = [])],
  ])("rejects %s", (_name, mutate) => {
    const body = clone(makeReport()) as any;
    mutate(body);
    expect(() => parseReport(body)).toThrow(ReportError);
  });
});
