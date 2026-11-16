import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { makeReport } from "./helpers";

const worker = exports.default as unknown as { fetch: (input: string | Request, init?: RequestInit) => Promise<Response> };
const url = (path: string) => `https://map.test${path}`;

describe("http", () => {
  it("serves the target list with CORS", async () => {
    const res = await worker.fetch(url("/v1/targets"));
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = (await res.json()) as any;
    expect(body.targets.find((t: any) => t.id === "youtube").host).toBe("www.youtube.com");
  });

  it("answers preflight, 404 and 405", async () => {
    expect((await worker.fetch(url("/v1/report"), { method: "OPTIONS" })).status).toBe(204);
    expect((await worker.fetch(url("/v1/nothing"))).status).toBe(404);
    expect((await worker.fetch(url("/v1/report"), { method: "DELETE" })).status).toBe(405);
    expect((await worker.fetch(url("/v1/map?target=nope"))).status).toBe(400);
  });

  it("refuses oversized and non-JSON bodies", async () => {
    const big = await worker.fetch(url("/v1/report"), { method: "POST", body: "x".repeat(40_000) });
    expect(big.status).toBe(413);
    const junk = await worker.fetch(
      new Request(url("/v1/report"), { method: "POST", body: "{nope", headers: { "CF-Connecting-IP": "203.0.113.9" }, cf: { asn: 12389, asOrganization: "Rostelecom", country: "RU", regionCode: "MOW" } } as RequestInit),
    );
    expect(junk.status).toBe(400);
  });

  it("accepts a report end to end", async () => {
    const res = await worker.fetch(
      new Request(url("/v1/report"), {
        method: "POST",
        body: JSON.stringify(makeReport()),
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
        cf: { asn: 12389, asOrganization: "Rostelecom", country: "RU", regionCode: "MOW" },
      } as RequestInit),
    );
    const body = (await res.json()) as any;
    expect(res.status, JSON.stringify(body)).toBe(202);
    expect(body.accepted).toBe(true);
  });
});
