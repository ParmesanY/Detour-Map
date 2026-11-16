// The probe's report (probe/Detour.NetProbe/Report.cs) and its strict validation: anything unexpected is
// rejected or dropped, so free text can't be smuggled into the database.
import { TARGET_BY_ID } from "./targets";

export interface HttpResult {
  bytes: number;
  status?: number | null;
  ms: number;
  complete: boolean;
  error?: string | null;
}

export interface TargetResult {
  t: string;
  dns?: string | null;
  dns_ip?: string | null;
  tcp?: string | null;
  tls?: string | null;
  tls_ctrl?: string | null;
  http?: HttpResult | null;
  quic?: string | null;
}

export interface ProbeReport {
  v: number;
  client: string;
  targets_ver: number;
  net: "home" | "mobile";
  ts: string;
  env: { vpn_adapter: boolean; dpi_bypass: boolean; nic: boolean };
  results: TargetResult[];
}

export const MAX_BODY_BYTES = 32 * 1024;
const MAX_RESULTS = 200;

const OUTCOMES = new Set(["ok", "timeout", "rst", "refused", "alert", "error", "stub", "nx", "none", "diff", "unsupported"]);
const CLIENT_RE = /^(detour|probe-cli)\/\d{1,4}(\.\d{1,6}){0,3}$/;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:00Z$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export class ReportError extends Error {}

function fail(message: string): never {
  throw new ReportError(message);
}

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function outcome(x: unknown, field: string): string | undefined {
  if (x == null) {
    return undefined;
  }
  if (typeof x !== "string" || !OUTCOMES.has(x)) {
    fail(`bad ${field}`);
  }
  return x;
}

function int(x: unknown, field: string, min: number, max: number): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < min || x > max) {
    fail(`bad ${field}`);
  }
  return x;
}

function bool(x: unknown, field: string): boolean {
  if (x === undefined) {
    return false;
  }
  if (typeof x !== "boolean") {
    fail(`bad ${field}`);
  }
  return x;
}

function parseHttp(x: unknown): HttpResult | undefined {
  if (x == null) {
    return undefined;
  }
  if (!isObject(x)) {
    fail("bad http");
  }
  return {
    bytes: int(x.bytes, "http.bytes", 0, 1 << 20),
    status: x.status == null ? undefined : int(x.status, "http.status", 100, 599),
    ms: int(x.ms, "http.ms", 0, 600_000),
    complete: bool(x.complete, "http.complete"),
    error: outcome(x.error, "http.error"),
  };
}

function parseResult(x: unknown): TargetResult {
  if (!isObject(x) || typeof x.t !== "string") {
    fail("bad result");
  }
  const dnsIp = x.dns_ip;
  if (dnsIp != null && (typeof dnsIp !== "string" || !IPV4_RE.test(dnsIp))) {
    fail("bad dns_ip");
  }
  return {
    t: x.t,
    dns: outcome(x.dns, "dns"),
    dns_ip: dnsIp ?? undefined,
    tcp: outcome(x.tcp, "tcp"),
    tls: outcome(x.tls, "tls"),
    tls_ctrl: outcome(x.tls_ctrl, "tls_ctrl"),
    http: parseHttp(x.http),
    quic: outcome(x.quic, "quic"),
  };
}

/** Validated report; results for targets this collector doesn't know are dropped. */
export function parseReport(body: unknown): ProbeReport {
  if (!isObject(body)) {
    fail("not an object");
  }
  if (body.v !== 1) {
    fail("unsupported version");
  }
  if (typeof body.client !== "string" || !CLIENT_RE.test(body.client)) {
    fail("bad client");
  }
  if (body.net !== "home" && body.net !== "mobile") {
    fail("bad net");
  }
  if (typeof body.ts !== "string" || !TS_RE.test(body.ts)) {
    fail("bad ts");
  }
  if (!isObject(body.env)) {
    fail("bad env");
  }
  if (!Array.isArray(body.results) || body.results.length === 0 || body.results.length > MAX_RESULTS) {
    fail("bad results");
  }
  const results = body.results.map(parseResult).filter((r) => TARGET_BY_ID.has(r.t));
  if (new Set(results.map((r) => r.t)).size !== results.length) {
    fail("duplicate target");
  }
  if (results.length === 0) {
    fail("no known targets");
  }
  return {
    v: 1,
    client: body.client,
    targets_ver: int(body.targets_ver, "targets_ver", 0, 1_000_000),
    net: body.net,
    ts: body.ts,
    env: {
      vpn_adapter: bool(body.env.vpn_adapter, "env.vpn_adapter"),
      dpi_bypass: bool(body.env.dpi_bypass, "env.dpi_bypass"),
      nic: bool(body.env.nic, "env.nic"),
    },
    results,
  };
}
