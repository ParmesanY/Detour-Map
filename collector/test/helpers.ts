import type { Origin } from "../src/ingest";
import type { ProbeReport, TargetResult } from "../src/report";
import { TARGETS } from "../src/targets";

const OK_HTTP = { bytes: 65536, status: 200, ms: 400, complete: true };

/** A plausible report: every target open, except the overrides. */
export function makeReport(overrides: Record<string, Partial<TargetResult>> = {}, patch: Partial<ProbeReport> = {}): ProbeReport {
  const results = TARGETS.map((t): TargetResult => {
    const base: TargetResult =
      t.kind === "ip" ? { t: t.id, tcp: "ok" } : { t: t.id, dns: "ok", tcp: "ok", tls: "ok", http: { ...OK_HTTP } };
    return { ...base, ...overrides[t.id] };
  });
  return {
    v: 1,
    client: "probe-cli/0.1.0",
    targets_ver: 1,
    net: "home",
    ts: "2026-11-16T14:00Z",
    env: { vpn_adapter: false, dpi_bypass: false, nic: true },
    results,
    ...patch,
  };
}

export function origin(n: number, patch: Partial<Origin> = {}): Origin {
  return { ip: `203.0.113.${n}`, asn: 12389, asOrg: "Rostelecom", country: "RU", region: "MOW", ...patch };
}

export const SNI_BLOCK: Partial<TargetResult> = { tls: "timeout", tls_ctrl: "ok", http: undefined };
