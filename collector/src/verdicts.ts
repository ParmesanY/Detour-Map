// Port of probe/Detour.NetProbe/Verdicts.cs. spec/verdict-cases.json is run by both test suites:
// change the rules in both places together.
import { TARGET_BY_ID } from "./targets";
import type { ProbeReport, TargetResult, HttpResult } from "./report";

export const Verdict = {
  Ok: "ok",
  Dns: "dns",
  Ip: "ip",
  Sni: "sni",
  Freeze: "freeze16k",
  Stall: "stall",
  Throttle: "throttle",
  Quic: "quic",
  Server: "server",
  Unknown: "unknown",
} as const;

export const ReportFlag = {
  NoNetwork: "no_network",
  Whitelist: "whitelist",
  Untrusted: "untrusted",
} as const;

/** Verdicts that mean the ISP blocks the target (QUIC-only drops don't count: the site still works). */
export const BLOCKING = [Verdict.Dns, Verdict.Ip, Verdict.Sni, Verdict.Freeze, Verdict.Stall, Verdict.Throttle] as const;

export const THROTTLE_KBPS = 300;
export const FREEZE_MAX_BYTES = 40_000;

export function classify(r: TargetResult): string[] {
  const verdicts: string[] = [];
  if (r.dns === "stub" || r.dns === "nx" || r.dns === "none") {
    verdicts.push(Verdict.Dns);
  }

  if (r.tcp == null) {
    return verdicts.length > 0 ? verdicts : [Verdict.Unknown];
  }
  if (r.tcp !== "ok") {
    verdicts.push(Verdict.Ip);
    return verdicts;
  }

  switch (r.tls) {
    case undefined:
    case null:
      break; // TCP-only target
    case "rst":
    case "timeout":
      verdicts.push(
        r.tls_ctrl === "ok" || r.tls_ctrl === "alert"
          ? Verdict.Sni
          : r.tls_ctrl === "rst" || r.tls_ctrl === "timeout" || r.tls_ctrl === "refused"
            ? Verdict.Ip
            : Verdict.Unknown,
      );
      break;
    case "alert":
      verdicts.push(Verdict.Server);
      break;
    case "ok":
      verdicts.push(classifyHttp(r.http));
      break;
    default:
      verdicts.push(Verdict.Unknown);
  }

  if ((r.quic === "timeout" || r.quic === "rst") && !verdicts.includes(Verdict.Ip) && !verdicts.includes(Verdict.Sni)) {
    verdicts.push(Verdict.Quic);
  }

  const result = verdicts.filter((v) => v !== Verdict.Ok);
  return result.length > 0 ? result : [Verdict.Ok];
}

function classifyHttp(h: HttpResult | undefined | null): string {
  if (h == null) {
    return Verdict.Unknown;
  }
  if (!h.complete && (h.error === "timeout" || h.error === "rst")) {
    return h.bytes === 0 ? Verdict.Stall : h.bytes < FREEZE_MAX_BYTES ? Verdict.Freeze : Verdict.Ok;
  }
  if (h.bytes >= 32 * 1024 && h.ms > 0 && Math.floor((h.bytes * 8) / h.ms) < THROTTLE_KBPS) {
    return Verdict.Throttle;
  }
  return Verdict.Ok;
}

/** Connected (and, for TLS targets, finished the handshake). */
function reachable(r: TargetResult): boolean {
  return r.tcp === "ok" && (r.tls == null || r.tls === "ok" || r.tls === "alert");
}

export function reportFlags(report: ProbeReport): string[] {
  const flags: string[] = [];
  if (report.env.dpi_bypass || (report.env.vpn_adapter && !report.env.nic)) {
    flags.push(ReportFlag.Untrusted);
  }
  const kindOf = (r: TargetResult) => TARGET_BY_ID.get(r.t)?.kind;
  const control = report.results.filter((r) => kindOf(r) === "control");
  if (control.length > 0 && control.every((r) => !reachable(r))) {
    flags.push(ReportFlag.NoNetwork);
    return flags;
  }
  const foreign = report.results.filter((r) => kindOf(r) === "hosting" || kindOf(r) === "ip");
  if (control.length > 0 && foreign.length >= 3 && foreign.every((r) => !reachable(r))) {
    flags.push(ReportFlag.Whitelist);
  }
  return flags;
}
