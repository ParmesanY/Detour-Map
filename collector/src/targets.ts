import spec from "../../spec/targets.json";

export type TargetKind = "control" | "hosting" | "site" | "ip";

export interface Target {
  id: string;
  name: string;
  kind: TargetKind;
  host?: string;
  ip?: string;
  port: number;
  path: string;
  tls: boolean;
  quic: boolean;
}

/** spec/targets.json with the probe's defaults filled in (the C# Target class has the same ones). */
export const TARGETS_VERSION: number = spec.version;
export const TARGETS: readonly Target[] = spec.targets.map((t) => {
  const raw = t as Partial<Target> & { id: string; name: string };
  return {
    id: raw.id,
    name: raw.name,
    kind: raw.kind ?? "site",
    host: raw.host,
    ip: raw.ip,
    port: raw.port ?? 443,
    path: raw.path ?? "/",
    tls: raw.tls ?? true,
    quic: raw.quic ?? false,
  };
});

export const TARGET_BY_ID: ReadonlyMap<string, Target> = new Map(TARGETS.map((t) => [t.id, t]));

/** Pseudo-target of the aggregates: share of reports in whitelist mode. */
export const WHITELIST_TARGET = "_whitelist";
