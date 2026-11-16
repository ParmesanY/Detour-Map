# spec

Files shared by the probe (C#) and the collector (TypeScript). Plain JSON, no comments: both sides import them as is.

## targets.json

What the probe measures. **Bump `version` on every change**: reports carry it. The collector knows only the current
list and drops results for unknown IDs, so keep IDs stable and never reuse one for a different host.

| Field | Meaning |
|---|---|
| `id` | stable ID, used in reports and on the map |
| `name` | display name |
| `kind` | `control` = domestic, never blocked (no network if it fails); `hosting` = a foreign test file (16 KB freeze, whitelist mode); `site` = a service (default); `ip` = bare address, TCP only |
| `host` / `ip` | what to probe; `ip` targets need `"tls": false` |
| `port`, `path` | default 443 and `/` |
| `tls` | default true |
| `quic` | also try a QUIC handshake |

## verdict-cases.json

Raw outcomes of one target → expected verdicts. `Detour.NetProbe.Tests` and the collector's tests both run them,
so the C# `Classifier` and `collector/src/verdicts.ts` stay identical.
