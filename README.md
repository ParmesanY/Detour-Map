# Detour Map

A crowdsourced map of internet blocks in Russia: what is blocked, by which ISP, in which region, and how
(DNS stubs, IP blocks, SNI filtering, the "16 KB freeze" on foreign hosting, QUIC drops, throttling).
Part of the [Detour](https://github.com/) family. Plan: [docs/PLAN.md](docs/PLAN.md) (in Russian).

Status: the probe (M1) and the collector (M2) work. A test collector runs at
`https://detour-map-collector.detour-map-collector.workers.dev` (may move to its own server later). The map site is next.

## detour-probe

A command-line probe. It changes nothing on the computer: it prints a table and saves a JSON report, and sends
it to a collector only with `--send`. The report holds no IP address: only per-target outcomes, the hour, and
whether a VPN or a DPI bypass was running.

```
dotnet run --project probe/Detour.NetProbe.Cli -- --net home
dotnet run --project probe/Detour.NetProbe.Cli -- --only youtube,discord,x --json
dotnet run --project probe/Detour.NetProbe.Cli -- --send http://localhost:8787
```

Each connection is bound to the physical network card, so a running VPN doesn't hide the ISP. A DPI bypass
(zapret, GoodbyeDPI, ByeDPI) does: stop it before probing.

Per target: the ISP's DNS answer vs DoH → TCP to the real address → TLS with the real SNI (and, if that fails,
with a neutral SNI on the same address, to tell SNI filtering from an IP block) → a 64 KB download → a QUIC
handshake. Rules turning these into verdicts: `probe/Detour.NetProbe/Verdicts.cs`, examples in
`spec/verdict-cases.json`.

## collector

A Cloudflare Worker with a D1 database. It takes reports, learns the ISP (ASN) and region from the connection,
and never stores the IP: the address only becomes a day-long pseudonym (HMAC with a salt that is deleted when
the day is over) for rate limiting and for counting distinct reporters. A cron job rebuilds daily aggregates;
the read API shows a group only when at least 3 different people reported it.

```
cd collector
npm install
npm run db:migrate:local
npm run dev        # http://localhost:8787
npm test           # runs in workerd against a local D1
```

Deploy (once per Cloudflare account): `npx wrangler login --device`, `npx wrangler d1 create detour-map`
(put its id into `wrangler.jsonc`), `npx wrangler d1 migrations apply detour-map --remote`, `npx wrangler deploy`.

API: `POST /v1/report`, `GET /v1/targets`, `/v1/summary`, `/v1/map?target=`, `/v1/isps?target=`,
`/v1/history?target=` (details in [docs/PLAN.md](docs/PLAN.md)).

## Layout

- `probe/Detour.NetProbe`: the measurement library (also used by the Detour client)
- `probe/Detour.NetProbe.Cli`: `detour-probe`
- `probe/Detour.NetProbe.Tests`: tests (`dotnet test --project probe/Detour.NetProbe.Tests`)
- `collector`: the Worker (TypeScript), D1 migrations, tests (vitest in workerd)
- `spec/targets.json`: what is probed; `spec/verdict-cases.json`: verdict examples shared by the C# and TS tests
