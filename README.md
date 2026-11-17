# Detour Map

A crowdsourced map of internet blocks in Russia: what is blocked, by which ISP, in which region, and how
(DNS stubs, IP blocks, SNI filtering, the "16 KB freeze" on foreign hosting, QUIC drops, throttling).
Part of the [Detour](https://github.com/) family. Plan: [docs/PLAN.md](docs/PLAN.md) (in Russian).

Status: the probe (M1), the collector (M2) and the map site (M3) work. A test instance runs at
https://detour-map-collector.detour-map-collector.workers.dev (may move to its own server later). Detour integration
is next.

## detour-probe

A command-line probe. It changes nothing on the computer: it prints a table and saves a JSON report, and sends
it to a collector only with `--send`. The report holds no IP address: only per-target outcomes, the hour, and
whether a VPN or a DPI bypass was running.

```
dotnet run --project probe/Detour.NetProbe.Cli -- --net home
dotnet run --project probe/Detour.NetProbe.Cli -- --only youtube,discord,x --json
dotnet run --project probe/Detour.NetProbe.Cli -- --send http://localhost:8787
```

### trace: how exactly one site is blocked

```
dotnet run --project probe/Detour.NetProbe.Cli -- trace x.com
dotnet run --project probe/Detour.NetProbe.Cli -- trace rutracker.org --markdown   # for a GitHub issue
```

Checks, in this order: the network (ya.ru), the ISP's DNS against DoH, TCP 443/80 to the real address, TLS with a
neutral name, the site's name sent to an unrelated server, a ClientHello split into TCP segments, TLS 1.3 and 1.2
alone, TLS as a browser does it plus a 64 KB download, plain HTTP for a block page, QUIC. The handshakes that don't
send the name in one piece go first: TSPU may punish an address for a while after it saw a blocked name.

Then it says what it found and what helps, e.g. "DPI by site name; a split ClientHello gets through, so zapret split
strategies should work", "IP block: needs a VPN", "freezes after ~16 KB". Output: colored text, `--json`, `--markdown`.
Exit code 1 when something is blocked. The report holds the site's addresses, never yours.

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

## site

The map: plain HTML/CSS/JS in `site/public`, served by the same Worker (static assets), so it talks only to its own
origin and loads nothing from third parties (strict CSP in `_headers`). Regions are pre-projected SVG paths in
`regions.json`, built from Natural Earth (public domain) with `site/tools/build-regions.mjs`; codes are ISO 3166-2,
the same as Cloudflare's `regionCode`.

To work on it locally with invented numbers: `cd collector`, `npm run seed:local` (local database only), `npm run dev`,
open http://localhost:8787.

## Layout

- `probe/Detour.NetProbe`: the measurement library (also used by the Detour client)
- `probe/Detour.NetProbe.Cli`: `detour-probe`
- `probe/Detour.NetProbe.Tests`: tests (`dotnet test --project probe/Detour.NetProbe.Tests`)
- `collector`: the Worker (TypeScript), D1 migrations, tests (vitest in workerd)
- `site`: the map site (`public/`) and the region geometry builder (`tools/`)
- `spec/targets.json`: what is probed; `spec/verdict-cases.json`: verdict examples shared by the C# and TS tests
