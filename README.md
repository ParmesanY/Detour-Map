# Detour Map

A crowdsourced map of internet blocks in Russia: what is blocked, by which ISP, in which region, and how
(DNS stubs, IP blocks, SNI filtering, the "16 KB freeze" on foreign hosting, QUIC drops, throttling).
Part of the [Detour](https://github.com/) family. Plan: [docs/PLAN.md](docs/PLAN.md) (in Russian).

Status: **M1, the probe**. The collector and the map site are next.

## detour-probe

A command-line probe. It changes nothing on the computer and, for now, sends nothing anywhere: it prints a
table and saves a JSON report. The report holds no IP address: only per-target outcomes, the hour, and whether a
VPN or a DPI bypass was running.

```
dotnet run --project probe/Detour.NetProbe.Cli -- --net home
dotnet run --project probe/Detour.NetProbe.Cli -- --only youtube,discord,x --json
```

Each connection is bound to the physical network card, so a running VPN doesn't hide the ISP. A DPI bypass
(zapret, GoodbyeDPI, ByeDPI) does: stop it before probing.

Per target: the ISP's DNS answer vs DoH → TCP to the real address → TLS with the real SNI (and, if that fails,
with a neutral SNI on the same address, to tell SNI filtering from an IP block) → a 64 KB download → a QUIC
handshake. Rules turning these into verdicts: `probe/Detour.NetProbe/Verdicts.cs`, examples in
`spec/verdict-cases.json`.

## Layout

- `probe/Detour.NetProbe`: the measurement library (also used by the Detour client)
- `probe/Detour.NetProbe.Cli`: `detour-probe`
- `probe/Detour.NetProbe.Tests`: tests (`dotnet test --project probe/Detour.NetProbe.Tests`)
- `spec/targets.json`: what is probed; `spec/verdict-cases.json`: verdict examples shared with the collector
