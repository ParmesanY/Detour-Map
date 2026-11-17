using System.Globalization;

namespace Detour.NetProbe;

/// <summary>Trace step outcomes → findings with fixes. Pure: tests feed it hand-made reports.</summary>
public static class TraceDiagnosis
{
    private static bool Cut(string? outcome) => outcome is Outcome.Reset or Outcome.Timeout;

    private static bool Passed(string? outcome) => outcome is Outcome.Ok or Outcome.Alert;

    public static List<TraceFinding> Diagnose(TraceReport r)
    {
        var f = new List<TraceFinding>();
        var host = r.Host;

        if (r.Env.DpiBypass)
        {
            f.Add(new TraceFinding
            {
                Code = "bypass_running", Severity = Severity.Warn,
                Title = "A DPI bypass is running",
                Detail = "zapret, GoodbyeDPI or ByeDPI changes the traffic, so the results show what the bypass achieves, not what the ISP does.",
                Fix = "Stop the bypass for a clean trace.",
            });
        }
        if (r.Env.VpnAdapter && !r.Env.Nic)
        {
            f.Add(new TraceFinding
            {
                Code = "vpn_not_bypassed", Severity = Severity.Warn,
                Title = "A VPN is up and the physical network card wasn't found",
                Detail = "The checks may have gone through the VPN: the results describe the VPN's network, not the ISP's.",
                Fix = "Turn the VPN off and run the trace again.",
            });
        }

        if (!Passed(r.OutcomeOf(TraceStep.Control)))
        {
            f.Add(new TraceFinding
            {
                Code = "no_network", Severity = Severity.Block,
                Title = "No network",
                Detail = "Even ya.ru doesn't answer over the network card, so nothing below says anything about this site.",
                Fix = "Check the connection; on a mobile network this may also be a whitelist-only mode.",
            });
            return f;
        }

        // DNS
        var dns = r.Step(TraceStep.DnsIsp);
        var realIps = r.Ips.Count > 0 ? string.Join(", ", r.Ips.Take(3)) : "unknown";
        switch (dns?.Outcome)
        {
            case Outcome.Stub or Outcome.NxDomain or Outcome.None:
                f.Add(new TraceFinding
                {
                    Code = "dns_substitution", Severity = Severity.Block,
                    Title = "DNS substitution",
                    Detail = dns.Outcome == Outcome.NxDomain
                        ? $"The ISP's DNS says {host} doesn't exist; the real address is {realIps}."
                        : $"The ISP's DNS answers {dns.Detail ?? "nothing"} instead of the real {realIps}.",
                    Fix = "Use encrypted DNS (DoH/DoT): Detour does it by default; in a browser turn on Secure DNS.",
                });
                break;
            case Outcome.Diff:
                f.Add(new TraceFinding
                {
                    Code = "dns_differs", Severity = Severity.Info,
                    Title = "The ISP's DNS gives other addresses than DoH",
                    Detail = $"ISP: {dns.Detail}; DoH: {realIps}. Usually a CDN picking another node, sometimes a block page. The trace used DoH's address.",
                });
                break;
            case Outcome.Timeout:
                f.Add(new TraceFinding
                {
                    Code = "dns_unchecked", Severity = Severity.Info,
                    Title = "The ISP's DNS wasn't checked",
                    Detail = "It didn't answer over the network card (a VPN's TUN often blocks such UDP). The trace used DoH.",
                });
                break;
        }

        if (r.Ip is null)
        {
            f.Add(new TraceFinding
            {
                Code = "no_address", Severity = Severity.Warn,
                Title = "The real address is unknown",
                Detail = "Neither DoH nor the ISP's DNS gave a usable address, so the connection checks didn't run.",
                Fix = "Check the domain name; if DoH itself is blocked here, run the trace from another network.",
            });
            return Finish(f, host);
        }

        // Address
        var tcp443 = r.OutcomeOf(TraceStep.Tcp443);
        if (tcp443 != Outcome.Ok)
        {
            f.Add(r.OutcomeOf(TraceStep.Tcp80) == Outcome.Ok
                ? new TraceFinding
                {
                    Code = "port_block", Severity = Severity.Block,
                    Title = "Port 443 is blocked to this address",
                    Detail = $"{r.Ip}: port 443 {tcp443}, port 80 open.",
                    Fix = "Needs a VPN or proxy.",
                }
                : new TraceFinding
                {
                    Code = "ip_block", Severity = Severity.Block,
                    Title = "IP block",
                    Detail = $"{r.Ip} doesn't accept connections at all ({tcp443}), whatever the site name.",
                    Fix = "Needs a VPN or proxy: DPI tricks (zapret, ByeDPI) can't reach a blocked address.",
                });
            AddPlainHttp(f, r);
            return Finish(f, host);
        }

        // TLS
        var sni = r.OutcomeOf(TraceStep.TlsSni);
        var control = r.OutcomeOf(TraceStep.TlsControl);
        if (Cut(sni) && Passed(control))
        {
            var anywhere = Cut(r.OutcomeOf(TraceStep.TlsOtherServer));
            var split = r.OutcomeOf(TraceStep.TlsSplit);
            f.Add(new TraceFinding
            {
                Code = "sni_filter", Severity = Severity.Block,
                Title = "DPI by site name (SNI)",
                Detail = $"The handshake with the name {host} is cut ({sni}); the same address with a neutral name works."
                         + (anywhere ? " The name is cut on an unrelated server too: the filter looks only at the name." : ""),
                Fix = Passed(split)
                    ? "A ClientHello split into TCP segments gets through: DPI doesn't reassemble it. zapret / ByeDPI split strategies (split, multisplit, disorder) should work."
                    : "A split ClientHello is cut too: try fake-packet strategies (fake, fakedsplit) or a VPN.",
            });
        }
        else if (Cut(sni) && Cut(control))
        {
            f.Add(new TraceFinding
            {
                Code = "ip_block_tls", Severity = Severity.Block,
                Title = "Address blocked after connecting",
                Detail = $"TCP to {r.Ip} connects, but every TLS handshake is cut, whatever the name.",
                Fix = "Needs a VPN or proxy.",
            });
        }
        else if (sni == Outcome.Alert)
        {
            f.Add(new TraceFinding
            {
                Code = "server_refused", Severity = Severity.Info,
                Title = "The server itself refused TLS",
                Detail = "It answered with a TLS alert: not what DPI does.",
            });
        }
        else if (sni == Outcome.Ok)
        {
            var v13 = r.OutcomeOf(TraceStep.Tls13);
            var v12 = r.OutcomeOf(TraceStep.Tls12);
            if (Cut(v13) && Passed(v12) || Cut(v12) && Passed(v13))
            {
                f.Add(new TraceFinding
                {
                    Code = "tls_version", Severity = Severity.Info,
                    Title = Cut(v13) ? "Only TLS 1.3 is cut" : "Only TLS 1.2 is cut",
                    Detail = $"TLS 1.3: {v13}, TLS 1.2: {v12}. A browser negotiates the working one, some apps don't.",
                });
            }
            AddDownload(f, r);
        }
        else if (sni is not null)
        {
            f.Add(new TraceFinding
            {
                Code = "tls_error", Severity = Severity.Info,
                Title = "TLS failed for another reason",
                Detail = $"Outcome: {sni}.",
            });
        }

        AddPlainHttp(f, r);

        var quic = r.OutcomeOf(TraceStep.Quic);
        if (quic == Outcome.Ok && Cut(sni))
        {
            f.Add(new TraceFinding
            {
                Code = "quic_passes", Severity = Severity.Info,
                Title = "QUIC (HTTP/3) gets through where TCP is cut",
                Detail = "The filter looks at TLS over TCP only. A browser that already uses HTTP/3 for this site may still open it.",
                Fix = "Not reliable on its own (the first visit always goes over TCP), but a sign that UDP-based tunnels may pass here.",
            });
        }
        if (Cut(quic) && sni == Outcome.Ok)
        {
            f.Add(new TraceFinding
            {
                Code = "quic_block", Severity = Severity.Warn,
                Title = "QUIC (HTTP/3) is dropped",
                Detail = "Browsers fall back to TCP, so pages still open; apps that rely on QUIC/UDP may not.",
            });
        }

        return Finish(f, host);
    }

    private static void AddDownload(List<TraceFinding> f, TraceReport r)
    {
        var step = r.Step(TraceStep.HttpsGet);
        var kb = ((r.Download?.Bytes ?? 0) / 1024.0).ToString("0.#", CultureInfo.InvariantCulture);
        switch (step?.Outcome)
        {
            case Verdict.Freeze:
                f.Add(new TraceFinding
                {
                    Code = "freeze16k", Severity = Severity.Block,
                    Title = "The connection freezes after ~16 KB",
                    Detail = $"{kb} KB arrived, then nothing. TSPU does this to foreign hosting (Hetzner, OVH, DigitalOcean…): small pages open, anything bigger hangs.",
                    Fix = "zapret's DPI tricks don't lift it. A VPN whose server is on another hosting does.",
                });
                break;
            case Verdict.Stall:
                f.Add(new TraceFinding
                {
                    Code = "stall", Severity = Severity.Block,
                    Title = "Nothing comes back after the handshake",
                    Detail = "TLS completes, then the request gets no answer.",
                    Fix = "Try zapret strategies; if they don't help, a VPN.",
                });
                break;
            case Verdict.Throttle:
                f.Add(new TraceFinding
                {
                    Code = "throttle", Severity = Severity.Block,
                    Title = "Throttled",
                    Detail = step.Detail,
                    Fix = "zapret often lifts throttling by name (as with YouTube); otherwise a VPN.",
                });
                break;
        }
    }

    private static void AddPlainHttp(List<TraceFinding> f, TraceReport r)
    {
        var plain = r.Step(TraceStep.HttpPlain);
        if (plain?.Outcome == TraceOutcome.BlockPage)
        {
            f.Add(new TraceFinding
            {
                Code = "http_block_page", Severity = Severity.Block,
                Title = "The ISP answers plain HTTP with a block page",
                Detail = plain.Detail,
                Fix = "Open the site over HTTPS; the page itself confirms the site is in the registry.",
            });
        }
    }

    private static List<TraceFinding> Finish(List<TraceFinding> f, string host)
    {
        if (!f.Any(x => x.Severity == Severity.Block))
        {
            f.Add(new TraceFinding
            {
                Code = "open", Severity = Severity.Ok,
                Title = $"No blocking found for {host}",
                Detail = "DNS, connection, TLS and a 64 KB download all work over this network.",
            });
        }
        return [.. f.OrderBy(x => x.Severity switch { Severity.Block => 0, Severity.Warn => 1, Severity.Info => 2, _ => 3 })];
    }
}
