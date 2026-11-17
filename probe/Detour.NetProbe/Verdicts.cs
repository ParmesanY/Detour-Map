namespace Detour.NetProbe;

/// <summary>How a target is blocked, derived from the raw outcomes.</summary>
public static class Verdict
{
    public const string Ok = "ok";
    /// <summary>The ISP's DNS returns a stub, NXDOMAIN or nothing.</summary>
    public const string Dns = "dns";
    /// <summary>The address itself is unreachable, whatever the name.</summary>
    public const string Ip = "ip";
    /// <summary>DPI cuts the TLS handshake by the name in the SNI.</summary>
    public const string Sni = "sni";
    /// <summary>The connection freezes after ~16 KB (TSPU on foreign hosting).</summary>
    public const string Freeze = "freeze16k";
    /// <summary>The handshake passes but no data comes back.</summary>
    public const string Stall = "stall";
    /// <summary>Data flows, but very slowly.</summary>
    public const string Throttle = "throttle";
    /// <summary>QUIC (HTTP/3) is dropped while TCP works.</summary>
    public const string Quic = "quic";
    /// <summary>The server itself refused (TLS alert): not an ISP block.</summary>
    public const string Server = "server";
    /// <summary>Not enough data to tell.</summary>
    public const string Unknown = "unknown";
}

/// <summary>Flags about the whole run.</summary>
public static class ReportFlag
{
    /// <summary>The domestic control sites fail: no network, the run says nothing.</summary>
    public const string NoNetwork = "no_network";
    /// <summary>Domestic sites work but every foreign address is unreachable: whitelist mode (mobile).</summary>
    public const string Whitelist = "whitelist";
    /// <summary>A DPI bypass ran, or a VPN was up and the probe couldn't bind to the physical card.</summary>
    public const string Untrusted = "untrusted";
}

/// <summary>
/// Raw outcomes → verdicts. The collector runs the same rules (spec/verdict-cases.json keeps both in step),
/// so they can change without updating clients.
/// </summary>
public static class Classifier
{
    /// <summary>Below this a full 32+ KB transfer counts as throttled (kbit/s).</summary>
    public const int ThrottleKbps = 300;
    /// <summary>A transfer that stops below this many bytes is the "16 KB" freeze (TLS overhead and headers included).</summary>
    public const int FreezeMaxBytes = 40_000;

    public static List<string> Classify(TargetResult r)
    {
        var verdicts = new List<string>();
        if (r.Dns is Outcome.Stub or Outcome.NxDomain or Outcome.None)
        {
            verdicts.Add(Verdict.Dns);
        }

        if (r.Tcp is null)
        {
            // No address to try (DoH failed too) or not measured.
            return verdicts.Count > 0 ? verdicts : [Verdict.Unknown];
        }
        if (r.Tcp != Outcome.Ok)
        {
            verdicts.Add(Verdict.Ip);
            return verdicts;
        }

        switch (r.Tls)
        {
            case null:
                break; // TCP-only target
            case Outcome.Reset or Outcome.Timeout:
                verdicts.Add(r.TlsCtrl switch
                {
                    Outcome.Ok or Outcome.Alert => Verdict.Sni,
                    Outcome.Reset or Outcome.Timeout or Outcome.Refused => Verdict.Ip,
                    _ => Verdict.Unknown,
                });
                break;
            case Outcome.Alert:
                verdicts.Add(Verdict.Server);
                break;
            case Outcome.Ok:
                verdicts.Add(ClassifyHttp(r.Http));
                break;
            default:
                verdicts.Add(Verdict.Unknown);
                break;
        }

        if (r.Quic is Outcome.Timeout or Outcome.Reset && !verdicts.Contains(Verdict.Ip) && !verdicts.Contains(Verdict.Sni))
        {
            verdicts.Add(Verdict.Quic);
        }

        verdicts.Remove(Verdict.Ok);
        return verdicts.Count > 0 ? verdicts : [Verdict.Ok];
    }

    internal static string ClassifyHttp(HttpResult? h)
    {
        if (h is null)
        {
            return Verdict.Unknown;
        }
        if (!h.Complete && h.Error is Outcome.Timeout or Outcome.Reset)
        {
            return h.Bytes switch
            {
                0 => Verdict.Stall,
                < FreezeMaxBytes => Verdict.Freeze,
                _ => Verdict.Ok, // cut late: big enough to have passed the freeze
            };
        }
        if (h.Bytes >= 32 * 1024 && h.Ms > 0 && h.Bytes * 8L / h.Ms < ThrottleKbps)
        {
            return Verdict.Throttle;
        }
        return Verdict.Ok;
    }

    /// <summary>Flags of a whole report; <paramref name="targets" /> tells the kinds of the target IDs.</summary>
    public static List<string> ReportFlags(ProbeReport report, TargetList targets)
    {
        var flags = new List<string>();
        if (report.Env.DpiBypass || (report.Env.VpnAdapter && !report.Env.Nic))
        {
            flags.Add(ReportFlag.Untrusted);
        }
        var kinds = targets.Targets.ToDictionary(t => t.Id, t => t.Kind);
        string? KindOf(TargetResult r) => kinds.GetValueOrDefault(r.T);

        var control = report.Results.Where(r => KindOf(r) == TargetKind.Control).ToList();
        if (control.Count > 0 && control.All(r => !Reachable(r)))
        {
            flags.Add(ReportFlag.NoNetwork);
            return flags;
        }
        var foreign = report.Results.Where(r => KindOf(r) is TargetKind.Hosting or TargetKind.Ip).ToList();
        if (control.Count > 0 && foreign.Count >= 3 && foreign.All(r => !Reachable(r)))
        {
            flags.Add(ReportFlag.Whitelist);
        }
        return flags;
    }

    /// <summary>Connected (and, for TLS targets, finished the handshake).</summary>
    private static bool Reachable(TargetResult r) =>
        r.Tcp == Outcome.Ok && r.Tls is null or Outcome.Ok or Outcome.Alert;
}
