namespace Detour.NetProbe;

/// <summary>Raw outcomes of single steps. Strings, not enums: the report is JSON read by other code.</summary>
public static class Outcome
{
    public const string Ok = "ok";
    public const string Timeout = "timeout";
    /// <summary>The connection was torn down: TCP reset, or closed with no TLS alert.</summary>
    public const string Reset = "rst";
    public const string Refused = "refused";
    /// <summary>TLS: the server itself refused the handshake with an alert (not what DPI does).</summary>
    public const string Alert = "alert";
    public const string Error = "error";
    /// <summary>DNS: a private / loopback / CGNAT / benchmark address, i.e. an ISP stub.</summary>
    public const string Stub = "stub";
    public const string NxDomain = "nx";
    /// <summary>DNS: an answer with no addresses.</summary>
    public const string None = "none";
    /// <summary>DNS: the ISP answer shares no address with DoH (a block page, or just a CDN picking another node).</summary>
    public const string Diff = "diff";
    public const string Unsupported = "unsupported";
}

/// <summary>
/// One probe run. Holds no IP address, host name or installation ID: the collector learns the ISP and
/// region from the connection the report arrives on and discards the address.
/// </summary>
public sealed class ProbeReport
{
    public int V { get; set; } = 1;
    /// <summary>"detour/7.25.6" or "probe-cli/0.1.0".</summary>
    public required string Client { get; init; }
    public int TargetsVer { get; init; }
    /// <summary>"home" or "mobile".</summary>
    public required string Net { get; init; }
    /// <summary>UTC hour of the run, "2026-11-16T14:00Z": coarse on purpose.</summary>
    public required string Ts { get; init; }
    public required ProbeEnv Env { get; init; }
    public required List<TargetResult> Results { get; init; }
}

/// <summary>What could spoil the measurement. Only flags, no adapter or process names.</summary>
public sealed class ProbeEnv
{
    /// <summary>A VPN / TUN adapter is up.</summary>
    public bool VpnAdapter { get; init; }
    /// <summary>A DPI bypass (zapret, GoodbyeDPI, ByeDPI…) is running: blocked sites would look open.</summary>
    public bool DpiBypass { get; init; }
    /// <summary>Probes were bound to the physical network card, so a VPN tunnel didn't carry them.</summary>
    public bool Nic { get; init; }
}

public sealed class TargetResult
{
    /// <summary>Target ID from the target list.</summary>
    public required string T { get; init; }
    /// <summary>ISP resolver vs DoH: ok / stub / nx / none / diff / timeout / error; null for IP-only targets.</summary>
    public string? Dns { get; set; }
    /// <summary>The ISP's answer when it is a stub or differs from DoH: identifies block pages.</summary>
    public string? DnsIp { get; set; }
    public string? Tcp { get; set; }
    /// <summary>TLS handshake with the target's own SNI.</summary>
    public string? Tls { get; set; }
    /// <summary>Same address, neutral SNI; only when <see cref="Tls" /> failed. Tells SNI filtering from an IP block.</summary>
    public string? TlsCtrl { get; set; }
    public HttpResult? Http { get; set; }
    public string? Quic { get; set; }
}

public sealed class HttpResult
{
    /// <summary>Decrypted bytes received (headers included), capped at 64 KB.</summary>
    public int Bytes { get; set; }
    public int? Status { get; set; }
    /// <summary>Request sent → last byte, or → the error.</summary>
    public long Ms { get; set; }
    /// <summary>The server closed the connection or 64 KB arrived.</summary>
    public bool Complete { get; set; }
    /// <summary>Why reading stopped early: timeout / rst / error.</summary>
    public string? Error { get; set; }
}
