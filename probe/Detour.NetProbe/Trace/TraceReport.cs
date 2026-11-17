namespace Detour.NetProbe;

/// <summary>Step IDs of a trace, in the order they run.</summary>
public static class TraceStep
{
    /// <summary>A domestic site (ya.ru): is there a network at all.</summary>
    public const string Control = "net.control";
    public const string DnsIsp = "dns.isp";
    public const string DnsDoh = "dns.doh";
    public const string Tcp443 = "tcp.443";
    public const string Tcp80 = "tcp.80";
    /// <summary>TLS to the target's address with a neutral name.</summary>
    public const string TlsControl = "tls.control";
    /// <summary>TLS with the target's name to another, unrelated server: is the name cut anywhere?</summary>
    public const string TlsOtherServer = "tls.other_server";
    /// <summary>TLS with the target's name, ClientHello split into TCP segments: does DPI reassemble it?</summary>
    public const string TlsSplit = "tls.split";
    public const string Tls13 = "tls.v13";
    public const string Tls12 = "tls.v12";
    /// <summary>TLS with the target's name, as a browser does it.</summary>
    public const string TlsSni = "tls.sni";
    /// <summary>64 KB over HTTPS: the 16 KB freeze, silence after the handshake, throttling.</summary>
    public const string HttpsGet = "https.get";
    /// <summary>Plain HTTP on port 80: an ISP's block page.</summary>
    public const string HttpPlain = "http.plain";
    public const string Quic = "quic";
}

/// <summary>Step outcomes beyond <see cref="Outcome" />.</summary>
public static class TraceOutcome
{
    public const string BlockPage = "block_page";
    public const string Skipped = "skipped";
}

public sealed class TraceStepResult
{
    public required string Id { get; init; }
    /// <summary>An <see cref="Outcome" /> or <see cref="TraceOutcome" /> value; for https.get a <see cref="Verdict" />.</summary>
    public required string Outcome { get; init; }
    /// <summary>Short human detail: the ISP's answer, the server's address, "14.2 KB, then silence"…</summary>
    public string? Detail { get; init; }
    public long Ms { get; init; }
}

public static class Severity
{
    public const string Block = "block";
    public const string Warn = "warn";
    public const string Info = "info";
    public const string Ok = "ok";
}

/// <summary>One conclusion of the trace, with what to do about it.</summary>
public sealed class TraceFinding
{
    /// <summary>Stable code for tools: dns_substitution, sni_filter, ip_block, freeze16k…</summary>
    public required string Code { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public string? Detail { get; init; }
    public string? Fix { get; init; }
}

/// <summary>
/// "How exactly is this domain blocked?" The report holds the target's addresses (public servers) but never the
/// user's IP, so it can go straight into a bug report.
/// </summary>
public sealed class TraceReport
{
    public int V { get; set; } = 1;
    /// <summary>"detour-trace/0.1.0".</summary>
    public required string Tool { get; init; }
    public required string Host { get; init; }
    /// <summary>UTC hour, like probe reports.</summary>
    public required string Ts { get; init; }
    public required ProbeEnv Env { get; init; }
    /// <summary>The target's real addresses (DoH).</summary>
    public List<string> Ips { get; init; } = [];
    /// <summary>The address the trace connected to.</summary>
    public string? Ip { get; set; }
    public List<TraceStepResult> Steps { get; init; } = [];
    public HttpResult? Download { get; set; }
    public List<TraceFinding> Findings { get; set; } = [];

    public TraceStepResult? Step(string id) => Steps.FirstOrDefault(s => s.Id == id);

    public string? OutcomeOf(string id) => Step(id)?.Outcome;
}
