using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Detour.NetProbe;

public sealed class ProbeOptions
{
    /// <summary>"detour/7.25.6", "probe-cli/0.1.0".</summary>
    public required string Client { get; init; }
    /// <summary>"home" or "mobile".</summary>
    public string Net { get; init; } = "home";
    public TargetList Targets { get; init; } = TargetList.Default;
    /// <summary>Only these target IDs (null = all).</summary>
    public IReadOnlySet<string>? Only { get; init; }
    public int Parallel { get; init; } = 4;
    /// <summary>Overrides the detected physical card (null = detect).</summary>
    public NicInfo? Nic { get; init; }
    /// <summary>The neutral SNI of the control handshake: a name no one blocks.</summary>
    public string ControlSni { get; init; } = "example.com";
    /// <summary>Reports each finished target.</summary>
    public IProgress<TargetResult>? Progress { get; init; }
}

/// <summary>Runs the measurements of a target list and builds the report.</summary>
public static class Prober
{
    private static readonly TimeSpan _connectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan _tlsTimeout = TimeSpan.FromSeconds(6);
    private static readonly TimeSpan _httpTimeout = TimeSpan.FromSeconds(8);
    public const int MaxBytes = 64 * 1024;

    private static readonly string[] _dpiBypassProcesses =
        ["winws", "goodbyedpi", "byedpi", "ciadpi", "zapret", "tpws", "nfqws", "spoofdpi"];

    public static ProbeEnv DetectEnv(NicInfo? nic) => new()
    {
        VpnAdapter = NicInfo.VpnAdapterUp(),
        DpiBypass = DpiBypassRunning(),
        Nic = nic is not null,
    };

    public static bool DpiBypassRunning()
    {
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (_dpiBypassProcesses.Contains(p.ProcessName.ToLowerInvariant()))
                    {
                        return true;
                    }
                }
                catch (InvalidOperationException)
                {
                    // exited meanwhile
                }
            }
        }
        return false;
    }

    public static async Task<ProbeReport> RunAsync(ProbeOptions options, CancellationToken ct = default)
    {
        var nic = options.Nic ?? NicInfo.Detect();
        var env = DetectEnv(nic);
        var targets = options.Targets.Targets.Where(t => options.Only is null || options.Only.Contains(t.Id)).ToList();
        using var doh = new DohResolver(nic?.Address);
        var ctx = new Context(nic, doh, options.ControlSni);
        using var gate = new SemaphoreSlim(Math.Max(1, options.Parallel));
        var results = await Task.WhenAll(targets.Select(async t =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var r = await ProbeTargetAsync(t, ctx, ct);
                options.Progress?.Report(r);
                return r;
            }
            finally
            {
                gate.Release();
            }
        }));
        var now = DateTime.UtcNow;
        return new ProbeReport
        {
            Client = options.Client,
            TargetsVer = options.Targets.Version,
            Net = options.Net,
            Ts = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm'Z'", CultureInfo.InvariantCulture),
            Env = env,
            Results = [.. results],
        };
    }

    public sealed record Context(NicInfo? Nic, DohResolver Doh, string ControlSni)
    {
        public IPAddress? Local => Nic?.Address;
    }

    public static async Task<TargetResult> ProbeTargetAsync(Target t, Context ctx, CancellationToken ct)
    {
        var r = new TargetResult { T = t.Id };
        IPAddress? ip = t.Ip is null ? null : IPAddress.Parse(t.Ip);
        if (ip is null && t.Host is not null)
        {
            var dohTask = ctx.Doh.ResolveAsync(t.Host, ct);
            var isp = await QueryIspAsync(t.Host, ctx, ct);
            var doh = await dohTask;
            r.Dns = UdpDns.Classify(isp, doh ?? []);
            if (r.Dns is Outcome.Stub or Outcome.Diff)
            {
                r.DnsIp = isp!.Addresses[0].ToString();
            }
            // The real address; the ISP's only when DoH is unreachable and its answer isn't a stub.
            ip = doh?.FirstOrDefault() ?? (r.Dns == Outcome.Ok ? isp!.Addresses[0] : null);
        }
        if (ip is null)
        {
            return r;
        }

        var (tcp, socket) = await TcpAsync(ip, t.Port, ctx.Local, ct);
        r.Tcp = tcp;
        if (socket is null)
        {
            return r;
        }
        if (!t.Tls || t.Host is null)
        {
            socket.Dispose();
            return r;
        }

        await using (var stream = new NetworkStream(socket, true))
        {
            var (tls, ssl) = await TlsAsync(stream, t.Host, ct);
            r.Tls = tls;
            if (ssl is not null)
            {
                await using (ssl)
                {
                    r.Http = await HttpAsync(ssl, t.Host, t.Path, ct);
                }
            }
        }

        if (r.Tls is Outcome.Reset or Outcome.Timeout)
        {
            // Same address, a name no one blocks: passes → the filter looks at the SNI; fails → the address is blocked.
            var (tcp2, socket2) = await TcpAsync(ip, t.Port, ctx.Local, ct);
            if (socket2 is null)
            {
                r.TlsCtrl = tcp2;
            }
            else
            {
                await using var stream2 = new NetworkStream(socket2, true);
                var (ctrl, ssl2) = await TlsAsync(stream2, ctx.ControlSni, ct);
                r.TlsCtrl = ctrl;
                if (ssl2 is not null)
                {
                    await ssl2.DisposeAsync();
                }
            }
        }

        if (t.Quic)
        {
            r.Quic = await QuicProbe.RunAsync(ip, t.Host, ctx.Local, ct);
        }
        return r;
    }

    private static async Task<DnsAnswer?> QueryIspAsync(string host, Context ctx, CancellationToken ct)
    {
        foreach (var server in ctx.Nic?.DnsServers ?? [])
        {
            if (await UdpDns.QueryAsync(server, host, ctx.Local, ct) is { } answer)
            {
                return answer;
            }
        }
        if (ctx.Nic is not null && ctx.Nic.DnsServers.Count > 0)
        {
            return null;
        }
        // No resolver known for the card: the system one (only correct without a VPN).
        try
        {
            return new DnsAnswer(0, await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct));
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
        {
            return new DnsAnswer(3, []);
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private static async Task<(string Outcome, Socket? Socket)> TcpAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_connectTimeout);
        try
        {
            return (Outcome.Ok, await NetUtil.ConnectAsync(ip, port, local, cts.Token));
        }
        catch (Exception ex) when (ex is SocketException or IOException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return (NetUtil.Classify(ex, cts.IsCancellationRequested), null);
        }
    }

    private static async Task<(string Outcome, SslStream? Stream)> TlsAsync(Stream stream, string sni, CancellationToken ct)
    {
        var ssl = new SslStream(stream, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_tlsTimeout);
        try
        {
            // Certificates aren't checked: only reachability is measured, nothing private is sent.
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, cts.Token);
            return (Outcome.Ok, ssl);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException
                                       || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            await ssl.DisposeAsync();
            return (NetUtil.Classify(ex, cts.IsCancellationRequested), null);
        }
    }

    /// <summary>GET, read up to 64 KB. A transfer that stops after a few KB is the "16 KB freeze".</summary>
    private static async Task<HttpResult> HttpAsync(Stream ssl, string host, string path, CancellationToken ct)
    {
        var result = new HttpResult();
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_httpTimeout);
        var buffer = new byte[16384];
        try
        {
            var request = Encoding.ASCII.GetBytes(
                $"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0\r\n" +
                "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
            await ssl.WriteAsync(request, cts.Token);
            while (result.Bytes < MaxBytes)
            {
                var n = await ssl.ReadAsync(buffer, cts.Token);
                if (n == 0)
                {
                    break;
                }
                if (result.Bytes == 0)
                {
                    result.Status = ParseStatus(buffer.AsSpan(0, n));
                }
                result.Bytes = Math.Min(MaxBytes, result.Bytes + n);
            }
            result.Complete = true;
        }
        catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            result.Error = NetUtil.Classify(ex, cts.IsCancellationRequested);
        }
        result.Ms = sw.ElapsedMilliseconds;
        return result;
    }

    /// <summary>"HTTP/1.1 301 Moved" → 301.</summary>
    public static int? ParseStatus(ReadOnlySpan<byte> head)
    {
        var line = Encoding.ASCII.GetString(head[..Math.Min(head.Length, 16)]);
        return line.StartsWith("HTTP/", StringComparison.Ordinal) && line.Length >= 12
               && int.TryParse(line.AsSpan(9, 3), NumberStyles.None, CultureInfo.InvariantCulture, out var code)
            ? code
            : null;
    }
}
