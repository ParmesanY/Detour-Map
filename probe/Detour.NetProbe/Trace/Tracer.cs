using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Detour.NetProbe;

public sealed class TraceOptions
{
    /// <summary>"detour-trace/0.1.0".</summary>
    public required string Tool { get; init; }
    public NicInfo? Nic { get; init; }
    /// <summary>A name no one blocks, for the control handshake.</summary>
    public string ControlSni { get; init; } = "example.com";
    /// <summary>An unrelated server that answers TLS for any name: does the target's name get cut there too?</summary>
    public IPAddress OtherServer { get; init; } = IPAddress.Parse("1.1.1.1");
    /// <summary>Domestic site that is never blocked: is there a network at all.</summary>
    public string ControlHost { get; init; } = "ya.ru";
    public IProgress<string>? Progress { get; init; }
}

/// <summary>
/// "How exactly is this domain blocked?" Runs every check against one host, all over the physical network card,
/// then <see cref="TraceDiagnosis" /> turns the outcomes into findings with fixes.
/// Order matters: TSPU may punish an address for a while after it saw a blocked name, so the handshakes that don't
/// send the real name in one piece (neutral name, other server, split ClientHello) run before the one that does.
/// </summary>
public static class Tracer
{
    private static readonly TimeSpan _plainHttpTimeout = TimeSpan.FromSeconds(6);

    public static async Task<TraceReport> TraceAsync(string host, TraceOptions options, CancellationToken ct = default)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        var nic = options.Nic ?? NicInfo.Detect();
        var local = nic?.Address;
        using var doh = new DohResolver(local);
        var ctx = new Prober.Context(nic, doh, options.ControlSni);
        var now = DateTime.UtcNow;
        var report = new TraceReport
        {
            Tool = options.Tool,
            Host = host,
            Ts = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm'Z'", CultureInfo.InvariantCulture),
            Env = Prober.DetectEnv(nic),
        };
        void Add(string id, string outcome, string? detail = null, long ms = 0)
        {
            report.Steps.Add(new TraceStepResult { Id = id, Outcome = outcome, Detail = detail, Ms = ms });
            options.Progress?.Report(id);
        }

        // Is there a network at all?
        var swControl = Stopwatch.StartNew();
        var controlIp = (await doh.ResolveAsync(options.ControlHost, ct))?.FirstOrDefault();
        if (controlIp is null)
        {
            Add(TraceStep.Control, Outcome.Error, "DoH unreachable", swControl.ElapsedMilliseconds);
        }
        else
        {
            var (outcome, socket) = await Prober.TcpAsync(controlIp, 443, local, ct);
            socket?.Dispose();
            Add(TraceStep.Control, outcome, options.ControlHost, swControl.ElapsedMilliseconds);
        }

        // DNS: the ISP's resolver against DoH.
        var swDns = Stopwatch.StartNew();
        var dohTask = doh.ResolveAsync(host, ct);
        var isp = await Prober.QueryIspAsync(host, ctx, ct);
        var dohIps = await dohTask;
        var dns = UdpDns.Classify(isp, dohIps ?? []);
        Add(TraceStep.DnsIsp, dns, isp?.Addresses.Length > 0 ? string.Join(", ", isp.Addresses.Take(3)) : null, swDns.ElapsedMilliseconds);
        Add(TraceStep.DnsDoh, dohIps is null ? Outcome.Error : dohIps.Length == 0 ? Outcome.None : Outcome.Ok,
            dohIps is { Length: > 0 } ? string.Join(", ", dohIps.Take(3)) : null);
        report.Ips.AddRange((dohIps ?? []).Select(a => a.ToString()));

        var ip = dohIps?.FirstOrDefault() ?? (dns == Outcome.Ok ? isp!.Addresses[0] : null);
        if (ip is null)
        {
            report.Findings = TraceDiagnosis.Diagnose(report);
            return report;
        }
        report.Ip = ip.ToString();

        var tcp443 = await TimedAsync(() => TcpOnlyAsync(ip, 443, local, ct));
        Add(TraceStep.Tcp443, tcp443.Value, report.Ip, tcp443.Ms);
        var tcp80 = await TimedAsync(() => TcpOnlyAsync(ip, 80, local, ct));
        Add(TraceStep.Tcp80, tcp80.Value, report.Ip, tcp80.Ms);

        if (tcp443.Value == Outcome.Ok)
        {
            var control = await TimedAsync(() => HandshakeAsync(ip, options.ControlSni, local, split: false, SslProtocols.Tls12 | SslProtocols.Tls13, ct));
            Add(TraceStep.TlsControl, control.Value, options.ControlSni, control.Ms);
            var other = await TimedAsync(() => HandshakeAsync(options.OtherServer, host, local, split: false, SslProtocols.Tls12 | SslProtocols.Tls13, ct));
            Add(TraceStep.TlsOtherServer, other.Value, options.OtherServer.ToString(), other.Ms);
            var split = await TimedAsync(() => HandshakeAsync(ip, host, local, split: true, SslProtocols.Tls12 | SslProtocols.Tls13, ct));
            Add(TraceStep.TlsSplit, split.Value, null, split.Ms);
            var v13 = await TimedAsync(() => HandshakeAsync(ip, host, local, split: false, SslProtocols.Tls13, ct));
            Add(TraceStep.Tls13, v13.Value, null, v13.Ms);
            var v12 = await TimedAsync(() => HandshakeAsync(ip, host, local, split: false, SslProtocols.Tls12, ct));
            Add(TraceStep.Tls12, v12.Value, null, v12.Ms);

            // The real thing, as a browser does it, then 64 KB over it.
            var sw = Stopwatch.StartNew();
            var (tcp, socket) = await Prober.TcpAsync(ip, 443, local, ct);
            if (socket is null)
            {
                Add(TraceStep.TlsSni, tcp, "TCP failed this time", sw.ElapsedMilliseconds);
            }
            else
            {
                await using var stream = new NetworkStream(socket, true);
                var (tls, ssl) = await Prober.TlsAsync(stream, host, ct);
                Add(TraceStep.TlsSni, tls, null, sw.ElapsedMilliseconds);
                if (ssl is not null)
                {
                    await using (ssl)
                    {
                        var http = await Prober.HttpAsync(ssl, host, "/", ct);
                        report.Download = http;
                        Add(TraceStep.HttpsGet, Classifier.ClassifyHttp(http), DescribeDownload(http), http.Ms);
                    }
                }
            }
        }

        if (tcp80.Value == Outcome.Ok)
        {
            var (outcome, detail, ms) = await PlainHttpAsync(ip, host, local, ct);
            Add(TraceStep.HttpPlain, outcome, detail, ms);
        }

        var quic = await TimedAsync(() => QuicProbe.RunAsync(ip, host, local, ct));
        Add(TraceStep.Quic, quic.Value, null, quic.Ms);

        report.Findings = TraceDiagnosis.Diagnose(report);
        return report;
    }

    private static async Task<(T Value, long Ms)> TimedAsync<T>(Func<Task<T>> step)
    {
        var sw = Stopwatch.StartNew();
        var value = await step();
        return (value, sw.ElapsedMilliseconds);
    }

    private static async Task<string> TcpOnlyAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        var (outcome, socket) = await Prober.TcpAsync(ip, port, local, ct);
        socket?.Dispose();
        return outcome;
    }

    /// <summary>A fresh connection and one TLS handshake; the TCP outcome if connecting already failed.</summary>
    private static async Task<string> HandshakeAsync(IPAddress ip, string sni, IPAddress? local, bool split, SslProtocols protocols, CancellationToken ct)
    {
        var (tcp, socket) = await Prober.TcpAsync(ip, 443, local, ct);
        if (socket is null)
        {
            return tcp;
        }
        Stream stream = new NetworkStream(socket, true);
        if (split)
        {
            stream = new SplitHelloStream(stream, sni, TimeSpan.FromMilliseconds(40));
        }
        await using (stream)
        {
            var (tls, ssl) = await Prober.TlsAsync(stream, sni, ct, protocols);
            if (ssl is not null)
            {
                await ssl.DisposeAsync();
            }
            return tls;
        }
    }

    private static async Task<(string Outcome, string? Detail, long Ms)> PlainHttpAsync(IPAddress ip, string host, IPAddress? local, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var (tcp, socket) = await Prober.TcpAsync(ip, 80, local, ct);
        if (socket is null)
        {
            return (tcp, null, sw.ElapsedMilliseconds);
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_plainHttpTimeout);
        await using var stream = new NetworkStream(socket, true);
        var buffer = new byte[16 * 1024];
        var read = 0;
        try
        {
            var request = Encoding.ASCII.GetBytes(
                $"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0\r\n" +
                "Accept: text/html\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(request, cts.Token);
            while (read < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(read), cts.Token);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            if (read == 0)
            {
                return (NetUtil.Classify(ex, cts.IsCancellationRequested), null, sw.ElapsedMilliseconds);
            }
        }
        if (read == 0)
        {
            return (Outcome.None, "empty answer", sw.ElapsedMilliseconds);
        }
        var answer = PlainHttp.Parse(buffer.AsSpan(0, read), host);
        var detail = answer.Location is null ? $"{answer.Status}" : $"{answer.Status} → {answer.Location}";
        return (answer.BlockPage ? TraceOutcome.BlockPage : Outcome.Ok, detail, sw.ElapsedMilliseconds);
    }

    private static string DescribeDownload(HttpResult h)
    {
        var kb = (h.Bytes / 1024.0).ToString("0.#", CultureInfo.InvariantCulture);
        var kbps = h.Ms > 0 ? h.Bytes * 8L / h.Ms : 0;
        return h.Complete
            ? $"{kb} KB in {h.Ms} ms ({kbps} kbit/s), HTTP {h.Status}"
            : $"{kb} KB, then {h.Error} after {h.Ms} ms";
    }
}
