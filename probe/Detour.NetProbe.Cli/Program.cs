using System.Reflection;
using System.Text.Json;
using Detour.NetProbe;

// detour-probe: measures what the ISP blocks and how, prints a table and saves the JSON report.
// Sends it to a collector only when asked with --send.

var net = "home";
string? targetsFile = null;
string? outFile = null;
var jsonOnly = false;
var force = false;
HashSet<string>? only = null;
Uri? send = null;

for (var i = 0; i < args.Length; i++)
{
    string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} needs a value");
    switch (args[i])
    {
        case "--net": net = Next(); break;
        case "--targets": targetsFile = Next(); break;
        case "--out" or "-o": outFile = Next(); break;
        case "--only": only = [.. Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)]; break;
        case "--json": jsonOnly = true; break;
        case "--force": force = true; break;
        case "--send":
            if (!Uri.TryCreate(Next(), UriKind.Absolute, out send) || send.Scheme is not ("https" or "http"))
            {
                Console.Error.WriteLine("--send needs the collector's address, e.g. https://map.example.org");
                return 2;
            }
            break;
        case "--help" or "-h" or "/?":
            Console.WriteLine("""
                detour-probe — what your ISP blocks and how (DNS, IP, SNI, 16 KB freeze, QUIC, throttling).
                Changes nothing on the computer. Sends nothing anywhere unless --send is given.

                  --net home|mobile   connection type (default home)
                  --only id,id        only these targets
                  --targets FILE      own target list instead of the built-in one
                  --out FILE          where to save the JSON report (default detour-probe-report.json)
                  --json              print only the JSON report to stdout
                  --force             run even while a DPI bypass (zapret, GoodbyeDPI…) is running
                  --send URL          send the report to the Detour Map collector at URL
                                      (the collector sees your IP only to tell the ISP and region; it stores neither the IP nor the city)
                """);
            return 0;
        default:
            Console.Error.WriteLine($"Unknown argument {args[i]}. See --help.");
            return 2;
    }
}
if (net is not ("home" or "mobile"))
{
    Console.Error.WriteLine("--net must be home or mobile.");
    return 2;
}

var targets = targetsFile is null ? TargetList.Default : TargetList.Parse(File.ReadAllText(targetsFile));
var nic = NicInfo.Detect();
var env = Prober.DetectEnv(nic);
var log = jsonOnly ? Console.Error : Console.Out;

log.WriteLine(nic is null
    ? "Physical network card not found: probing through the default route."
    : $"Network card: {nic.Name}, ISP resolvers: {(nic.DnsServers.Count > 0 ? string.Join(", ", nic.DnsServers) : "none (system resolver)")}");
if (env.VpnAdapter)
{
    log.WriteLine(nic is null
        ? "WARNING: a VPN adapter is up and the physical card wasn't found; results will show the VPN, not the ISP."
        : "Note: a VPN adapter is up; probes are bound to the physical card and bypass it.");
}
if (env.DpiBypass)
{
    log.WriteLine("WARNING: a DPI bypass (zapret / GoodbyeDPI / ByeDPI…) is running: blocked sites will look open.");
    if (!force)
    {
        log.WriteLine("Stop it and run again, or pass --force.");
        return 3;
    }
}

var version = Assembly.GetExecutingAssembly().GetName().Version;
var count = only is null ? targets.Targets.Count : targets.Targets.Count(t => only.Contains(t.Id));
var done = 0;
using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

var report = await Prober.RunAsync(new ProbeOptions
{
    Client = $"probe-cli/{version?.ToString(3) ?? "0"}",
    Net = net,
    Targets = targets,
    Only = only,
    Nic = nic,
    Progress = new SyncProgress<TargetResult>(r => Console.Error.Write($"\r{Interlocked.Increment(ref done)}/{count} {r.T,-24}")),
}, cancel.Token);
Console.Error.Write("\r" + new string(' ', 40) + "\r");

var json = JsonSerializer.Serialize(report, new ProbeJson(new JsonSerializerOptions(ProbeJson.Default.Options) { WriteIndented = true }).ProbeReport);
if (jsonOnly)
{
    Console.WriteLine(json);
}
else
{
    var names = targets.Targets.ToDictionary(t => t.Id, t => t.Name);
    Console.WriteLine();
    Console.WriteLine($"{"Target",-20} {"DNS",-8} {"TCP",-8} {"TLS",-14} {"HTTP",-22} {"QUIC",-8} Verdict");
    Console.WriteLine(new string('-', 96));
    foreach (var r in report.Results)
    {
        var tls = r.Tls is null ? "" : r.TlsCtrl is null ? r.Tls : $"{r.Tls}/ctl {r.TlsCtrl}";
        var http = r.Http is null ? "" : $"{r.Http.Bytes / 1024.0:0.#} KB {r.Http.Ms} ms{(r.Http.Error is null ? "" : " " + r.Http.Error)}";
        var verdict = string.Join(", ", Classifier.Classify(r));
        Console.WriteLine($"{names.GetValueOrDefault(r.T, r.T),-20} {r.Dns,-8} {r.Tcp,-8} {tls,-14} {http,-22} {r.Quic,-8} {verdict}");
    }
    var flags = Classifier.ReportFlags(report, targets);
    if (flags.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("Report flags: " + string.Join(", ", flags));
    }
}

var path = outFile ?? "detour-probe-report.json";
File.WriteAllText(path, json);
log.WriteLine();
log.WriteLine($"Report saved to {Path.GetFullPath(path)} (no IP address in it).");

if (send is not null)
{
    try
    {
        var sent = await ReportSender.SendAsync(report, send, nic, cancel.Token);
        log.WriteLine(sent.Accepted
            ? $"Sent to {send.Host}: accepted{(sent.Flags is { Count: > 0 } f ? " (" + string.Join(", ", f) + ")" : "")}."
            : $"Sent to {send.Host}: refused, HTTP {sent.HttpStatus}: {sent.Error}");
        return sent.Accepted ? 0 : 4;
    }
    catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
    {
        log.WriteLine($"Couldn't send to {send.Host}: {ex.Message}");
        return 4;
    }
}
return 0;

/// <summary>Progress&lt;T&gt; posts to the thread pool; a console needs it in order.</summary>
internal sealed class SyncProgress<T>(Action<T> report) : IProgress<T>
{
    private readonly Lock _lock = new();

    public void Report(T value)
    {
        lock (_lock)
        {
            report(value);
        }
    }
}
