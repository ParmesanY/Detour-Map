using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Detour.NetProbe;

namespace Detour.NetProbe.Cli;

/// <summary><c>detour-probe trace &lt;domain&gt;</c>: how exactly one domain is blocked, with fixes.</summary>
internal static class TraceCommand
{
    private const string Help = """
        detour-probe trace <domain> — how exactly a site is blocked, and what helps.
        Checks DNS, the address, TLS by name, a split ClientHello, TLS 1.2/1.3, the 16 KB freeze,
        the ISP's HTTP block page and QUIC. Changes nothing on the computer, sends nothing anywhere.

          --json            print the report as JSON (for tools)
          --markdown        print the report as Markdown (for GitHub issues and forums)
          --out FILE        also save the JSON report to FILE
          --force           run even while a DPI bypass (zapret, GoodbyeDPI…) is running

        The report holds the site's addresses but never yours.
        """;

    private static readonly (string Id, string Label)[] _labels =
    [
        (TraceStep.Control, "Network (ya.ru)"),
        (TraceStep.DnsIsp, "DNS, ISP's resolver"),
        (TraceStep.DnsDoh, "DNS, DoH"),
        (TraceStep.Tcp443, "TCP 443"),
        (TraceStep.Tcp80, "TCP 80"),
        (TraceStep.TlsControl, "TLS, neutral name"),
        (TraceStep.TlsOtherServer, "TLS, name to other server"),
        (TraceStep.TlsSplit, "TLS, split ClientHello"),
        (TraceStep.Tls13, "TLS 1.3 only"),
        (TraceStep.Tls12, "TLS 1.2 only"),
        (TraceStep.TlsSni, "TLS, as a browser"),
        (TraceStep.HttpsGet, "HTTPS, 64 KB"),
        (TraceStep.HttpPlain, "HTTP, port 80"),
        (TraceStep.Quic, "QUIC / HTTP3"),
    ];

    public static async Task<int> RunAsync(string[] args)
    {
        string? host = null;
        string? outFile = null;
        var json = false;
        var markdown = false;
        var force = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--json": json = true; break;
                case "--markdown" or "--md": markdown = true; break;
                case "--force": force = true; break;
                case "--out" or "-o" when i + 1 < args.Length: outFile = args[++i]; break;
                case "--help" or "-h" or "/?": Console.WriteLine(Help); return 0;
                default:
                    if (args[i].StartsWith('-') || host is not null)
                    {
                        Console.Error.WriteLine($"Unknown argument {args[i]}. See trace --help.");
                        return 2;
                    }
                    host = args[i];
                    break;
            }
        }
        host = NormalizeHost(host);
        if (host is null)
        {
            Console.Error.WriteLine("Give a domain: detour-probe trace youtube.com");
            return 2;
        }

        var nic = NicInfo.Detect();
        if (!force && Prober.DpiBypassRunning())
        {
            Console.Error.WriteLine("A DPI bypass (zapret / GoodbyeDPI / ByeDPI…) is running: it would hide the ISP's blocks. Stop it, or pass --force.");
            return 3;
        }
        var quiet = json || markdown;
        if (!quiet)
        {
            Console.WriteLine($"Tracing {host} over {(nic is null ? "the default route" : $"network card \"{nic.Name}\"")}…");
        }
        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0";
        var report = await Tracer.TraceAsync(host, new TraceOptions
        {
            Tool = $"detour-trace/{version}",
            Nic = nic,
            Progress = quiet ? null : new Progress<string>(id => Console.Error.Write($"\r  {Label(id),-30}")),
        }, cancel.Token);
        if (!quiet)
        {
            Console.Error.Write("\r" + new string(' ', 40) + "\r");
        }

        var text = JsonSerializer.Serialize(report, new ProbeJson(new JsonSerializerOptions(ProbeJson.Default.Options) { WriteIndented = true }).TraceReport);
        if (outFile is not null)
        {
            File.WriteAllText(outFile, text);
        }
        if (json)
        {
            Console.WriteLine(text);
        }
        else if (markdown)
        {
            Console.WriteLine(Markdown(report));
        }
        else
        {
            PrintText(report);
        }
        return report.Findings.Any(f => f.Severity == Severity.Block) ? 1 : 0;
    }

    /// <summary>"https://www.YouTube.com/watch?v=1" → "www.youtube.com".</summary>
    public static string? NormalizeHost(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }
        var s = input.Trim();
        if (!s.Contains("://", StringComparison.Ordinal))
        {
            s = "https://" + s;
        }
        return Uri.TryCreate(s, UriKind.Absolute, out var uri) && uri.Host.Contains('.') ? uri.Host.ToLowerInvariant() : null;
    }

    private static string Label(string id) => _labels.FirstOrDefault(l => l.Id == id).Label ?? id;

    private static void PrintText(TraceReport r)
    {
        Console.WriteLine();
        foreach (var s in r.Steps)
        {
            Console.Write($"  {Label(s.Id),-28} ");
            WriteColored($"{s.Outcome,-11}", OutcomeColor(s));
            Console.WriteLine(s.Detail is null ? "" : $" {s.Detail}");
        }
        Console.WriteLine();
        foreach (var f in r.Findings)
        {
            var (mark, color) = f.Severity switch
            {
                Severity.Block => ("BLOCK", ConsoleColor.Red),
                Severity.Warn => ("WARN ", ConsoleColor.Yellow),
                Severity.Info => ("INFO ", ConsoleColor.Cyan),
                _ => ("OK   ", ConsoleColor.Green),
            };
            Console.Write("  ");
            WriteColored(mark, color);
            Console.WriteLine($" {f.Title}");
            if (f.Detail is not null)
            {
                Console.WriteLine($"        {f.Detail}");
            }
            if (f.Fix is not null)
            {
                WriteColored("        → ", ConsoleColor.DarkGray);
                Console.WriteLine(f.Fix);
            }
        }
        Console.WriteLine();
        Console.WriteLine("  For a bug report: detour-probe trace " + r.Host + " --markdown");
    }

    private static ConsoleColor OutcomeColor(TraceStepResult s) => s.Outcome switch
    {
        Outcome.Ok or Verdict.Ok => ConsoleColor.Green,
        Outcome.Alert or Outcome.Diff or Outcome.Unsupported or TraceOutcome.Skipped => ConsoleColor.Yellow,
        Outcome.Timeout when s.Id == TraceStep.DnsIsp => ConsoleColor.Yellow,
        _ => ConsoleColor.Red,
    };

    private static void WriteColored(string text, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = old;
    }

    /// <summary>For GitHub issues and forums: no IP of the reporter, only the site's.</summary>
    public static string Markdown(TraceReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"### Trace: `{r.Host}`");
        sb.AppendLine();
        sb.AppendLine($"`{r.Tool}` · {r.Ts} · {RuntimeInformation.OSDescription} · VPN up: {(r.Env.VpnAdapter ? "yes (bypassed)" : "no")} · DPI bypass running: {(r.Env.DpiBypass ? "**yes**" : "no")}");
        sb.AppendLine();
        foreach (var f in r.Findings)
        {
            var mark = f.Severity switch { Severity.Block => "🔴", Severity.Warn => "🟡", Severity.Info => "🔵", _ => "🟢" };
            sb.AppendLine($"- {mark} **{f.Title}**{(f.Detail is null ? "" : $" — {f.Detail}")}");
            if (f.Fix is not null)
            {
                sb.AppendLine($"  - Fix: {f.Fix}");
            }
        }
        sb.AppendLine();
        sb.AppendLine("| Check | Outcome | Detail | ms |");
        sb.AppendLine("|---|---|---|---:|");
        foreach (var s in r.Steps)
        {
            sb.AppendLine($"| {Label(s.Id)} | `{s.Outcome}` | {(s.Detail ?? "").Replace("|", "\\|")} | {s.Ms} |");
        }
        sb.AppendLine();
        sb.AppendLine("<sub>Made with detour-probe trace. Holds the site's addresses, not the reporter's.</sub>");
        return sb.ToString();
    }
}
