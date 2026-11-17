using System.Reflection;
using System.Text.Json;
using Detour.NetProbe;

namespace Detour.NetProbe.Cli;

/// <summary><c>detour-probe tune &lt;domain&gt;</c>: finds a zapret (winws) or ByeDPI strategy that opens a site.</summary>
internal static class TuneCommand
{
    private const string Help = """
        detour-probe tune <domain> --winws PATH | --byedpi PATH — find a DPI bypass strategy that opens a site.
        First traces the site (see trace --help) to rule out what can't help, then starts the bypass with one
        strategy after another and checks each the way a browser connects. Prints the best one, ready to paste.

          --winws PATH      zapret's winws.exe (needs admin rights; files like tls_clienthello_*.bin next to it)
          --byedpi PATH     ByeDPI's ciadpi.exe (no admin rights; runs as a local proxy on 127.0.0.1)
          --all             try every strategy and rank them (default: stop at the first that works)
          --repeats N       attempts per strategy (default 2; a strategy works when all pass)
          --skip-trace      don't trace first: try every strategy class
          --force           tune even if the trace says nothing can help or nothing is blocked
          --yes             don't ask before starting winws
          --json            print the report as JSON
          --out FILE        also save the JSON report to FILE

        winws only touches TCP 443 to this one domain, on the physical network card; it is stopped after each
        strategy and when the command ends. Stop zapret, GoodbyeDPI or ByeDPI before tuning.
        """;

    public static async Task<int> RunAsync(string[] args)
    {
        string? host = null, winws = null, byedpi = null, outFile = null;
        var all = false;
        var skipTrace = false;
        var force = false;
        var yes = false;
        var json = false;
        var repeats = 2;
        for (var i = 0; i < args.Length; i++)
        {
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            switch (args[i])
            {
                case "--winws": winws = Next(); break;
                case "--byedpi": byedpi = Next(); break;
                case "--all": all = true; break;
                case "--skip-trace": skipTrace = true; break;
                case "--force": force = true; break;
                case "--yes" or "-y": yes = true; break;
                case "--json": json = true; break;
                case "--out" or "-o": outFile = Next(); break;
                case "--repeats":
                    if (!int.TryParse(Next(), out repeats) || repeats is < 1 or > 10)
                    {
                        Console.Error.WriteLine("--repeats needs a number from 1 to 10.");
                        return 2;
                    }
                    break;
                case "--help" or "-h" or "/?": Console.WriteLine(Help); return 0;
                default:
                    if (args[i].StartsWith('-') || host is not null)
                    {
                        Console.Error.WriteLine($"Unknown argument {args[i]}. See tune --help.");
                        return 2;
                    }
                    host = args[i];
                    break;
            }
        }
        host = TraceCommand.NormalizeHost(host);
        if (host is null)
        {
            Console.Error.WriteLine("Give a domain: detour-probe tune rutracker.org --winws C:\\zapret\\bin\\winws.exe");
            return 2;
        }
        if ((winws is null) == (byedpi is null))
        {
            Console.Error.WriteLine("Give exactly one engine: --winws PATH (zapret) or --byedpi PATH (ByeDPI's ciadpi.exe).");
            return 2;
        }
        var exe = winws ?? byedpi!;
        if (!File.Exists(exe))
        {
            Console.Error.WriteLine($"Not found: {exe}");
            return 2;
        }
        if (winws is not null && OperatingSystem.IsWindows() && !Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("winws needs administrator rights: run the terminal as administrator.");
            return 2;
        }
        if (Prober.DpiBypassRunning())
        {
            Console.Error.WriteLine("A DPI bypass (zapret / GoodbyeDPI / ByeDPI…) is already running: two at once conflict and hide the result. Stop it first.");
            return 3;
        }

        var nic = NicInfo.Detect();
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0";
        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

        TraceReport? trace = null;
        if (!skipTrace)
        {
            if (!json)
            {
                Console.Error.Write($"Tracing {host}…");
            }
            trace = await Tracer.TraceAsync(host, new TraceOptions { Tool = $"detour-trace/{version}", Nic = nic }, cancel.Token);
            if (!json)
            {
                Console.Error.Write("\r" + new string(' ', 60) + "\r");
                foreach (var f in trace.Findings.Where(f => f.Severity is Severity.Block))
                {
                    Console.WriteLine($"  trace: {f.Title}");
                }
            }
        }

        var plan = TunePlanner.Plan(trace);
        if (plan.StopCode is not null && !force)
        {
            // Nothing to start: say why without asking about winws first.
            return Finish(new TuneReport
            {
                Tool = $"detour-tune/{version}", Host = host, Ts = trace?.Ts ?? "", Engine = winws is null ? "byedpi" : "winws",
                Trace = trace?.Findings.Select(f => f.Code).ToList() ?? [], StopCode = plan.StopCode, StopReason = plan.StopReason, Notes = plan.Notes,
            }, json, outFile);
        }

        await using ITuneEngine engine = winws is not null
            ? new WinwsEngine(winws, nic?.IfIndex ?? 0)
            : new ByeDpiEngine(byedpi!, nic?.Address);
        var count = plan.StopCode is null ? plan.Pick(engine.Catalog).Count(engine.CanRun) : engine.Catalog.Count(engine.CanRun);
        if (winws is not null && !yes)
        {
            Console.WriteLine();
            Console.WriteLine($"  This starts winws.exe (the WinDivert driver) up to {count} times, for TCP 443 to {host} only,");
            Console.WriteLine($"  on network card \"{nic?.Name ?? "default"}\". Other traffic is untouched; winws is stopped at the end.");
            if (Console.IsInputRedirected)
            {
                Console.Error.WriteLine("  Pass --yes to confirm when input is redirected.");
                return 2;
            }
            Console.Write("  Continue? [y/N] ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() is not ("y" or "yes" or "д" or "да"))
            {
                return 2;
            }
        }
        // Ctrl+C or closing the window must not leave winws running.
        AppDomain.CurrentDomain.ProcessExit += (_, _) => engine.StopAsync().GetAwaiter().GetResult();

        if (!json)
        {
            Console.WriteLine();
            Console.WriteLine($"  {"strategy",-24} {"result",-8} time");
        }
        TuneReport report;
        try
        {
            report = await Tuner.TuneAsync(host, engine, new TuneOptions
            {
                Tool = $"detour-tune/{version}",
                Nic = nic,
                Trace = trace,
                Repeats = repeats,
                All = all,
                Force = force,
                Starting = json ? null : new SyncProgress<TuneCandidate>(c => Console.Write($"  {c.Name,-24} …")),
                Progress = json ? null : new SyncProgress<TuneResult>(PrintRow),
            }, cancel.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("\n  Stopped.");
            return 130;
        }
        return Finish(report, json, outFile);
    }

    private static int Finish(TuneReport report, bool json, string? outFile)
    {
        var text = JsonSerializer.Serialize(report, new ProbeJson(new JsonSerializerOptions(ProbeJson.Default.Options) { WriteIndented = true }).TuneReport);
        if (outFile is not null)
        {
            File.WriteAllText(outFile, text);
        }
        if (json)
        {
            Console.WriteLine(text);
        }
        else
        {
            Console.WriteLine();
            if (report.StopReason is not null)
            {
                Console.WriteLine($"  {report.StopReason}");
            }
            foreach (var n in report.Notes)
            {
                Console.WriteLine($"  Note: {n}");
            }
            if (report.Best is not null)
            {
                Console.WriteLine();
                Console.WriteLine($"  Best: {report.Best}{(report.Stable ? "" : " (unstable)")}");
                Console.WriteLine($"  {report.Export}");
            }
            else if (report.StopCode is null)
            {
                Console.WriteLine("  No strategy got through. A VPN is the way for this site.");
            }
        }
        return report.Best is not null ? 0 : report.StopCode is "open" or "dns_substitution" or "http_block_page" ? 0 : 1;
    }

    private static void PrintRow(TuneResult r)
    {
        var text = r.Error is not null ? "error" : $"{r.Passed}/{r.Total}";
        var time = r.Passed > 0 ? $"{r.Ms} ms" : r.Error ?? r.Failure ?? "";
        Console.Write($"\r  {r.Name,-24} ");
        var color = r.Error is not null ? ConsoleColor.Yellow : r.Works ? ConsoleColor.Green : r.Passed > 0 ? ConsoleColor.Yellow : ConsoleColor.Red;
        if (Console.IsOutputRedirected)
        {
            Console.Write($"{text,-8}");
        }
        else
        {
            var old = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.Write($"{text,-8}");
            Console.ForegroundColor = old;
        }
        Console.WriteLine($" {time}");
    }

    /// <summary>Progress&lt;T&gt; posts to the thread pool, so rows could print out of order; this calls back inline.</summary>
    private sealed class SyncProgress<T>(Action<T> action) : IProgress<T>
    {
        public void Report(T value) => action(value);
    }
}
