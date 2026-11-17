using System.Diagnostics;
using System.Globalization;
using System.Net;

namespace Detour.NetProbe;

public sealed class TuneOptions
{
    /// <summary>"detour-tune/0.1.0".</summary>
    public required string Tool { get; init; }
    public NicInfo? Nic { get; init; }
    /// <summary>The trace the plan is made from; null tries every class.</summary>
    public TraceReport? Trace { get; init; }
    /// <summary>Attempts per strategy; a strategy works when all pass.</summary>
    public int Repeats { get; init; } = 2;
    /// <summary>Try every strategy and rank them, instead of stopping at the first that works.</summary>
    public bool All { get; init; }
    /// <summary>Tune even when the plan says there is nothing to win (open site, address block).</summary>
    public bool Force { get; init; }
    /// <summary>Strategies the registry recommends for this ISP: tried first, each checked here like any other.</summary>
    public IReadOnlyList<StrategyHint>? Hints { get; init; }
    /// <summary>Called after each strategy (and the baseline) with its result.</summary>
    public IProgress<TuneResult>? Progress { get; init; }
    /// <summary>Called before each strategy starts.</summary>
    public IProgress<TuneCandidate>? Starting { get; init; }
}

/// <summary>
/// Picks a DPI bypass strategy for one site: the trace rules classes in or out, then each remaining strategy is
/// started, checked the way a browser connects (TLS with the real name, then 64 KB), and stopped again.
/// </summary>
public static class Tuner
{
    /// <summary>A strategy and a check are on the same address; rotating addresses keeps one punished address
    /// (TSPU blocks an address for a while after it saw a blocked name) from failing everything after it.</summary>
    private const int MaxIps = 3;

    public static async Task<TuneReport> TuneAsync(string host, ITuneEngine engine, TuneOptions options, CancellationToken ct = default)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        var nic = options.Nic ?? NicInfo.Detect();
        var local = nic?.Address;
        var now = DateTime.UtcNow;
        var report = new TuneReport
        {
            Tool = options.Tool,
            Host = host,
            Ts = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm'Z'", CultureInfo.InvariantCulture),
            Engine = engine.Name,
            Env = Prober.DetectEnv(nic),
            Trace = options.Trace?.Findings.Select(f => f.Code).ToList() ?? [],
        };

        var plan = TunePlanner.Plan(options.Trace);
        report.Notes.AddRange(plan.Notes);
        if (plan.StopCode is not null)
        {
            report.StopCode = plan.StopCode;
            report.StopReason = plan.StopReason;
            if (!options.Force)
            {
                return report;
            }
            plan = new TunePlan { Order = [.. StrategyClass.All] };
        }

        var ips = await ResolveAsync(host, options.Trace, local, ct);
        report.Ips.AddRange(ips.Select(a => a.ToString()));
        if (ips.Count == 0)
        {
            report.StopCode = "no_address";
            report.StopReason = "The site's name doesn't resolve even over DoH.";
            return report;
        }

        var direct = new DirectEngine();
        report.Baseline = await MeasureAsync(direct, new TuneCandidate("no bypass", "", []), host, ips, local, options.Repeats, ct);
        options.Progress?.Report(report.Baseline);
        if (report.Baseline.Works && !options.Force)
        {
            report.StopCode = "open";
            report.StopReason = "The site opens without any bypass right now: nothing to tune.";
            return report;
        }

        var hinted = Registry.Candidates(engine, options.Hints ?? []);
        if (hinted.Count > 0)
        {
            report.Notes.Add($"{hinted.Count} strategies from the registry for this ISP go first.");
        }
        var candidates = hinted.Concat(plan.Pick(engine.Catalog).Where(c => hinted.All(h => h.Name != c.Name))).ToList();
        report.Hinted = [.. hinted.Select(c => c.Name)];
        var missing = candidates.Count(c => !engine.CanRun(c));
        if (missing > 0)
        {
            report.Notes.Add($"{missing} strategies skipped: their files aren't next to {engine.Name}.");
        }
        await RunCandidatesAsync(engine, candidates.Where(engine.CanRun), host,
            c => MeasureAsync(engine, c, host, ips, local, options.Repeats, ct), options, report.Results, ct);

        var best = TuneReport.Rank(report.Results);
        if (best is not null)
        {
            report.Best = best.Name;
            report.Stable = best.Works;
            report.Export = engine.Export(candidates.First(c => c.Name == best.Name), host);
            if (!best.Works)
            {
                report.Notes.Add($"No strategy passed every attempt; {best.Name} passed {best.Passed} of {best.Total}.");
            }
        }
        return report;
    }

    /// <summary>Start, measure, stop, one candidate after another; stops at the first that works unless <see cref="TuneOptions.All" />.
    /// The engine is stopped in the end whatever happens.</summary>
    internal static async Task RunCandidatesAsync(ITuneEngine engine, IEnumerable<TuneCandidate> candidates, string host,
        Func<TuneCandidate, Task<TuneResult>> measure, TuneOptions options, List<TuneResult> results, CancellationToken ct)
    {
        try
        {
            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested();
                options.Starting?.Report(candidate);
                var error = await engine.StartAsync(candidate, host, ct);
                TuneResult result;
                if (error is not null)
                {
                    result = new TuneResult { Name = candidate.Name, Class = candidate.Class, Args = candidate.ArgLine, Error = error };
                }
                else
                {
                    result = await measure(candidate);
                    await engine.StopAsync();
                }
                results.Add(result);
                options.Progress?.Report(result);
                if (result.Works && !options.All)
                {
                    break;
                }
            }
        }
        finally
        {
            await engine.StopAsync();
        }
    }

    /// <summary>Runs <paramref name="repeats" /> checks through the engine (which is already running).</summary>
    public static async Task<TuneResult> MeasureAsync(ITuneEngine engine, TuneCandidate candidate, string host, IReadOnlyList<IPAddress> ips,
        IPAddress? local, int repeats, CancellationToken ct)
    {
        var result = new TuneResult
        {
            Name = candidate.Name,
            Class = candidate.Class.Length > 0 ? candidate.Class : null,
            Args = candidate.Args.Length > 0 ? candidate.ArgLine : null,
        };
        long okMs = 0;
        for (var i = 0; i < repeats; i++)
        {
            var ip = ips[i % ips.Count];
            var sw = Stopwatch.StartNew();
            var outcome = await CheckAsync(engine, ip, host, local, ct);
            result.Total++;
            if (outcome == Outcome.Ok)
            {
                result.Passed++;
                okMs += sw.ElapsedMilliseconds;
            }
            else
            {
                result.Failure = outcome;
            }
        }
        result.Ms = result.Passed > 0 ? okMs / result.Passed : 0;
        return result;
    }

    /// <summary>Connect, TLS with the real name, 64 KB: ok, or how it failed.</summary>
    private static async Task<string> CheckAsync(ITuneEngine engine, IPAddress ip, string host, IPAddress? local, CancellationToken ct)
    {
        var (tcp, stream) = await engine.ConnectAsync(ip, 443, local, ct);
        if (stream is null)
        {
            return tcp;
        }
        await using (stream)
        {
            var (tls, ssl) = await Prober.TlsAsync(stream, host, ct);
            if (ssl is null)
            {
                return tls;
            }
            await using (ssl)
            {
                var http = await Prober.HttpAsync(ssl, host, "/", ct);
                var verdict = Classifier.ClassifyHttp(http);
                if (verdict != Verdict.Ok)
                {
                    return verdict;
                }
                return http.Status is null ? Outcome.Error : Outcome.Ok;
            }
        }
    }

    private static async Task<List<IPAddress>> ResolveAsync(string host, TraceReport? trace, IPAddress? local, CancellationToken ct)
    {
        if (trace is not null && trace.Host == host && trace.Ips.Count > 0)
        {
            var parsed = trace.Ips.Select(s => IPAddress.TryParse(s, out var a) ? a : null).OfType<IPAddress>()
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Take(MaxIps).ToList();
            if (parsed.Count > 0)
            {
                return parsed;
            }
        }
        using var doh = new DohResolver(local);
        return [.. (await doh.ResolveAsync(host, ct) ?? []).Take(MaxIps)];
    }
}
