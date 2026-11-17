using System.Text.Json;

namespace Detour.NetProbe;

/// <summary>One strategy the registry recommends for the asking ISP.</summary>
public sealed class StrategyHint
{
    public string Id { get; set; } = "";
    public string Key { get; set; } = "";
    public string Args { get; set; } = "";
    public int Reporters { get; set; }
    public int Works { get; set; }
    public int Fails { get; set; }
    public double Score { get; set; }
    public long? Ms { get; set; }
}

public sealed class StrategyHints
{
    public string? Engine { get; set; }
    public long Asn { get; set; }
    public string? AsOrg { get; set; }
    public string? Target { get; set; }
    public List<StrategyHint> Strategies { get; set; } = [];
}

public sealed class StrategyBaseline
{
    public int Passed { get; set; }
    public int Total { get; set; }
}

public sealed class StrategyResultOut
{
    public required string Args { get; set; }
    public int Passed { get; set; }
    public int Total { get; set; }
    public long Ms { get; set; }
}

/// <summary>What a tune run tells the registry: the engine, the strategies and how they did. No site name: only a
/// target ID from the public list, or nothing.</summary>
public sealed class StrategyReport
{
    public int V { get; set; } = 1;
    public required string Client { get; set; }
    public required string Engine { get; set; }
    public required string Net { get; set; }
    public string? Target { get; set; }
    public required ProbeEnv Env { get; set; }
    public required StrategyBaseline Baseline { get; set; }
    public List<StrategyResultOut> Results { get; set; } = [];
}

/// <summary>
/// The strategy registry on the collector: <c>GET /v1/strategies</c> (best strategies for the asking ISP; the
/// collector reads the ISP from the connection, so the request goes over the physical card) and
/// <c>POST /v1/strategies</c> (a tune run's results).
/// </summary>
public static class Registry
{
    /// <summary>Fewer hints than this for one target: also ask for the ISP's strategies on any site.</summary>
    private const int EnoughHints = 3;

    /// <summary>Hints for this ISP; null when the registry can't be reached.</summary>
    public static async Task<StrategyHints?> GetHintsAsync(Uri endpoint, string engine, string? target, NicInfo? nic, CancellationToken ct = default)
    {
        using var doh = new DohResolver(nic?.Address);
        using var client = ReportSender.CreateClient(nic?.Address, doh);
        async Task<StrategyHints?> Get(string? t)
        {
            var path = $"/v1/strategies?engine={Uri.EscapeDataString(engine)}" + (t is null ? "" : $"&target={Uri.EscapeDataString(t)}");
            try
            {
                using var response = await client.GetAsync(new Uri(endpoint, path), ct);
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }
                return JsonSerializer.Deserialize(await response.Content.ReadAsStringAsync(ct), ProbeJson.Default.StrategyHints);
            }
            catch (Exception ex) when (ex is HttpRequestException or JsonException or IOException
                                           || (ex is OperationCanceledException && !ct.IsCancellationRequested))
            {
                return null;
            }
        }

        var hints = await Get(target);
        if (target is not null && (hints is null || hints.Strategies.Count < EnoughHints))
        {
            var any = await Get(null);
            if (any is not null)
            {
                if (hints is null)
                {
                    return any;
                }
                hints.Strategies.AddRange(any.Strategies.Where(s => hints.Strategies.All(h => h.Key != s.Key)));
            }
        }
        return hints;
    }

    /// <summary>The target ID of a host in the public list ("www.youtube.com" → "youtube"), or null.</summary>
    public static string? TargetIdForHost(string host, TargetList? targets = null)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        var bare = host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;
        return (targets ?? TargetList.Default).Targets.FirstOrDefault(t =>
        {
            if (t.Host is null)
            {
                return false;
            }
            var h = t.Host.ToLowerInvariant();
            return h == host || h == bare || h == "www." + bare;
        })?.Id;
    }

    /// <summary>The report for the registry; null when there is nothing worth sending (site wasn't blocked, nothing ran).</summary>
    public static StrategyReport? BuildReport(TuneReport tune, string client, string net)
    {
        if (tune.Baseline is not { Total: > 0 } baseline || baseline.Works || tune.Engine is not (StrategyKey.Winws or StrategyKey.ByeDpi))
        {
            return null;
        }
        var results = tune.Results
            .Where(r => r.Error is null && r.Total > 0 && r.Args is not null && StrategyKey.Normalize(tune.Engine, r.Args).Key is not null)
            .Select(r => new StrategyResultOut { Args = r.Args!, Passed = r.Passed, Total = r.Total, Ms = r.Ms })
            .ToList();
        if (results.Count == 0)
        {
            return null;
        }
        return new StrategyReport
        {
            Client = client,
            Engine = tune.Engine,
            Net = net,
            Target = TargetIdForHost(tune.Host),
            Env = tune.Env ?? new ProbeEnv(),
            Baseline = new StrategyBaseline { Passed = baseline.Passed, Total = baseline.Total },
            Results = results,
        };
    }

    public static Task<SendResult> SendAsync(StrategyReport report, Uri endpoint, NicInfo? nic, CancellationToken ct = default) =>
        ReportSender.PostAsync(endpoint, "/v1/strategies", JsonSerializer.Serialize(report, ProbeJson.Default.StrategyReport), nic, ct);

    /// <summary>
    /// Hints as candidates for <paramref name="engine" />: one that equals a built-in strategy becomes that strategy
    /// (same name, same class), others become "registry-&lt;id&gt;". Hints that don't normalize are dropped: nothing
    /// from the registry runs unless it passes the same allowlist as the collector's.
    /// </summary>
    public static List<TuneCandidate> Candidates(ITuneEngine engine, IEnumerable<StrategyHint> hints)
    {
        var builtIn = engine.Catalog
            .Select(c => (Key: StrategyKey.Normalize(engine.Name, c.Args).Key, Candidate: c))
            .Where(x => x.Key is not null)
            .GroupBy(x => x.Key!)
            .ToDictionary(g => g.Key, g => g.First().Candidate);
        var list = new List<TuneCandidate>();
        foreach (var hint in hints)
        {
            var normalized = StrategyKey.Normalize(engine.Name, hint.Args);
            if (normalized.Key is null || list.Any(c => StrategyKey.Normalize(engine.Name, c.Args).Key == normalized.Key))
            {
                continue;
            }
            list.Add(builtIn.TryGetValue(normalized.Key, out var known)
                ? known
                : new TuneCandidate($"registry-{StrategyKey.Id(normalized.Key)}", StrategyClass.Registry, normalized.Tokens));
        }
        return list;
    }
}
