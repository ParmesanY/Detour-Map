namespace Detour.NetProbe;

/// <summary>How one strategy did: <see cref="Passed" /> of <see cref="Total" /> attempts reached the site and read 64 KB.</summary>
public sealed class TuneResult
{
    public required string Name { get; init; }
    public string? Class { get; init; }
    /// <summary>The strategy's args (empty for the baseline, "no bypass").</summary>
    public string? Args { get; init; }
    public int Passed { get; set; }
    public int Total { get; set; }
    /// <summary>Average time of the passing attempts (connect + TLS + 64 KB).</summary>
    public long Ms { get; set; }
    /// <summary>How the last failing attempt failed (an <see cref="Outcome" /> or <see cref="Verdict" />); null if none failed.</summary>
    public string? Failure { get; set; }
    /// <summary>The engine didn't start with these args.</summary>
    public string? Error { get; set; }

    public bool Works => Total > 0 && Passed == Total;
}

public sealed class TuneReport
{
    public int V { get; set; } = 1;
    public required string Tool { get; init; }
    public required string Host { get; init; }
    public required string Ts { get; init; }
    /// <summary>"winws" or "byedpi".</summary>
    public required string Engine { get; init; }
    public ProbeEnv? Env { get; init; }
    public List<string> Ips { get; init; } = [];
    /// <summary>Finding codes of the trace the plan was made from.</summary>
    public List<string> Trace { get; set; } = [];
    public string? StopCode { get; set; }
    public string? StopReason { get; set; }
    public List<string> Notes { get; set; } = [];
    /// <summary>The site without any bypass, measured the same way.</summary>
    public TuneResult? Baseline { get; set; }
    public List<TuneResult> Results { get; set; } = [];
    /// <summary>Name of the best strategy; null if none got through even once.</summary>
    public string? Best { get; set; }
    /// <summary>Best passed every attempt (not just some).</summary>
    public bool Stable { get; set; }
    /// <summary>The best strategy, ready to paste: winws args for a .bat (with <c>%BIN%</c>) or a ciadpi command line.</summary>
    public string? Export { get; set; }

    /// <summary>Most passes, then fastest. Strategies that never passed don't count.</summary>
    public static TuneResult? Rank(IEnumerable<TuneResult> results) => results
        .Where(r => r.Passed > 0 && r.Error is null)
        .OrderByDescending(r => (double)r.Passed / r.Total)
        .ThenBy(r => r.Ms)
        .FirstOrDefault();
}
