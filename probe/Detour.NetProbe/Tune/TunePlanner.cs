namespace Detour.NetProbe;

/// <summary>What to try, in which order, or why not to try at all.</summary>
public sealed class TunePlan
{
    /// <summary>Set when no DPI trick can help (or there is nothing to fix): a finding code from the trace.</summary>
    public string? StopCode { get; init; }
    public string? StopReason { get; init; }
    /// <summary>Strategy classes in the order to try them; classes left out are ruled out by the trace.</summary>
    public required List<string> Order { get; init; }
    public List<string> Notes { get; } = [];

    /// <summary>The engine's candidates this plan keeps, class by class in plan order, catalog order inside a class.</summary>
    public List<TuneCandidate> Pick(IEnumerable<TuneCandidate> catalog)
    {
        var list = catalog.ToList();
        return [.. Order.SelectMany(cls => list.Where(c => c.Class == cls))];
    }
}

/// <summary>
/// Turns a <see cref="TraceReport" /> into a <see cref="TunePlan" />. Pure, so the rules are tested without a network.
/// </summary>
public static class TunePlanner
{
    private static readonly string[] _addressBlocks = ["ip_block", "ip_block_tls", "port_block", "no_address"];

    public static TunePlan Plan(TraceReport? trace)
    {
        if (trace is null)
        {
            return new TunePlan { Order = [.. StrategyClass.All] };
        }
        var codes = trace.Findings.Select(f => f.Code).ToHashSet();
        if (codes.Contains("no_network"))
        {
            return Stop("no_network", "No network at all: there is nothing to tune.");
        }
        if (_addressBlocks.FirstOrDefault(codes.Contains) is { } address)
        {
            return Stop(address, "The site is blocked by address, not by name: no DPI trick gets through, it needs a VPN.");
        }
        var blocks = trace.Findings.Where(f => f.Severity == Severity.Block).Select(f => f.Code).ToHashSet();
        blocks.Remove("dns_substitution");
        if (blocks.Count == 0)
        {
            return codes.Contains("dns_substitution")
                ? Stop("dns_substitution", "Only DNS lies: an encrypted resolver (DoH) fixes it, no DPI strategy is needed.")
                : Stop("open", "The site isn't blocked over HTTPS here: nothing to tune.");
        }
        if (blocks.SetEquals(["http_block_page"]))
        {
            return Stop("http_block_page", "Only plain HTTP shows a block page; HTTPS works: nothing to tune.");
        }

        TunePlan plan;
        if (blocks.Contains("sni_filter"))
        {
            var split = trace.OutcomeOf(TraceStep.TlsSplit);
            if (split == Outcome.Ok)
            {
                plan = new TunePlan { Order = [StrategyClass.Split, StrategyClass.Disorder, StrategyClass.TlsRec, StrategyClass.Oob, StrategyClass.FakeSplit, StrategyClass.Fake] };
                plan.Notes.Add("A split ClientHello got through in the trace: plain splits go first.");
            }
            else if (split is not null && split != TraceOutcome.Skipped)
            {
                // DPI reassembles segments: a plain split is what the trace already did.
                plan = new TunePlan { Order = [StrategyClass.Fake, StrategyClass.FakeSplit, StrategyClass.Disorder, StrategyClass.TlsRec, StrategyClass.Oob] };
                plan.Notes.Add("DPI reassembled the split ClientHello in the trace: plain splits are skipped, fakes go first.");
            }
            else
            {
                plan = new TunePlan { Order = [.. StrategyClass.All] };
            }
        }
        else
        {
            // The 16 KB freeze, silence or throttling after the handshake: TSPU on foreign hosting.
            plan = new TunePlan { Order = [StrategyClass.FakeSplit, StrategyClass.Fake, StrategyClass.Disorder, StrategyClass.Split, StrategyClass.TlsRec, StrategyClass.Oob] };
            if (blocks.Overlaps(["freeze16k", "stall", "throttle"]))
            {
                plan.Notes.Add("The transfer is cut after the handshake (hosting-wide TSPU limit): strategies help only sometimes, a VPN always does.");
            }
        }
        if (codes.Contains("dns_substitution"))
        {
            plan.Notes.Add("DNS lies too: use an encrypted resolver (DoH) alongside the strategy.");
        }
        return plan;
    }

    private static TunePlan Stop(string code, string reason) => new() { StopCode = code, StopReason = reason, Order = [] };
}
