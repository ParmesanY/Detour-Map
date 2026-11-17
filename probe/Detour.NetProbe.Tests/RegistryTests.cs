using System.Text.Json.Nodes;

namespace Detour.NetProbe.Tests;

public class RegistryTests
{
    public static IEnumerable<Func<(string Name, string Engine, string Args, string? Key, string? Error)>> Cases()
    {
        var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "strategy-cases.json")))!["cases"]!.AsArray();
        foreach (var c in cases)
        {
            var item = (c!["name"]!.GetValue<string>(), c["engine"]!.GetValue<string>(), c["args"]!.GetValue<string>(),
                c["key"]?.GetValue<string>(), c["error"]?.GetValue<string>());
            yield return () => item;
        }
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task Strategy_keys_match_the_shared_cases((string Name, string Engine, string Args, string? Key, string? Error) c)
    {
        var r = StrategyKey.Normalize(c.Engine, c.Args);
        if (c.Key is not null)
        {
            await Assert.That(r.Key).IsEqualTo(c.Key);
        }
        else
        {
            await Assert.That(r.Error).IsEqualTo(c.Error);
        }
    }

    [Test]
    public async Task Every_builtin_strategy_normalizes()
    {
        foreach (var c in TuneCatalog.Winws)
        {
            await Assert.That(StrategyKey.Normalize(StrategyKey.Winws, c.Args).Key).IsNotNull();
        }
        foreach (var c in TuneCatalog.ByeDpi)
        {
            await Assert.That(StrategyKey.Normalize(StrategyKey.ByeDpi, c.Args).Key).IsNotNull();
        }
    }

    [Test]
    public async Task Tune_export_normalizes_back_to_the_same_key()
    {
        var engine = new WinwsEngine("winws.exe", 0);
        foreach (var c in TuneCatalog.Winws)
        {
            var fromExport = StrategyKey.Normalize(StrategyKey.Winws, engine.Export(c, "x.com")).Key;
            await Assert.That(fromExport).IsEqualTo(StrategyKey.Normalize(StrategyKey.Winws, c.Args).Key);
        }
    }

    private static StrategyHint Hint(string args) => new() { Args = args, Key = "winws:" + args };

    [Test]
    public async Task Hints_map_to_builtin_strategies_or_become_registry_ones()
    {
        var engine = new WinwsEngine("winws.exe", 0);
        var list = Registry.Candidates(engine,
        [
            Hint("--dpi-desync-fooling=ts --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-tls=%BIN%tls_clienthello_www_google_com.bin"),
            Hint("--dpi-desync=fake --dpi-desync-ttl=3"),
            Hint("--dpi-desync=fake --debug=@C:\\x.txt"),
            Hint("--dpi-desync=fake --dpi-desync-ttl=3"),
        ]);
        await Assert.That(list.Count).IsEqualTo(2);
        await Assert.That(list[0].Name).IsEqualTo("fake-ts");
        await Assert.That(list[1].Class).IsEqualTo(StrategyClass.Registry);
        await Assert.That(list[1].Name).StartsWith("registry-");
        await Assert.That(list[1].ArgLine).IsEqualTo("--dpi-desync=fake --dpi-desync-ttl=3");
    }

    [Test]
    public async Task Target_id_for_host()
    {
        await Assert.That(Registry.TargetIdForHost("www.youtube.com")).IsEqualTo("youtube");
        await Assert.That(Registry.TargetIdForHost("youtube.com")).IsEqualTo("youtube");
        await Assert.That(Registry.TargetIdForHost("my-secret-site.example")).IsNull();
    }

    private static TuneReport Tuned(int baselinePassed) => new()
    {
        Tool = "t", Host = "my-secret-site.example", Ts = "2026-11-17T10:00Z", Engine = "winws",
        Env = new ProbeEnv { Nic = true },
        Baseline = new TuneResult { Name = "no bypass", Passed = baselinePassed, Total = 2 },
        Results =
        [
            new TuneResult { Name = "split-1", Args = "--dpi-desync=multisplit --dpi-desync-split-pos=1", Passed = 0, Total = 2 },
            new TuneResult { Name = "broken", Args = "--dpi-desync=x", Error = "exited" },
            new TuneResult { Name = "fake-ts", Args = "--dpi-desync=fake --dpi-desync-fooling=ts", Passed = 2, Total = 2, Ms = 620 },
        ],
    };

    [Test]
    public async Task Report_for_the_registry_keeps_failures_drops_errors_and_hides_the_site()
    {
        var r = Registry.BuildReport(Tuned(0), "detour-tune/0.1.0", "home")!;
        await Assert.That(r.Results.Select(x => x.Passed).ToList()).IsEquivalentTo([0, 2]);
        await Assert.That(r.Target).IsNull();
        var json = System.Text.Json.JsonSerializer.Serialize(r, ProbeJson.Default.StrategyReport);
        await Assert.That(json).DoesNotContain("my-secret-site");
        await Assert.That(json).Contains("\"baseline\":{\"passed\":0,\"total\":2}");
    }

    [Test]
    public async Task Nothing_is_sent_for_an_open_site()
    {
        await Assert.That(Registry.BuildReport(Tuned(2), "detour-tune/0.1.0", "home")).IsNull();
    }
}
