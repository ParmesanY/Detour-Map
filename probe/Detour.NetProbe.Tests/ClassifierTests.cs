using System.Text.Json;
using System.Text.Json.Nodes;

namespace Detour.NetProbe.Tests;

public class ClassifierTests
{
    public static IEnumerable<Func<(string Name, string ResultJson, string[] Expect)>> Cases()
    {
        var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "verdict-cases.json")))!.AsArray();
        foreach (var c in cases)
        {
            var name = c!["name"]!.GetValue<string>();
            var result = c["result"]!.ToJsonString();
            var expect = c["expect"]!.AsArray().Select(e => e!.GetValue<string>()).ToArray();
            yield return () => (name, result, expect);
        }
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task Shared_case((string Name, string ResultJson, string[] Expect) c)
    {
        var result = JsonSerializer.Deserialize(c.ResultJson, ProbeJson.Default.TargetResult)!;
        await Assert.That(Classifier.Classify(result)).IsEquivalentTo(c.Expect);
    }

    private static ProbeReport Report(params (string Id, string? Tcp, string? Tls)[] results) => new()
    {
        Client = "test",
        Net = "home",
        Ts = "2026-11-16T14:00Z",
        Env = new ProbeEnv { Nic = true },
        Results = [.. results.Select(r => new TargetResult { T = r.Id, Tcp = r.Tcp, Tls = r.Tls })],
    };

    private static readonly TargetList _kinds = new()
    {
        Version = 1,
        Targets =
        [
            new Target { Id = "ya", Name = "ya", Kind = TargetKind.Control, Host = "ya.ru" },
            new Target { Id = "h1", Name = "h1", Kind = TargetKind.Hosting, Host = "h1.example" },
            new Target { Id = "h2", Name = "h2", Kind = TargetKind.Hosting, Host = "h2.example" },
            new Target { Id = "ip1", Name = "ip1", Kind = TargetKind.Ip, Ip = "1.1.1.1", Tls = false },
        ],
    };

    [Test]
    public async Task Whitelist_when_only_domestic_works()
    {
        var flags = Classifier.ReportFlags(Report(("ya", "ok", "ok"), ("h1", "timeout", null), ("h2", "ok", "timeout"), ("ip1", "timeout", null)), _kinds);
        await Assert.That(flags).IsEquivalentTo([ReportFlag.Whitelist]);
    }

    [Test]
    public async Task No_network_when_control_fails()
    {
        var flags = Classifier.ReportFlags(Report(("ya", "timeout", null), ("h1", "timeout", null)), _kinds);
        await Assert.That(flags).IsEquivalentTo([ReportFlag.NoNetwork]);
    }

    [Test]
    public async Task No_flags_on_a_normal_run()
    {
        var flags = Classifier.ReportFlags(Report(("ya", "ok", "ok"), ("h1", "ok", "ok"), ("h2", "ok", "timeout"), ("ip1", "ok", null)), _kinds);
        await Assert.That(flags).IsEmpty();
    }

    [Test]
    public async Task Untrusted_with_dpi_bypass_or_unbound_vpn()
    {
        var withDpi = Report(("ya", "ok", "ok"));
        withDpi = new ProbeReport { Client = "t", Net = "home", Ts = withDpi.Ts, Env = new ProbeEnv { DpiBypass = true, Nic = true }, Results = withDpi.Results };
        var vpnUnbound = new ProbeReport { Client = "t", Net = "home", Ts = withDpi.Ts, Env = new ProbeEnv { VpnAdapter = true, Nic = false }, Results = withDpi.Results };
        var vpnBound = new ProbeReport { Client = "t", Net = "home", Ts = withDpi.Ts, Env = new ProbeEnv { VpnAdapter = true, Nic = true }, Results = withDpi.Results };

        await Assert.That(Classifier.ReportFlags(withDpi, _kinds)).Contains(ReportFlag.Untrusted);
        await Assert.That(Classifier.ReportFlags(vpnUnbound, _kinds)).Contains(ReportFlag.Untrusted);
        await Assert.That(Classifier.ReportFlags(vpnBound, _kinds)).IsEmpty();
    }
}
