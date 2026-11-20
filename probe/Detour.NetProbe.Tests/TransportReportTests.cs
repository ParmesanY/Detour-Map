using System.Text.Json;
using System.Text.Json.Nodes;

namespace Detour.NetProbe.Tests;

public class TransportReportTests
{
    [Test]
    public async Task Kinds_MatchSpec()
    {
        var spec = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "transports.json")))!["transports"]!
            .AsArray().Select(n => n!.GetValue<string>()).ToList();
        await Assert.That(TransportReport.Kinds.SequenceEqual(spec)).IsTrue();
    }

    [Test]
    public async Task Report_SerializesSnakeCase_NoServerFields()
    {
        var report = new TransportReport
        {
            Client = "detour/0.4.1",
            Net = "home",
            Env = new ProbeEnv { DpiBypass = false, Nic = true },
            Results = [new TransportResult { Transport = "hysteria2", Ok = 3, Frozen = 1 }],
        };
        var json = JsonSerializer.Serialize(report, ProbeJson.Default.TransportReport);
        await Assert.That(json).Contains("\"dpi_bypass\":false");
        await Assert.That(json).Contains("\"transport\":\"hysteria2\"");
        await Assert.That(json).DoesNotContain("address");
    }
}