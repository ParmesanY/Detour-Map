using System.Text.Json;

namespace Detour.NetProbe.Tests;

public class ReportTests
{
    [Test]
    public async Task Builtin_targets_load_and_are_valid()
    {
        var list = TargetList.Default;
        await Assert.That(list.Version).IsGreaterThan(0);
        await Assert.That(list.Targets.Count(t => t.Kind == TargetKind.Control)).IsGreaterThanOrEqualTo(1);
        await Assert.That(list.Targets.Count(t => t.Kind is TargetKind.Hosting or TargetKind.Ip)).IsGreaterThanOrEqualTo(3);
        await Assert.That(list.Targets.Where(t => t.Kind == TargetKind.Ip).All(t => !t.Tls)).IsTrue();
        // Defaults survive deserialisation (init-only properties would be reset to 0 / false / null).
        var youtube = list.Targets.Single(t => t.Id == "youtube");
        await Assert.That(youtube.Port).IsEqualTo(443);
        await Assert.That(youtube.Tls).IsTrue();
        await Assert.That(youtube.Path).IsEqualTo("/");
        await Assert.That(youtube.Kind).IsEqualTo(TargetKind.Site);
    }

    [Test]
    public async Task Duplicate_or_hostless_targets_are_rejected()
    {
        await Assert.That(() => TargetList.Parse("""{"version":1,"targets":[{"id":"a","name":"A","host":"a.com"},{"id":"a","name":"A","host":"b.com"}]}"""))
            .Throws<InvalidDataException>();
        await Assert.That(() => TargetList.Parse("""{"version":1,"targets":[{"id":"a","name":"A","ip":"1.1.1.1"}]}"""))
            .Throws<InvalidDataException>(); // TLS needs a host
    }

    [Test]
    public async Task Report_json_is_snake_case_without_nulls_or_addresses()
    {
        var report = new ProbeReport
        {
            Client = "probe-cli/0.1.0",
            TargetsVer = 1,
            Net = "home",
            Ts = "2026-11-16T14:00Z",
            Env = new ProbeEnv { VpnAdapter = true, Nic = true },
            Results =
            [
                new TargetResult { T = "youtube", Dns = "ok", Tcp = "ok", Tls = "rst", TlsCtrl = "ok" },
                new TargetResult { T = "x", Dns = "ok", Tcp = "ok", Tls = "ok", Http = new HttpResult { Bytes = 14000, Ms = 8000, Error = "timeout" } },
            ],
        };
        var json = JsonSerializer.Serialize(report, ProbeJson.Default.ProbeReport);

        await Assert.That(json).Contains("\"targets_ver\":1");
        await Assert.That(json).Contains("\"vpn_adapter\":true");
        await Assert.That(json).Contains("\"tls_ctrl\":\"ok\"");
        await Assert.That(json).DoesNotContain("null");
        await Assert.That(json).DoesNotContain("\"quic\"");

        var back = JsonSerializer.Deserialize(json, ProbeJson.Default.ProbeReport)!;
        await Assert.That(back.Results[1].Http!.Bytes).IsEqualTo(14000);
    }

    [Test]
    [Arguments("HTTP/1.1 200 OK\r\n", 200)]
    [Arguments("HTTP/1.1 301 Moved", 301)]
    [Arguments("garbage", null)]
    public async Task Status_line(string head, int? expected)
    {
        await Assert.That(Prober.ParseStatus(System.Text.Encoding.ASCII.GetBytes(head))).IsEqualTo(expected);
    }

    [Test]
    [Arguments("Wintun Userspace Tunnel", true)]
    [Arguments("singbox_tun", true)]
    [Arguments("tun0", true)]
    [Arguments("wg0", true)]
    [Arguments("Intel(R) Wi-Fi 6 AX201 160MHz", false)]
    [Arguments("Realtek PCIe GbE Family Controller", false)]
    [Arguments("Teredo Tunneling Pseudo-Interface", false)]
    public async Task Vpn_adapter_names(string name, bool expected)
    {
        await Assert.That(NicInfo.IsVpnName(name)).IsEqualTo(expected);
    }
}
