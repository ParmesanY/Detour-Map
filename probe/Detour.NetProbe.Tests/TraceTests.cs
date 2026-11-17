using System.Text;

namespace Detour.NetProbe.Tests;

public class TraceTests
{
    private static TraceReport Report(params (string Id, string Outcome)[] steps) => Report(null, steps);

    private static TraceReport Report(ProbeEnv? env, params (string Id, string Outcome)[] steps)
    {
        var r = new TraceReport
        {
            Tool = "test",
            Host = "x.com",
            Ts = "2026-11-17T10:00Z",
            Env = env ?? new ProbeEnv { Nic = true },
            Ips = ["104.244.42.1"],
            Ip = "104.244.42.1",
        };
        r.Steps.Add(new TraceStepResult { Id = TraceStep.Control, Outcome = Outcome.Ok });
        foreach (var (id, outcome) in steps)
        {
            r.Steps.Add(new TraceStepResult { Id = id, Outcome = outcome, Detail = id == TraceStep.DnsIsp ? "10.10.34.36" : null });
        }
        return r;
    }

    private static List<string> Codes(TraceReport r) => [.. TraceDiagnosis.Diagnose(r).Select(f => f.Code)];

    [Test]
    public async Task Sni_filter_with_split_that_passes_recommends_split_strategies()
    {
        var r = Report((TraceStep.DnsIsp, Outcome.Ok), (TraceStep.Tcp443, Outcome.Ok), (TraceStep.Tcp80, Outcome.Ok),
            (TraceStep.TlsControl, Outcome.Alert), (TraceStep.TlsOtherServer, Outcome.Reset), (TraceStep.TlsSplit, Outcome.Ok),
            (TraceStep.TlsSni, Outcome.Timeout), (TraceStep.Quic, Outcome.Timeout));
        var findings = TraceDiagnosis.Diagnose(r);
        var sni = findings.Single(f => f.Code == "sni_filter");
        await Assert.That(sni.Severity).IsEqualTo(Severity.Block);
        await Assert.That(sni.Detail!).Contains("unrelated server");
        await Assert.That(sni.Fix!).Contains("split");
        // QUIC isn't reported on top of a TLS block.
        await Assert.That(Codes(r)).DoesNotContain("quic_block");
    }

    [Test]
    public async Task Quic_passing_where_tcp_tls_is_cut_is_noted()
    {
        var r = Report((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Ok), (TraceStep.TlsSni, Outcome.Timeout),
            (TraceStep.Quic, Outcome.Ok));
        await Assert.That(Codes(r)).IsEquivalentTo(["sni_filter", "quic_passes"]);
    }

    [Test]
    public async Task Sni_filter_where_split_is_cut_too_suggests_fake_or_vpn()
    {
        var r = Report((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Ok), (TraceStep.TlsSplit, Outcome.Reset),
            (TraceStep.TlsSni, Outcome.Reset));
        var sni = TraceDiagnosis.Diagnose(r).Single(f => f.Code == "sni_filter");
        await Assert.That(sni.Fix!).Contains("fake");
    }

    [Test]
    public async Task Dns_stub_and_ip_block()
    {
        var r = Report((TraceStep.DnsIsp, Outcome.Stub), (TraceStep.Tcp443, Outcome.Timeout), (TraceStep.Tcp80, Outcome.Timeout));
        var codes = Codes(r);
        await Assert.That(codes).IsEquivalentTo(["dns_substitution", "ip_block"]);
        var dns = TraceDiagnosis.Diagnose(r).First(f => f.Code == "dns_substitution");
        await Assert.That(dns.Detail!).Contains("10.10.34.36");
        await Assert.That(dns.Detail!).Contains("104.244.42.1");
    }

    [Test]
    public async Task Port_443_only_block()
    {
        var r = Report((TraceStep.Tcp443, Outcome.Timeout), (TraceStep.Tcp80, Outcome.Ok));
        await Assert.That(Codes(r)).Contains("port_block");
    }

    [Test]
    public async Task Every_handshake_cut_is_an_address_block()
    {
        var r = Report((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Timeout), (TraceStep.TlsSni, Outcome.Timeout));
        await Assert.That(Codes(r)).Contains("ip_block_tls");
    }

    [Test]
    public async Task Freeze_after_handshake()
    {
        var r = Report((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok), (TraceStep.HttpsGet, Verdict.Freeze));
        r.Download = new HttpResult { Bytes = 16384, Ms = 8000, Error = Outcome.Timeout };
        var freeze = TraceDiagnosis.Diagnose(r).Single(f => f.Code == "freeze16k");
        await Assert.That(freeze.Detail!).Contains("16 KB");
    }

    [Test]
    public async Task Quic_drop_alone_is_a_warning_and_the_site_counts_as_open()
    {
        var r = Report((TraceStep.DnsIsp, Outcome.Ok), (TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok),
            (TraceStep.HttpsGet, Verdict.Ok), (TraceStep.Quic, Outcome.Timeout));
        await Assert.That(Codes(r)).IsEquivalentTo(["quic_block", "open"]);
    }

    [Test]
    public async Task No_network_stops_the_diagnosis()
    {
        var r = Report();
        r.Steps[0] = new TraceStepResult { Id = TraceStep.Control, Outcome = Outcome.Timeout };
        r.Steps.Add(new TraceStepResult { Id = TraceStep.Tcp443, Outcome = Outcome.Timeout });
        await Assert.That(Codes(r)).IsEquivalentTo(["no_network"]);
    }

    [Test]
    public async Task Bypass_running_is_flagged_first_among_warnings()
    {
        var r = Report(new ProbeEnv { DpiBypass = true, Nic = true },
            (TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok), (TraceStep.HttpsGet, Verdict.Ok));
        await Assert.That(Codes(r)).IsEquivalentTo(["bypass_running", "open"]);
    }

    [Test]
    public async Task Blocks_come_before_warnings_and_info()
    {
        var r = Report((TraceStep.DnsIsp, Outcome.Timeout), (TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Ok),
            (TraceStep.TlsSni, Outcome.Reset));
        await Assert.That(TraceDiagnosis.Diagnose(r).Select(f => f.Severity).ToList()).IsEquivalentTo([Severity.Block, Severity.Info]);
        await Assert.That(TraceDiagnosis.Diagnose(r)[0].Code).IsEqualTo("sni_filter");
    }

    // ---- split ClientHello ----

    private sealed class RecordingStream : MemoryStream
    {
        public List<int> Writes { get; } = [];

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Writes.Add(buffer.Length);
            return base.WriteAsync(buffer, cancellationToken);
        }
    }

    [Test]
    public async Task Split_point_is_inside_the_name()
    {
        var hello = Encoding.ASCII.GetBytes("\x16\x03\x01....\x00\x00rutracker.org\x00\x10....");
        var at = SplitHelloStream.SplitPoint(hello, "rutracker.org");
        var nameStart = Encoding.ASCII.GetString(hello).IndexOf("rutracker.org", StringComparison.Ordinal);
        await Assert.That(at).IsGreaterThan(nameStart);
        await Assert.That(at).IsLessThan(nameStart + "rutracker.org".Length);
    }

    [Test]
    public async Task Only_the_first_write_is_split_and_nothing_is_lost()
    {
        var inner = new RecordingStream();
        await using var split = new SplitHelloStream(inner, "x.com", TimeSpan.Zero);
        await split.WriteAsync(Encoding.ASCII.GetBytes("hello x.com world"));
        await split.WriteAsync(Encoding.ASCII.GetBytes("second"));
        await Assert.That(inner.Writes.Count).IsEqualTo(3);
        await Assert.That(Encoding.ASCII.GetString(inner.ToArray())).IsEqualTo("hello x.com worldsecond");
    }

    // ---- plain HTTP ----

    [Test]
    public async Task Redirect_to_the_site_itself_is_normal()
    {
        var a = PlainHttp.Parse(Encoding.ASCII.GetBytes("HTTP/1.1 301 Moved\r\nLocation: https://www.x.com/\r\n\r\n"), "x.com");
        await Assert.That(a.Status).IsEqualTo(301);
        await Assert.That(a.BlockPage).IsFalse();
    }

    [Test]
    public async Task Redirect_to_a_stub_page_is_a_block()
    {
        var a = PlainHttp.Parse(Encoding.ASCII.GetBytes("HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/?id=17\r\n\r\n"), "rutracker.org");
        await Assert.That(a.BlockPage).IsTrue();
    }

    [Test]
    public async Task Block_page_text_and_451_are_blocks()
    {
        var page = PlainHttp.Parse(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Доступ к ресурсу ограничен</h1> по решению РКН"), "meduza.io");
        await Assert.That(page.BlockPage).IsTrue();
        var legal = PlainHttp.Parse(Encoding.ASCII.GetBytes("HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n"), "meduza.io");
        await Assert.That(legal.BlockPage).IsTrue();
    }

    [Test]
    public async Task Trace_report_json_has_no_nulls_and_snake_case()
    {
        var r = Report((TraceStep.TlsOtherServer, Outcome.Reset));
        r.Findings = TraceDiagnosis.Diagnose(r);
        var json = System.Text.Json.JsonSerializer.Serialize(r, ProbeJson.Default.TraceReport);
        await Assert.That(json).Contains("\"tls.other_server\"");
        await Assert.That(json).Contains("\"findings\"");
        await Assert.That(json).DoesNotContain("null");
    }
}
