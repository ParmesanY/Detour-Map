using System.Net;
using System.Net.Sockets;

namespace Detour.NetProbe.Tests;

public class TuneTests
{
    private static TraceReport Trace(params (string Id, string Outcome)[] steps)
    {
        var r = new TraceReport
        {
            Tool = "test",
            Host = "x.com",
            Ts = "2026-11-17T10:00Z",
            Env = new ProbeEnv { Nic = true },
            Ips = ["104.244.42.1"],
            Ip = "104.244.42.1",
        };
        r.Steps.Add(new TraceStepResult { Id = TraceStep.Control, Outcome = Outcome.Ok });
        foreach (var (id, outcome) in steps)
        {
            r.Steps.Add(new TraceStepResult { Id = id, Outcome = outcome });
        }
        r.Findings = TraceDiagnosis.Diagnose(r);
        return r;
    }

    // ---- plan ----

    [Test]
    public async Task Without_a_trace_every_class_is_tried()
    {
        var plan = TunePlanner.Plan(null);
        await Assert.That(plan.StopCode).IsNull();
        await Assert.That(plan.Pick(TuneCatalog.Winws).Count).IsEqualTo(TuneCatalog.Winws.Length);
    }

    [Test]
    public async Task Split_that_passed_in_the_trace_goes_first()
    {
        var plan = TunePlanner.Plan(Trace((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Ok),
            (TraceStep.TlsSplit, Outcome.Ok), (TraceStep.TlsSni, Outcome.Reset)));
        await Assert.That(plan.Order[0]).IsEqualTo(StrategyClass.Split);
        await Assert.That(plan.Pick(TuneCatalog.Winws)[0].Class).IsEqualTo(StrategyClass.Split);
    }

    [Test]
    public async Task Split_that_was_cut_in_the_trace_is_skipped_and_fakes_go_first()
    {
        var plan = TunePlanner.Plan(Trace((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Ok),
            (TraceStep.TlsSplit, Outcome.Reset), (TraceStep.TlsSni, Outcome.Reset)));
        await Assert.That(plan.Order).DoesNotContain(StrategyClass.Split);
        await Assert.That(plan.Order[0]).IsEqualTo(StrategyClass.Fake);
        var picked = plan.Pick(TuneCatalog.ByeDpi);
        await Assert.That(picked.Any(c => c.Class == StrategyClass.Split)).IsFalse();
        await Assert.That(picked.Count).IsGreaterThan(0);
    }

    [Test]
    public async Task Address_block_stops_tuning()
    {
        var plan = TunePlanner.Plan(Trace((TraceStep.Tcp443, Outcome.Timeout), (TraceStep.Tcp80, Outcome.Timeout)));
        await Assert.That(plan.StopCode).IsEqualTo("ip_block");
        await Assert.That(plan.StopReason!).Contains("VPN");
        await Assert.That(plan.Pick(TuneCatalog.Winws)).IsEmpty();
    }

    [Test]
    public async Task Every_handshake_cut_stops_tuning_too()
    {
        var plan = TunePlanner.Plan(Trace((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsControl, Outcome.Timeout), (TraceStep.TlsSni, Outcome.Timeout)));
        await Assert.That(plan.StopCode).IsEqualTo("ip_block_tls");
    }

    [Test]
    public async Task Open_site_needs_no_tuning()
    {
        var plan = TunePlanner.Plan(Trace((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok), (TraceStep.HttpsGet, Verdict.Ok)));
        await Assert.That(plan.StopCode).IsEqualTo("open");
    }

    [Test]
    public async Task Dns_only_block_needs_doh_not_a_strategy()
    {
        var r = Trace((TraceStep.DnsIsp, Outcome.Stub), (TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok), (TraceStep.HttpsGet, Verdict.Ok));
        var plan = TunePlanner.Plan(r);
        await Assert.That(plan.StopCode).IsEqualTo("dns_substitution");
        await Assert.That(plan.StopReason!).Contains("DoH");
    }

    [Test]
    public async Task Freeze_puts_fake_splits_first_with_a_note()
    {
        var r = Trace((TraceStep.Tcp443, Outcome.Ok), (TraceStep.TlsSni, Outcome.Ok), (TraceStep.HttpsGet, Verdict.Freeze));
        r.Download = new HttpResult { Bytes = 16384, Ms = 8000, Error = Outcome.Timeout };
        r.Findings = TraceDiagnosis.Diagnose(r);
        var plan = TunePlanner.Plan(r);
        await Assert.That(plan.StopCode).IsNull();
        await Assert.That(plan.Order[0]).IsEqualTo(StrategyClass.FakeSplit);
        await Assert.That(plan.Notes.Single()).Contains("VPN");
    }

    // ---- catalog and engines ----

    [Test]
    public async Task Catalog_names_are_unique_and_classes_known()
    {
        var all = TuneCatalog.Winws.Concat(TuneCatalog.ByeDpi).ToList();
        await Assert.That(all.Select(c => c.Name).Distinct().Count()).IsEqualTo(all.Count);
        await Assert.That(all.All(c => StrategyClass.All.Contains(c.Class))).IsTrue();
        await Assert.That(all.All(c => c.Args.Length > 0)).IsTrue();
    }

    [Test]
    public async Task Bin_files_are_found_in_args()
    {
        var seqovl = TuneCatalog.Winws.Single(c => c.Name == "seqovl");
        await Assert.That(seqovl.Files.ToList()).IsEquivalentTo(["tls_clienthello_www_google_com.bin"]);
        await Assert.That(TuneCatalog.Winws.Single(c => c.Name == "split-1").Files).IsEmpty();
    }

    [Test]
    public async Task Winws_args_touch_only_the_host_on_the_card()
    {
        var dir = Path.Combine(Path.GetTempPath(), "detour-tune-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var engine = new WinwsEngine(Path.Combine(dir, "winws.exe"), 12);
            var seqovl = TuneCatalog.Winws.Single(c => c.Name == "seqovl");
            await Assert.That(engine.CanRun(seqovl)).IsFalse();
            await File.WriteAllBytesAsync(Path.Combine(dir, "tls_clienthello_www_google_com.bin"), [1]);
            await Assert.That(engine.CanRun(seqovl)).IsTrue();

            var args = engine.BuildArgs(seqovl, "rutracker.org");
            await Assert.That(args[0]).IsEqualTo("--wf-iface=12");
            await Assert.That(args).Contains("--hostlist-domains=rutracker.org");
            await Assert.That(args).Contains("--wf-tcp=443");
            await Assert.That(args.Any(a => a.Contains("%BIN%"))).IsFalse();
            await Assert.That(args.Last()).IsEqualTo("--dpi-desync-split-seqovl-pattern=" + Path.Combine(dir, "tls_clienthello_www_google_com.bin"));

            // The export stays in the .bat convention.
            var export = engine.Export(seqovl, "rutracker.org");
            await Assert.That(export).StartsWith("--filter-tcp=443 --hostlist-domains=rutracker.org --dpi-desync=multisplit");
            await Assert.That(export).EndsWith("--dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_www_google_com.bin\"");
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task Byedpi_listens_on_loopback_and_binds_out_to_the_card()
    {
        var engine = new ByeDpiEngine("ciadpi.exe", IPAddress.Parse("192.168.1.10"), 10999);
        var args = engine.BuildArgs(TuneCatalog.ByeDpi.Single(c => c.Name == "bd-tlsrec-split"), "x.com");
        await Assert.That(string.Join(' ', args)).IsEqualTo("-i 127.0.0.1 -p 10999 -I 192.168.1.10 -r1+s -s1");
        await Assert.That(engine.Export(TuneCatalog.ByeDpi[0], "x.com")).IsEqualTo("ciadpi -s1");
    }

    // ---- SOCKS5 ----

    /// <summary>A one-connection SOCKS5 server that answers CONNECT with <paramref name="reply" /> and echoes the request.</summary>
    private static async Task<(int Port, Task<byte[]> Request)> FakeSocksAsync(byte reply)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var request = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            listener.Stop();
            var s = client.GetStream();
            var greet = new byte[3];
            await s.ReadExactlyAsync(greet);
            await s.WriteAsync(new byte[] { 5, 0 });
            var req = new byte[10];
            await s.ReadExactlyAsync(req);
            await s.WriteAsync(new byte[] { 5, reply, 0, 1, 0, 0, 0, 0, 0, 0 });
            return req;
        });
        return (port, request);
    }

    [Test]
    public async Task Socks5_connect_by_ip()
    {
        var (port, request) = await FakeSocksAsync(0);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var outcome = await Socks5.ConnectAsync(client.GetStream(), IPAddress.Parse("104.244.42.1"), 443, CancellationToken.None);
        await Assert.That(outcome).IsEqualTo(Outcome.Ok);
        await Assert.That((await request).ToArray()).IsEquivalentTo(new byte[] { 5, 1, 0, 1, 104, 244, 42, 1, 1, 187 });
    }

    [Test]
    public async Task Socks5_refusal_is_reported()
    {
        var (port, _) = await FakeSocksAsync(5);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var outcome = await Socks5.ConnectAsync(client.GetStream(), IPAddress.Parse("1.2.3.4"), 443, CancellationToken.None);
        await Assert.That(outcome).IsEqualTo(Outcome.Refused);
    }

    // ---- ranking and the loop ----

    [Test]
    public async Task Rank_prefers_stable_then_fast_and_ignores_errors()
    {
        List<TuneResult> results =
        [
            new() { Name = "flaky", Passed = 1, Total = 2, Ms = 100 },
            new() { Name = "slow", Passed = 2, Total = 2, Ms = 900 },
            new() { Name = "fast", Passed = 2, Total = 2, Ms = 300 },
            new() { Name = "broken", Error = "exited", Passed = 0, Total = 0 },
            new() { Name = "cut", Passed = 0, Total = 2 },
        ];
        await Assert.That(TuneReport.Rank(results)!.Name).IsEqualTo("fast");
        await Assert.That(TuneReport.Rank(results.Where(r => r.Name is "flaky" or "cut"))!.Name).IsEqualTo("flaky");
        await Assert.That(TuneReport.Rank(results.Where(r => r.Name is "cut" or "broken"))).IsNull();
    }

    /// <summary>An engine that "fixes" the connection only for one candidate: a local TLS-less server stands in for the site.</summary>
    private sealed class FakeEngine(string works) : ITuneEngine
    {
        public string Works => works;
        public string? Running { get; private set; }
        public List<string> Started { get; } = [];
        public string Name => "fake";
        public IReadOnlyList<TuneCandidate> Catalog { get; } =
        [
            new("a", StrategyClass.Split, ["-a"]),
            new("b", StrategyClass.Fake, ["-b"]),
            new("c", StrategyClass.Fake, ["-c"]),
            new("broken", StrategyClass.Fake, ["-x"]),
        ];
        public bool CanRun(TuneCandidate candidate) => true;

        public Task<string?> StartAsync(TuneCandidate candidate, string host, CancellationToken ct)
        {
            Started.Add(candidate.Name);
            if (candidate.Name == "broken")
            {
                return Task.FromResult<string?>("exited with code 1");
            }
            Running = candidate.Name;
            return Task.FromResult<string?>(null);
        }

        public Task StopAsync()
        {
            Running = null;
            return Task.CompletedTask;
        }

        public Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct) =>
            Task.FromResult<(string, Stream?)>(Running == works ? (Outcome.Ok, new MemoryStream()) : (Outcome.Reset, null));

        public string Export(TuneCandidate candidate, string host) => "export " + candidate.Name;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Test]
    public async Task Measure_counts_attempts_and_keeps_the_failure()
    {
        var engine = new FakeEngine("none");
        await engine.StartAsync(engine.Catalog[0], "x.com", CancellationToken.None);
        var r = await Tuner.MeasureAsync(engine, engine.Catalog[0], "x.com", [IPAddress.Loopback], null, 3, CancellationToken.None);
        await Assert.That(r.Total).IsEqualTo(3);
        await Assert.That(r.Passed).IsEqualTo(0);
        await Assert.That(r.Failure).IsEqualTo(Outcome.Reset);
        await Assert.That(r.Works).IsFalse();
    }

    /// <summary>Passes when the engine is running the candidate it "works" with: the loop is what's tested here.</summary>
    private static Func<TuneCandidate, Task<TuneResult>> MeasureVia(FakeEngine engine) => c =>
        Task.FromResult(new TuneResult { Name = c.Name, Total = 2, Passed = engine.Running == c.Name && engine.Works == c.Name ? 2 : 0 });

    [Test]
    public async Task Loop_stops_at_the_first_strategy_that_works_and_stops_the_engine()
    {
        var engine = new FakeEngine("b");
        var results = new List<TuneResult>();
        await Tuner.RunCandidatesAsync(engine, engine.Catalog, "x.com", MeasureVia(engine), new TuneOptions { Tool = "t" }, results, CancellationToken.None);
        await Assert.That(engine.Started).IsEquivalentTo(["a", "b"]);
        await Assert.That(results.Select(r => r.Works).ToList()).IsEquivalentTo([false, true]);
        await Assert.That(engine.Running).IsNull();
        await Assert.That(TuneReport.Rank(results)!.Name).IsEqualTo("b");
    }

    [Test]
    public async Task Loop_with_all_tries_everything_and_records_engine_errors()
    {
        var engine = new FakeEngine("c");
        var results = new List<TuneResult>();
        await Tuner.RunCandidatesAsync(engine, engine.Catalog, "x.com", MeasureVia(engine), new TuneOptions { Tool = "t", All = true }, results, CancellationToken.None);
        await Assert.That(engine.Started.Count).IsEqualTo(4);
        var broken = results.Single(r => r.Name == "broken");
        await Assert.That(broken.Error!).Contains("exited");
        await Assert.That(broken.Works).IsFalse();
        await Assert.That(TuneReport.Rank(results)!.Name).IsEqualTo("c");
    }

    [Test]
    public async Task Tune_report_json_is_snake_case_without_nulls()
    {
        var report = new TuneReport
        {
            Tool = "test", Host = "x.com", Ts = "2026-11-17T10:00Z", Engine = "winws",
            Results = [new TuneResult { Name = "split-1", Class = StrategyClass.Split, Args = "--dpi-desync=multisplit", Passed = 2, Total = 2, Ms = 300 }],
            Best = "split-1", Stable = true, Export = "--filter-tcp=443",
        };
        var json = System.Text.Json.JsonSerializer.Serialize(report, ProbeJson.Default.TuneReport);
        await Assert.That(json).DoesNotContain("\"stop_code\"");
        await Assert.That(json).Contains("\"best\":\"split-1\"");
        await Assert.That(json).DoesNotContain("null");
    }
}
