using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Detour.NetProbe;

/// <summary>A DPI bypass Tune can start with a candidate's args, check through, and stop.</summary>
public interface ITuneEngine : IAsyncDisposable
{
    /// <summary>"winws", "byedpi", or "direct" for the baseline.</summary>
    string Name { get; }
    IReadOnlyList<TuneCandidate> Catalog { get; }
    /// <summary>Are the files the candidate needs there?</summary>
    bool CanRun(TuneCandidate candidate);
    /// <summary>Starts the engine for <paramref name="host" /> only. Returns an error, or null when it runs.</summary>
    Task<string?> StartAsync(TuneCandidate candidate, string host, CancellationToken ct);
    Task StopAsync();
    /// <summary>A connection to ip:port the way traffic goes with this engine running.</summary>
    Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct);
    /// <summary>The candidate as the user would paste it.</summary>
    string Export(TuneCandidate candidate, string host);
}

/// <summary>No bypass: the baseline.</summary>
public sealed class DirectEngine : ITuneEngine
{
    public string Name => "direct";
    public IReadOnlyList<TuneCandidate> Catalog => [];
    public bool CanRun(TuneCandidate candidate) => true;
    public Task<string?> StartAsync(TuneCandidate candidate, string host, CancellationToken ct) => Task.FromResult<string?>(null);
    public Task StopAsync() => Task.CompletedTask;
    public string Export(TuneCandidate candidate, string host) => string.Empty;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public async Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        var (outcome, socket) = await Prober.TcpAsync(ip, port, local, ct);
        return (outcome, socket is null ? null : new NetworkStream(socket, true));
    }
}

/// <summary>Runs one external process per candidate; kills it (and its children) on stop.</summary>
public abstract class ProcessEngine(string exePath) : ITuneEngine
{
    private Process? _process;
    private readonly List<string> _stderr = [];

    /// <summary>How long a just-started engine gets to hook in before it is measured.</summary>
    public TimeSpan Settle { get; init; } = TimeSpan.FromSeconds(1.5);

    public string ExePath { get; } = exePath;
    public abstract string Name { get; }
    public abstract IReadOnlyList<TuneCandidate> Catalog { get; }
    public abstract Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct);
    public abstract string Export(TuneCandidate candidate, string host);
    public abstract IReadOnlyList<string> BuildArgs(TuneCandidate candidate, string host);

    public virtual bool CanRun(TuneCandidate candidate) => true;

    public async Task<string?> StartAsync(TuneCandidate candidate, string host, CancellationToken ct)
    {
        await StopAsync();
        var psi = new ProcessStartInfo(ExePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(ExePath)) ?? "",
        };
        foreach (var a in BuildArgs(candidate, host))
        {
            psi.ArgumentList.Add(a);
        }
        lock (_stderr)
        {
            _stderr.Clear();
        }
        var proc = new Process { StartInfo = psi };
        void Collect(object? _, DataReceivedEventArgs e)
        {
            if (e.Data is { Length: > 0 } line)
            {
                lock (_stderr)
                {
                    _stderr.Add(line);
                    if (_stderr.Count > 20)
                    {
                        _stderr.RemoveAt(0);
                    }
                }
            }
        }
        proc.OutputDataReceived += Collect;
        proc.ErrorDataReceived += Collect;
        try
        {
            proc.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            proc.Dispose();
            return $"can't start {Path.GetFileName(ExePath)}: {ex.Message}";
        }
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        _process = proc;
        try
        {
            await Task.Delay(Settle, ct);
        }
        catch (OperationCanceledException)
        {
            await StopAsync();
            throw;
        }
        if (proc.HasExited)
        {
            string tail;
            lock (_stderr)
            {
                tail = string.Join(" | ", _stderr.TakeLast(3));
            }
            var code = proc.ExitCode;
            await StopAsync();
            return $"{Path.GetFileName(ExePath)} exited with code {code}" + (tail.Length > 0 ? $": {tail}" : "");
        }
        return null;
    }

    public async Task StopAsync()
    {
        var proc = Interlocked.Exchange(ref _process, null);
        if (proc is null)
        {
            return;
        }
        try
        {
            if (!proc.HasExited)
            {
                proc.Kill(entireProcessTree: true);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await proc.WaitForExitAsync(cts.Token);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        {
            // already gone, or stuck: nothing more to do
        }
        proc.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// zapret's winws (WinDivert; admin rights). Only the target's traffic is touched: TCP 443 on the physical card,
/// and the desync applies only to <c>--hostlist-domains=&lt;host&gt;</c>.
/// </summary>
public sealed class WinwsEngine(string exePath, int ifIndex) : ProcessEngine(exePath)
{
    public override string Name => "winws";
    public override IReadOnlyList<TuneCandidate> Catalog => TuneCatalog.Winws;

    /// <summary>Where <c>%BIN%</c> files are: next to winws.exe, as in Flowseal's releases.</summary>
    public string BinDir => Path.GetDirectoryName(Path.GetFullPath(ExePath)) ?? "";

    public override bool CanRun(TuneCandidate candidate) => candidate.Files.All(f => File.Exists(Path.Combine(BinDir, f)));

    public override IReadOnlyList<string> BuildArgs(TuneCandidate candidate, string host)
    {
        var args = new List<string>();
        if (ifIndex > 0)
        {
            // Without it WinDivert would also mangle packets inside a VPN tunnel.
            args.Add($"--wf-iface={ifIndex}");
        }
        args.AddRange(["--wf-tcp=443", "--filter-tcp=443", $"--hostlist-domains={host}"]);
        args.AddRange(candidate.Args.Select(a => a.Replace(TuneCandidate.BinToken, BinDir + Path.DirectorySeparatorChar, StringComparison.Ordinal)));
        return args;
    }

    public override string Export(TuneCandidate candidate, string host) =>
        $"--filter-tcp=443 --hostlist-domains={host} {string.Join(' ', candidate.Args.Select(Quote))}";

    private static string Quote(string arg)
    {
        var eq = arg.IndexOf('=', StringComparison.Ordinal);
        return arg.Contains(TuneCandidate.BinToken, StringComparison.Ordinal) && eq > 0 ? $"{arg[..(eq + 1)]}\"{arg[(eq + 1)..]}\"" : arg;
    }

    public override async Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        var (outcome, socket) = await Prober.TcpAsync(ip, port, local, ct);
        return (outcome, socket is null ? null : new NetworkStream(socket, true));
    }
}

/// <summary>
/// ByeDPI (ciadpi): a SOCKS5 proxy on 127.0.0.1 that rewrites outgoing handshakes. No driver, no admin rights.
/// Its outgoing connections are bound to the physical card (<c>-I</c>) so a VPN doesn't carry them.
/// </summary>
public sealed class ByeDpiEngine(string exePath, IPAddress? nicAddress, int port = 10801) : ProcessEngine(exePath)
{
    private static readonly TimeSpan _connectTimeout = TimeSpan.FromSeconds(8);

    public override string Name => "byedpi";
    public override IReadOnlyList<TuneCandidate> Catalog => TuneCatalog.ByeDpi;
    public int Port => port;

    public override IReadOnlyList<string> BuildArgs(TuneCandidate candidate, string host)
    {
        var args = new List<string> { "-i", "127.0.0.1", "-p", port.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        if (nicAddress is not null)
        {
            args.AddRange(["-I", nicAddress.ToString()]);
        }
        args.AddRange(candidate.Args);
        return args;
    }

    public override string Export(TuneCandidate candidate, string host) => "ciadpi " + candidate.ArgLine;

    public override async Task<(string Outcome, Stream? Stream)> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        var (outcome, socket) = await Prober.TcpAsync(IPAddress.Loopback, Port, null, ct);
        if (socket is null)
        {
            return (Outcome.Error, null); // the proxy itself isn't there
        }
        var stream = new NetworkStream(socket, true);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_connectTimeout);
        try
        {
            var result = await Socks5.ConnectAsync(stream, ip, port, cts.Token);
            if (result == Outcome.Ok)
            {
                return (result, stream);
            }
            await stream.DisposeAsync();
            return (result, null);
        }
        catch (Exception ex) when (ex is IOException or SocketException or EndOfStreamException
                                       || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            await stream.DisposeAsync();
            return (NetUtil.Classify(ex, cts.IsCancellationRequested), null);
        }
    }
}
