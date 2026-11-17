using System.Text;

namespace Detour.NetProbe;

/// <summary>
/// Sends the first write (the TLS ClientHello) as two TCP segments, cut in the middle of the server name, with a short
/// pause between them. DPI that doesn't reassemble segments then never sees the whole name; if the handshake passes
/// this way but not in one piece, zapret / ByeDPI "split" strategies will work for this site.
/// Needs a socket with NoDelay, or Nagle may glue the pieces back together.
/// </summary>
public sealed class SplitHelloStream(Stream inner, string host, TimeSpan pause) : Stream
{
    private bool _split;

    /// <summary>Where to cut: the middle of the name if it is in the buffer, else after the first 6 bytes.</summary>
    public static int SplitPoint(ReadOnlySpan<byte> buffer, string host)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var at = buffer.IndexOf(name);
        if (at >= 0)
        {
            return at + Math.Max(1, name.Length / 2);
        }
        return Math.Min(6, Math.Max(1, buffer.Length - 1));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_split || buffer.Length < 2)
        {
            await inner.WriteAsync(buffer, cancellationToken);
            return;
        }
        _split = true;
        var cut = SplitPoint(buffer.Span, host);
        await inner.WriteAsync(buffer[..cut], cancellationToken);
        await inner.FlushAsync(cancellationToken);
        await Task.Delay(pause, cancellationToken);
        await inner.WriteAsync(buffer[cut..], cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override void Flush() => inner.Flush();
    public override bool CanRead => inner.CanRead;
    public override bool CanWrite => inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await inner.DisposeAsync();
        await base.DisposeAsync();
    }
}
