using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Detour.NetProbe;

/// <summary>Minimal SOCKS5 CONNECT by IP address (RFC 1928, no auth): enough to go through ByeDPI.</summary>
public static class Socks5
{
    /// <summary>Asks the proxy on <paramref name="stream" /> to connect to ip:port. Returns an <see cref="Outcome" />.</summary>
    public static async Task<string> ConnectAsync(Stream stream, IPAddress ip, int port, CancellationToken ct)
    {
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, ct);
        var hello = new byte[2];
        await stream.ReadExactlyAsync(hello, ct);
        if (hello[0] != 5 || hello[1] != 0)
        {
            return Outcome.Error;
        }

        var addr = ip.GetAddressBytes();
        var request = new byte[4 + addr.Length + 2];
        request[0] = 5;
        request[1] = 1; // CONNECT
        request[3] = (byte)(ip.AddressFamily == AddressFamily.InterNetworkV6 ? 4 : 1);
        addr.CopyTo(request, 4);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4 + addr.Length), (ushort)port);
        await stream.WriteAsync(request, ct);

        var head = new byte[4];
        await stream.ReadExactlyAsync(head, ct);
        if (head[0] != 5)
        {
            return Outcome.Error;
        }
        var rest = head[3] switch
        {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => await ReadByteAsync(stream, ct) + 2,
            _ => -1,
        };
        if (rest < 0)
        {
            return Outcome.Error;
        }
        await stream.ReadExactlyAsync(new byte[rest], ct);
        return head[1] switch
        {
            0 => Outcome.Ok,
            4 or 6 => Outcome.Timeout, // host unreachable, TTL expired
            5 => Outcome.Refused,
            _ => Outcome.Error,
        };
    }

    private static async Task<int> ReadByteAsync(Stream stream, CancellationToken ct)
    {
        var b = new byte[1];
        await stream.ReadExactlyAsync(b, ct);
        return b[0];
    }
}
