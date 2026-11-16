using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Detour.NetProbe;

public sealed record DnsAnswer(int Rcode, IPAddress[] Addresses);

/// <summary>
/// A bare A query over UDP to the ISP's resolver, sent from the physical card. The system resolver can't be
/// used: under a VPN's TUN it answers with the tunnel's fake addresses. The first matching reply wins, so an
/// answer injected by DPI on the way is what we see, as a browser would.
/// </summary>
public static class UdpDns
{
    public static byte[] BuildQuery(ushort id, string host)
    {
        var packet = new List<byte>(18 + host.Length)
        {
            (byte)(id >> 8), (byte)id, 0x01, 0x00, // recursion desired
            0, 1, 0, 0, 0, 0, 0, 0,                // one question
        };
        foreach (var label in host.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
            {
                throw new ArgumentException($"Bad host name '{host}'.", nameof(host));
            }
            packet.Add((byte)bytes.Length);
            packet.AddRange(bytes);
        }
        packet.AddRange([0, 0, 1, 0, 1]); // root, type A, class IN
        return [.. packet];
    }

    /// <summary>Null when the packet isn't a well-formed answer to query <paramref name="id" />.</summary>
    public static DnsAnswer? Parse(ReadOnlySpan<byte> p, ushort id)
    {
        if (p.Length < 12 || ((p[0] << 8) | p[1]) != id || (p[2] & 0x80) == 0)
        {
            return null;
        }
        try
        {
            var questions = (p[4] << 8) | p[5];
            var answers = (p[6] << 8) | p[7];
            var pos = 12;
            for (var i = 0; i < questions; i++)
            {
                pos = SkipName(p, pos) + 4;
            }
            var ips = new List<IPAddress>();
            for (var i = 0; i < answers; i++)
            {
                pos = SkipName(p, pos);
                var type = (p[pos] << 8) | p[pos + 1];
                var cls = (p[pos + 2] << 8) | p[pos + 3];
                var length = (p[pos + 8] << 8) | p[pos + 9];
                pos += 10;
                if (type == 1 && cls == 1 && length == 4)
                {
                    ips.Add(new IPAddress(p.Slice(pos, 4)));
                }
                pos += length;
            }
            return new DnsAnswer(p[3] & 0x0F, [.. ips]);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static int SkipName(ReadOnlySpan<byte> p, int pos)
    {
        while (true)
        {
            var length = p[pos];
            if (length == 0)
            {
                return pos + 1;
            }
            if ((length & 0xC0) == 0xC0)
            {
                return pos + 2; // compression pointer ends the name
            }
            pos += length + 1;
        }
    }

    /// <summary>Null on silence or an ICMP error (two tries, 2 s each).</summary>
    public static async Task<DnsAnswer?> QueryAsync(IPAddress server, string host, IPAddress? local, CancellationToken ct)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (local is not null && local.AddressFamily == server.AddressFamily)
        {
            socket.Bind(new IPEndPoint(local, 0));
        }
        var id = (ushort)Random.Shared.Next(ushort.MaxValue + 1);
        var query = BuildQuery(id, host);
        var buffer = new byte[1500];
        var any = new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            try
            {
                await socket.SendToAsync(query, new IPEndPoint(server, 53), cts.Token);
                while (true)
                {
                    var r = await socket.ReceiveFromAsync(buffer, any, cts.Token);
                    if (Parse(buffer.AsSpan(0, r.ReceivedBytes), id) is { } answer)
                    {
                        return answer;
                    }
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // silence: try again
            }
            catch (SocketException)
            {
                return null;
            }
        }
        return null;
    }

    /// <summary>The ISP's answer against DoH's.</summary>
    public static string Classify(DnsAnswer? isp, IReadOnlyCollection<IPAddress> doh)
    {
        if (isp is null)
        {
            return Outcome.Timeout;
        }
        if (isp.Rcode == 3)
        {
            return Outcome.NxDomain;
        }
        if (isp.Rcode != 0)
        {
            return Outcome.Error;
        }
        if (isp.Addresses.Length == 0)
        {
            return Outcome.None;
        }
        if (isp.Addresses.Any(NetUtil.IsBogon))
        {
            return Outcome.Stub;
        }
        return doh.Count > 0 && !isp.Addresses.Any(doh.Contains) ? Outcome.Diff : Outcome.Ok;
    }
}
