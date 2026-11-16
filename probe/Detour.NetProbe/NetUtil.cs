using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Detour.NetProbe;

public static class NetUtil
{
    /// <summary>TCP connection bound to <paramref name="local" /> (the physical card) when given.</summary>
    public static async Task<Socket> ConnectAsync(IPAddress ip, int port, IPAddress? local, CancellationToken ct)
    {
        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (local is not null && local.AddressFamily == ip.AddressFamily)
            {
                socket.Bind(new IPEndPoint(local, 0));
            }
            await socket.ConnectAsync(ip, port, ct);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Private, loopback, link-local, CGNAT and benchmark ranges: what ISP DNS stubs return.</summary>
    public static bool IsBogon(IPAddress a)
    {
        if (a.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }
        var b = a.GetAddressBytes();
        return b[0] is 0 or 10 or 127
               || (b[0] == 169 && b[1] == 254)
               || (b[0] == 172 && b[1] is >= 16 and <= 31)
               || (b[0] == 192 && b[1] == 168)
               || (b[0] == 100 && b[1] is >= 64 and <= 127)
               || (b[0] == 198 && b[1] is 18 or 19);
    }

    /// <summary>
    /// Outcome of a failed connect / handshake / read. <paramref name="timedOut" />: our own deadline fired.
    /// A TLS alert means the server refused; a reset, a bare close or silence is what DPI does.
    /// </summary>
    public static string Classify(Exception ex, bool timedOut)
    {
        if (timedOut || ex is OperationCanceledException)
        {
            return Outcome.Timeout;
        }
        if (ex is AuthenticationException && Innermost(ex) is not SocketException)
        {
            return Outcome.Alert;
        }
        if (Innermost(ex) is SocketException se)
        {
            return se.SocketErrorCode switch
            {
                SocketError.ConnectionReset or SocketError.ConnectionAborted => Outcome.Reset,
                SocketError.ConnectionRefused => Outcome.Refused,
                SocketError.TimedOut => Outcome.Timeout,
                _ => Outcome.Error,
            };
        }
        // "Received an unexpected EOF or 0 bytes from the transport stream": closed mid-handshake.
        return ex is IOException ? Outcome.Reset : Outcome.Error;
    }

    private static Exception Innermost(Exception ex)
    {
        while (ex.InnerException is not null)
        {
            ex = ex.InnerException;
        }
        return ex;
    }
}
