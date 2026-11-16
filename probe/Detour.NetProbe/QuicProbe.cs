using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;

namespace Detour.NetProbe;

/// <summary>Does a QUIC (HTTP/3) handshake to port 443/udp complete? Russian DPI often drops QUIC wholesale.</summary>
public static class QuicProbe
{
    private static readonly TimeSpan _timeout = TimeSpan.FromSeconds(5);

    public static async Task<string> RunAsync(IPAddress ip, string host, IPAddress? local, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return Outcome.Unsupported;
        }
        return await HandshakeAsync(ip, host, local, ct);
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static async Task<string> HandshakeAsync(IPAddress ip, string host, IPAddress? local, CancellationToken ct)
    {
        if (!QuicConnection.IsSupported)
        {
            return Outcome.Unsupported;
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        try
        {
            await using var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(ip, 443),
                LocalEndPoint = local is null ? null : new IPEndPoint(local, 0),
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                HandshakeTimeout = _timeout,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    ApplicationProtocols = [new SslApplicationProtocol("h3")],
                    // Only reachability is measured; nothing is sent over the connection.
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                },
            }, cts.Token);
            return Outcome.Ok;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Outcome.Timeout;
        }
        catch (QuicException ex)
        {
            return ex.QuicError switch
            {
                QuicError.ConnectionTimeout or QuicError.ConnectionIdle => Outcome.Timeout,
                QuicError.ConnectionRefused => Outcome.Refused,
                _ => Outcome.Error,
            };
        }
        catch (AuthenticationException)
        {
            return Outcome.Alert;
        }
    }
}
