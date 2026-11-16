using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace Detour.NetProbe;

/// <summary>
/// The real addresses of a host: DNS-over-HTTPS to resolvers addressed by IP, over the physical card,
/// so neither the ISP's DNS nor a VPN tunnel can change the answer.
/// </summary>
public sealed class DohResolver : IDisposable
{
    private static readonly string[] _urls =
    [
        "https://1.1.1.1/dns-query?type=A&name=",
        "https://8.8.8.8/resolve?type=A&name=",
    ];

    private readonly HttpClient _client;

    public DohResolver(IPAddress? local)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (ctx, ct) =>
            {
                var socket = await NetUtil.ConnectAsync(IPAddress.Parse(ctx.DnsEndPoint.Host), ctx.DnsEndPoint.Port, local, ct);
                return new NetworkStream(socket, true);
            },
        };
        _client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }

    /// <summary>Null when every resolver failed; empty when the name has no A records.</summary>
    public async Task<IPAddress[]?> ResolveAsync(string host, CancellationToken ct)
    {
        foreach (var url in _urls)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url + Uri.EscapeDataString(host));
                request.Headers.Accept.ParseAdd("application/dns-json");
                using var response = await _client.SendAsync(request, ct);
                if (ParseAnswer(await response.Content.ReadAsStringAsync(ct)) is { } ips)
                {
                    return ips;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException
                                           || (ex is OperationCanceledException && !ct.IsCancellationRequested))
            {
                // next resolver
            }
        }
        return null;
    }

    /// <summary>A records of a DNS JSON answer (Google / Cloudflare format); null if it isn't one.</summary>
    public static IPAddress[]? ParseAnswer(string json)
    {
        try
        {
            var root = JsonNode.Parse(json);
            if (root?["Status"] is null)
            {
                return null;
            }
            return root["Answer"]?.AsArray()
                .Where(a => a?["type"]?.GetValue<int>() == 1)
                .Select(a => IPAddress.TryParse(a!["data"]?.GetValue<string>(), out var ip) ? ip : null)
                .OfType<IPAddress>()
                .ToArray() ?? [];
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    public void Dispose() => _client.Dispose();
}
