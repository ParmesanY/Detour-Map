using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace Detour.NetProbe;

/// <summary>The collector's answer to a report.</summary>
public sealed class SendResult
{
    public int HttpStatus { get; set; }
    public bool Accepted { get; set; }
    public string? Error { get; set; }
    public List<string>? Flags { get; set; }
    /// <summary>Target ID → verdicts as the collector computed them.</summary>
    public Dictionary<string, List<string>>? Verdicts { get; set; }
}

/// <summary>
/// Posts a report to the collector over the physical network card. Sent through a VPN, the collector would
/// see the VPN server's network instead of the ISP's, and the report would land in the wrong place on the map.
/// </summary>
public static class ReportSender
{
    public static async Task<SendResult> SendAsync(ProbeReport report, Uri endpoint, NicInfo? nic, CancellationToken ct = default)
    {
        var local = nic?.Address;
        using var doh = new DohResolver(local);
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (ctx, c) =>
            {
                var host = ctx.DnsEndPoint.Host;
                IPAddress[] addresses;
                if (IPAddress.TryParse(host, out var literal))
                {
                    addresses = [literal];
                }
                else if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    addresses = [IPAddress.Loopback];
                }
                else
                {
                    // DoH: under a VPN's TUN the system resolver would hand out the tunnel's fake addresses.
                    addresses = await doh.ResolveAsync(host, c) ?? await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, c);
                }
                var ip = addresses.FirstOrDefault() ?? throw new HttpRequestException($"Can't resolve {host}.");
                var socket = await NetUtil.ConnectAsync(ip, ctx.DnsEndPoint.Port, IPAddress.IsLoopback(ip) ? null : local, c);
                return new NetworkStream(socket, true);
            },
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        var json = JsonSerializer.Serialize(report, ProbeJson.Default.ProbeReport);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await client.PostAsync(new Uri(endpoint, "/v1/report"), content, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        SendResult? result = null;
        try
        {
            result = JsonSerializer.Deserialize(text, ProbeJson.Default.SendResult);
        }
        catch (JsonException)
        {
            // not the collector's JSON (a proxy's error page, say)
        }
        result ??= new SendResult { Error = text.Length > 200 ? text[..200] : text };
        result.HttpStatus = (int)response.StatusCode;
        return result;
    }
}
