using System.Text.Json;

namespace Detour.NetProbe;

/// <summary>
/// VPN transports by ISP (<c>/v1/transports</c>): how a client's VPN connection fared per transport kind. Only the
/// kind from <see cref="Kinds"/> is sent: never a server address, name or provider. Shared list: spec/transports.json.
/// </summary>
public sealed class TransportReport
{
    public int V { get; set; } = 1;
    public required string Client { get; set; }
    public required string Net { get; set; }
    public required ProbeEnv Env { get; set; }
    public List<TransportResult> Results { get; set; } = [];

    public static readonly IReadOnlyList<string> Kinds =
    [
        "vless-reality", "vless-reality-xhttp", "vless-tls", "vless-xhttp", "vless-ws", "vless-grpc", "vmess", "trojan",
        "shadowsocks", "hysteria2", "tuic", "wireguard", "amneziawg", "warp", "other",
    ];
}

/// <summary>Checks of one transport since the last report: passed cleanly, froze (data stopped after a few KB), failed.</summary>
public sealed class TransportResult
{
    public required string Transport { get; set; }
    public int Ok { get; set; }
    public int Frozen { get; set; }
    public int Fail { get; set; }
}

public sealed class TransportStat
{
    public string Transport { get; set; } = "";
    public int Reporters { get; set; }
    public int Checks { get; set; }
    /// <summary>Share of checks that passed cleanly / froze, 0..1.</summary>
    public double Ok { get; set; }
    public double Frozen { get; set; }
}

public sealed class TransportHints
{
    public long Asn { get; set; }
    public string? AsOrg { get; set; }
    public List<TransportStat> Transports { get; set; } = [];
}

public static class Transports
{
    /// <summary>The asking ISP's transports (the collector reads the ISP from the connection); null when unreachable.</summary>
    public static async Task<TransportHints?> GetAsync(Uri endpoint, NicInfo? nic, CancellationToken ct = default)
    {
        using var doh = new DohResolver(nic?.Address);
        using var client = ReportSender.CreateClient(nic?.Address, doh);
        try
        {
            using var response = await client.GetAsync(new Uri(endpoint, "/v1/transports"), ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            return JsonSerializer.Deserialize(await response.Content.ReadAsStringAsync(ct), ProbeJson.Default.TransportHints);
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or IOException
                                       || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    public static Task<SendResult> SendAsync(TransportReport report, Uri endpoint, NicInfo? nic, CancellationToken ct = default) =>
        ReportSender.PostAsync(endpoint, "/v1/transports", JsonSerializer.Serialize(report, ProbeJson.Default.TransportReport), nic, ct);
}
