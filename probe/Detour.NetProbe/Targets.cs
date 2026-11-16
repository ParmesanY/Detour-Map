using System.Text.Json;

namespace Detour.NetProbe;

public static class TargetKind
{
    /// <summary>A domestic site that is never blocked: if it fails, there is no network.</summary>
    public const string Control = "control";
    /// <summary>A foreign hosting test file: the "16 KB freeze" and whitelist mode show here.</summary>
    public const string Hosting = "hosting";
    public const string Site = "site";
    /// <summary>A bare address, TCP only (Telegram data centres and the like).</summary>
    public const string Ip = "ip";
}

public sealed class Target
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string Kind { get; set; } = TargetKind.Site;
    public string? Host { get; set; }
    public string? Ip { get; set; }
    public int Port { get; set; } = 443;
    public string Path { get; set; } = "/";
    public bool Tls { get; set; } = true;
    public bool Quic { get; set; }
}

public sealed class TargetList
{
    public int Version { get; set; }
    public List<Target> Targets { get; set; } = [];

    /// <summary>The list built into the library (spec/targets.json).</summary>
    public static TargetList Default { get; } = LoadEmbedded();

    public static TargetList Parse(string json)
    {
        var list = JsonSerializer.Deserialize(json, ProbeJson.Default.TargetList)
                   ?? throw new InvalidDataException("Empty target list.");
        list.Validate();
        return list;
    }

    public void Validate()
    {
        var ids = new HashSet<string>();
        foreach (var t in Targets)
        {
            if (!ids.Add(t.Id))
            {
                throw new InvalidDataException($"Duplicate target id '{t.Id}'.");
            }
            if (t.Host is null && t.Ip is null)
            {
                throw new InvalidDataException($"Target '{t.Id}' has neither host nor ip.");
            }
            if (t.Ip is not null && !System.Net.IPAddress.TryParse(t.Ip, out _))
            {
                throw new InvalidDataException($"Target '{t.Id}' has a bad ip '{t.Ip}'.");
            }
            if (t.Host is null && (t.Tls || t.Quic))
            {
                throw new InvalidDataException($"Target '{t.Id}' needs a host for TLS / QUIC.");
            }
        }
    }

    private static TargetList LoadEmbedded()
    {
        using var stream = typeof(TargetList).Assembly.GetManifestResourceStream("Detour.NetProbe.targets.json")
                           ?? throw new InvalidOperationException("targets.json is not embedded.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }
}
