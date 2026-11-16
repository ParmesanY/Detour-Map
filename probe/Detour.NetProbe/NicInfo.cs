using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Detour.NetProbe;

/// <summary>
/// The default physical network card. Every probe binds to its address, so a VPN tunnel (which owns the
/// default route) doesn't carry it, and DNS goes to the card's own resolvers, not to the tunnel's.
/// </summary>
public sealed record NicInfo(string Name, IPAddress Address, IReadOnlyList<IPAddress> DnsServers)
{
    private static readonly HashSet<NetworkInterfaceType> _physicalTypes =
    [
        NetworkInterfaceType.Ethernet, NetworkInterfaceType.Wireless80211, NetworkInterfaceType.GigabitEthernet,
        NetworkInterfaceType.FastEthernetFx, NetworkInterfaceType.FastEthernetT,
    ];

    private static readonly string[] _physicalNamePrefixes = ["eth", "enp", "ens", "eno", "enx", "wlp", "wlan", "en0", "en1", "en2"];

    private static readonly string[] _physicalKeywords = ["ethernet", "wlan", "wi-fi", "wifi", "airport"];

    /// <summary>Names of VPN / TUN adapters (Detour's own sing-box TUN included). Declared before
    /// <see cref="_virtualKeywords" />: static fields initialise in order.</summary>
    internal static readonly string[] VpnKeywords =
    [
        "wintun", "wireguard", "tap-windows", "tap adapter", "openvpn", "anyconnect", "vpn", "sing-box", "singbox",
        "xray", "clash", "mihomo", "amnezia", "outline", "throne", "tailscale", "zerotier", "utun",
    ];

    private static readonly string[] _virtualKeywords =
    [
        "virtual", "loopback", "loop back", "hyper-v", "vmware", "virtualbox", "vbox", "docker", "veth", "virbr",
        "cni", "flannel", "cali", "kube", "npcap", "wan miniport", "lightweight filter", "filter driver",
        "packet scheduler", "kernel debug", .. VpnKeywords,
    ];

    public static NicInfo? Detect()
    {
        try
        {
            var physical = NetworkInterface.GetAllNetworkInterfaces().Where(IsPhysical).ToList();
            var withGateway = physical.Where(HasIPv4Gateway).ToList();
            var candidates = withGateway.Count > 0 ? withGateway : physical;
            var nic = candidates.FirstOrDefault(n => n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet)
                      ?? candidates.FirstOrDefault(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                      ?? candidates.FirstOrDefault();
            if (nic is null)
            {
                return null;
            }
            var props = nic.GetIPProperties();
            var address = props.UnicastAddresses.Select(a => a.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (address is null)
            {
                return null;
            }
            var dns = props.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
            return new NicInfo(nic.Name, address, dns);
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    /// <summary>Is any VPN / TUN adapter up?</summary>
    public static bool VpnAdapterUp()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                n.OperationalStatus == OperationalStatus.Up && (IsVpnName(n.Name) || IsVpnName(n.Description)));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    internal static bool IsVpnName(string text)
    {
        var lower = text.ToLowerInvariant();
        return VpnKeywords.Any(lower.Contains)
               || System.Text.RegularExpressions.Regex.IsMatch(lower, @"^(tun|tap|wg|utun)\d*$");
    }

    private static bool IsPhysical(NetworkInterface n)
    {
        if (n.OperationalStatus != OperationalStatus.Up || !n.Supports(NetworkInterfaceComponent.IPv4))
        {
            return false;
        }
        var text = $"{n.Name} {n.Description}".ToLowerInvariant();
        if (_virtualKeywords.Any(text.Contains) || IsVpnName(n.Name))
        {
            return false;
        }
        return _physicalTypes.Contains(n.NetworkInterfaceType)
               || _physicalNamePrefixes.Any(p => n.Name.StartsWith(p, StringComparison.OrdinalIgnoreCase))
               || _physicalKeywords.Any(text.Contains);
    }

    private static bool HasIPv4Gateway(NetworkInterface n)
    {
        try
        {
            return n.GetIPProperties().GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork
                && !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.None));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }
}
