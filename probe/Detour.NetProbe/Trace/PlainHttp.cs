using System.Text;
using System.Text.RegularExpressions;

namespace Detour.NetProbe;

/// <summary>An answer to plain HTTP (port 80): ISPs answer blocked sites with their own page or a redirect to it.</summary>
public sealed record PlainHttpAnswer(int? Status, string? Location, bool BlockPage);

public static partial class PlainHttp
{
    /// <summary>Words of block pages and the hosts they redirect to (RKN registry, ISP stub pages).</summary>
    [GeneratedRegex(@"rkn\.gov|eais\.|blocklist|blocked|zapret-info|warning\.rt\.ru|доступ\s+(к\s+\S+\s+)?ограничен|заблокирован|ограничен\s+по\s+решению|блокировк",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BlockWords();

    [GeneratedRegex(@"^Location:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LocationHeader();

    public static PlainHttpAnswer Parse(ReadOnlySpan<byte> response, string host)
    {
        var text = Encoding.UTF8.GetString(response);
        var status = Prober.ParseStatus(response);
        var headEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var head = headEnd >= 0 ? text[..headEnd] : text;
        var body = headEnd >= 0 ? text[(headEnd + 4)..] : "";
        var location = LocationHeader().Match(head) is { Success: true } m ? m.Groups[1].Value : null;

        var block = status == 451;
        if (location is not null && Uri.TryCreate(location, UriKind.Absolute, out var target))
        {
            // A redirect to the same site (http → https, www) is normal; to a stub page is not.
            var sameSite = target.Host.Equals(host, StringComparison.OrdinalIgnoreCase)
                           || target.Host.EndsWith("." + host, StringComparison.OrdinalIgnoreCase)
                           || host.EndsWith("." + target.Host, StringComparison.OrdinalIgnoreCase);
            block |= !sameSite && BlockWords().IsMatch(location);
        }
        block |= status is 200 or 403 && BlockWords().IsMatch(body);
        return new PlainHttpAnswer(status, location, block);
    }
}
