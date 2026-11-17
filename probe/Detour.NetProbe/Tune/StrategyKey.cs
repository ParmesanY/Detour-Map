using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Detour.NetProbe;

/// <summary>
/// One key per strategy, whatever way it was written: the registry counts "works for ISP X" per key, and a client
/// starts nothing it got from the registry unless it normalizes cleanly here. Context args (which traffic, which
/// interface, where to listen) are dropped; only an allowlist of desync options passes; files are reduced to
/// <c>%BIN%name.bin</c>. The collector does the same in <c>collector/src/strategy.ts</c>; shared cases are in
/// <c>spec/strategy-cases.json</c>.
/// </summary>
public static partial class StrategyKey
{
    public const string Winws = "winws";
    public const string ByeDpi = "byedpi";
    public const int MaxTokens = 24;
    public const int MaxKeyLength = 600;

    /// <summary>Error codes: engine, option, value, empty, too_long.</summary>
    public sealed record Result(string? Key, string? Error)
    {
        /// <summary>The args part of the key, as tokens.</summary>
        public string[] Tokens => Key is null ? [] : Key[(Key.IndexOf(':') + 1)..].Split(' ');
    }

    public static Result Normalize(string engine, string line) => Normalize(engine, Tokenize(line));

    public static Result Normalize(string engine, IEnumerable<string> args)
    {
        var tokens = args.Where(t => t.Length > 0).ToList();
        var (list, error) = engine switch
        {
            Winws => NormalizeWinws(tokens),
            ByeDpi => NormalizeByeDpi(tokens),
            _ => (null, "engine"),
        };
        if (error is not null)
        {
            return new Result(null, error);
        }
        if (list!.Count == 0)
        {
            return new Result(null, "empty");
        }
        var key = $"{engine}:{string.Join(' ', list)}";
        return list.Count > MaxTokens || key.Length > MaxKeyLength ? new Result(null, "too_long") : new Result(key, null);
    }

    /// <summary>Short stable ID of a key: 12 hex chars of SHA-256.</summary>
    public static string Id(string key) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..12];

    /// <summary>Splits on spaces; double quotes group and are removed.</summary>
    public static List<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        var any = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                quoted = !quoted;
                any = true;
            }
            else if (char.IsWhiteSpace(ch) && !quoted)
            {
                if (any || sb.Length > 0)
                {
                    tokens.Add(sb.ToString());
                }
                sb.Clear();
                any = false;
            }
            else
            {
                sb.Append(ch);
            }
        }
        if (any || sb.Length > 0)
        {
            tokens.Add(sb.ToString());
        }
        return tokens;
    }

    // ---- winws / nfqws ----

    private static readonly string[] _winwsContext = ["--filter-", "--hostlist", "--ipset", "--wf-", "--new", "--skip", "--comment"];

    private static (List<string>?, string?) NormalizeWinws(List<string> tokens)
    {
        var kept = new List<(string Name, string Token)>();
        foreach (var token in tokens)
        {
            var eq = token.IndexOf('=');
            var name = (eq < 0 ? token : token[..eq]).ToLowerInvariant();
            var value = eq < 0 ? null : token[(eq + 1)..];
            if (_winwsContext.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
            {
                continue;
            }
            if (!WinwsOption().IsMatch(name))
            {
                return (null, "option");
            }
            if (value is null)
            {
                kept.Add((name, name));
                continue;
            }
            value = value.Replace("^", "", StringComparison.Ordinal);
            if (IsFile(value))
            {
                var file = value[(value.LastIndexOfAny(['\\', '/', '%']) + 1)..];
                if (!BinFile().IsMatch(file))
                {
                    return (null, "value");
                }
                value = TuneCandidate.BinToken + file;
            }
            else if (value.Length > 120 || !WinwsValue().IsMatch(value))
            {
                return (null, "value");
            }
            kept.Add((name, $"{name}={value}"));
        }
        // Option order within a profile doesn't matter to winws; repeated options keep their order (stable sort).
        return ([.. kept.OrderBy(k => k.Name, StringComparer.Ordinal).Select(k => k.Token)], null);
    }

    private static bool IsFile(string value) =>
        value.Contains(TuneCandidate.BinToken, StringComparison.Ordinal) || value.Contains('\\') || value.Contains('/')
        || value.EndsWith(".bin", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"^--(dpi-desync(-[a-z0-9]+)*|ip-id|dup(-[a-z0-9]+)*|orig(-[a-z0-9]+)*)$")]
    private static partial Regex WinwsOption();

    [GeneratedRegex(@"^[A-Za-z0-9_.,:+\-=!]*$")]
    private static partial Regex WinwsValue();

    [GeneratedRegex(@"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*\.bin$")]
    private static partial Regex BinFile();

    // ---- ByeDPI (ciadpi) ----

    private static readonly Dictionary<string, char> _byeLong = new()
    {
        ["split"] = 's', ["disorder"] = 'd', ["oob"] = 'o', ["disoob"] = 'q', ["fake"] = 'f', ["ttl"] = 't', ["tlsrec"] = 'r',
        ["mod-http"] = 'M', ["fake-sni"] = 'n', ["md5sig"] = 'S',
        ["ip"] = 'i', ["port"] = 'p', ["conn-ip"] = 'I', ["max-conn"] = 'c', ["pidfile"] = 'w', ["buf-size"] = 'b', ["debug"] = 'x',
        ["daemon"] = 'D', ["no-udp"] = 'U',
    };

    private const string ByeDesyncWithValue = "sdoqftrMn";
    private const string ByeDesyncFlags = "S";
    private const string ByeContextWithValue = "ipIcwbx";
    private const string ByeContextFlags = "DU";

    private static (List<string>?, string?) NormalizeByeDpi(List<string> tokens)
    {
        if (tokens.Count > 0 && Path.GetFileNameWithoutExtension(tokens[0].Replace('\\', '/').Split('/')[^1]).Equals("ciadpi", StringComparison.OrdinalIgnoreCase))
        {
            tokens = tokens[1..];
        }
        var kept = new List<string>();
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            char opt;
            string? value;
            if (token.StartsWith("--", StringComparison.Ordinal))
            {
                var eq = token.IndexOf('=');
                var name = eq < 0 ? token[2..] : token[2..eq];
                if (!_byeLong.TryGetValue(name, out opt))
                {
                    return (null, "option");
                }
                value = eq < 0 ? null : token[(eq + 1)..];
            }
            else if (token.Length >= 2 && token[0] == '-' && char.IsAsciiLetter(token[1]))
            {
                opt = token[1];
                value = token.Length > 2 ? token[2..] : null;
            }
            else
            {
                return (null, "option");
            }

            var needsValue = ByeDesyncWithValue.Contains(opt) || ByeContextWithValue.Contains(opt);
            var isFlag = ByeDesyncFlags.Contains(opt) || ByeContextFlags.Contains(opt);
            if (!needsValue && !isFlag)
            {
                return (null, "option");
            }
            if (needsValue && value is null)
            {
                if (i + 1 >= tokens.Count)
                {
                    return (null, "value");
                }
                value = tokens[++i];
            }
            if (isFlag && value is not null)
            {
                return (null, "value");
            }
            if (ByeContextWithValue.Contains(opt) || ByeContextFlags.Contains(opt))
            {
                continue;
            }
            if (value is not null && (value.Length > 60 || !ByeValue().IsMatch(value)))
            {
                return (null, "value");
            }
            kept.Add($"-{opt}{value}");
        }
        return (kept, null);
    }

    [GeneratedRegex(@"^[A-Za-z0-9_.,:+\-]+$")]
    private static partial Regex ByeValue();
}
