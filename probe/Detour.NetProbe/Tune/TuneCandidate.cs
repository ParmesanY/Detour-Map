using System.Text.RegularExpressions;

namespace Detour.NetProbe;

/// <summary>What a strategy does to the ClientHello. Trace results rule whole classes in or out.</summary>
public static class StrategyClass
{
    /// <summary>Cut into TCP segments, sent in order.</summary>
    public const string Split = "split";
    /// <summary>Cut into segments, sent out of order.</summary>
    public const string Disorder = "disorder";
    /// <summary>Cut into two TLS records (ByeDPI).</summary>
    public const string TlsRec = "tlsrec";
    /// <summary>Out-of-band byte inside the hello (ByeDPI).</summary>
    public const string Oob = "oob";
    /// <summary>A fake ClientHello DPI sees and the server drops (bad seq, timestamp, md5sig, low TTL).</summary>
    public const string Fake = "fake";
    /// <summary>Fakes plus a split or overlapping segments.</summary>
    public const string FakeSplit = "fakesplit";

    public static readonly string[] All = [Split, Disorder, TlsRec, Oob, FakeSplit, Fake];

    /// <summary>A strategy from the registry that isn't in the built-in catalog.</summary>
    public const string Registry = "registry";
}

/// <summary>
/// One strategy to try. <see cref="Args" /> may reference files of the zapret release as <c>%BIN%name.bin</c>
/// (the Flowseal .bat convention), so an exported line can go straight into a .bat.
/// </summary>
public sealed partial record TuneCandidate(string Name, string Class, string[] Args)
{
    public const string BinToken = "%BIN%";

    /// <summary>Files the args need from the engine's folder.</summary>
    public IEnumerable<string> Files => Args.SelectMany(a => FileRegex().Matches(a).Select(m => m.Groups[1].Value));

    public string ArgLine => string.Join(' ', Args);

    [GeneratedRegex(@"%BIN%([\w.\-]+)")]
    private static partial Regex FileRegex();
}

/// <summary>The built-in strategy sets. Grounded in Flowseal's zapret-discord-youtube and ByeDPI's documented options.</summary>
public static class TuneCatalog
{
    private const string GoogleHello = TuneCandidate.BinToken + "tls_clienthello_www_google_com.bin";
    private const string FakeMod = "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com";

    /// <summary>winws (zapret, Windows) / nfqws: desync args for TCP 443.</summary>
    public static readonly TuneCandidate[] Winws =
    [
        new("split-1", StrategyClass.Split, ["--dpi-desync=multisplit", "--dpi-desync-split-pos=1"]),
        new("split-sni", StrategyClass.Split, ["--dpi-desync=multisplit", "--dpi-desync-split-pos=1,sniext+1"]),
        new("split-midsld", StrategyClass.Split, ["--dpi-desync=multisplit", "--dpi-desync-split-pos=midsld"]),
        new("disorder-midsld", StrategyClass.Disorder, ["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"]),
        new("disorder-sni", StrategyClass.Disorder, ["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,sniext+1"]),
        new("seqovl", StrategyClass.FakeSplit,
            ["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-split-seqovl-pattern=" + GoogleHello]),
        new("fake-seqovl-ts", StrategyClass.FakeSplit,
        [
            "--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
            "--dpi-desync-repeats=8", "--dpi-desync-split-seqovl-pattern=" + GoogleHello, FakeMod,
        ]),
        new("fake-disorder-badseq", StrategyClass.FakeSplit,
        [
            "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-repeats=11", "--dpi-desync-fooling=badseq", FakeMod,
        ]),
        new("fake-fakedsplit-badseq", StrategyClass.FakeSplit,
        [
            "--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2",
            "--dpi-desync-repeats=8", FakeMod,
        ]),
        new("fake-hostfakesplit-ts", StrategyClass.FakeSplit,
        [
            "--dpi-desync=fake,hostfakesplit", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru", "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
            "--dpi-desync-fooling=ts",
        ]),
        new("fake-ts", StrategyClass.Fake, ["--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=ts", "--dpi-desync-fake-tls=" + GoogleHello]),
        new("fake-badseq", StrategyClass.Fake,
        [
            "--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2",
            "--dpi-desync-fake-tls=" + GoogleHello,
        ]),
        new("fake-md5sig", StrategyClass.Fake, ["--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=md5sig", FakeMod]),
    ];

    /// <summary>ByeDPI (ciadpi), a local SOCKS proxy: no driver, no admin rights. Positions: <c>1+s</c> = one byte into the SNI.</summary>
    public static readonly TuneCandidate[] ByeDpi =
    [
        new("bd-split-1", StrategyClass.Split, ["-s1"]),
        new("bd-split-sni", StrategyClass.Split, ["-s1+s"]),
        new("bd-disorder-1", StrategyClass.Disorder, ["-d1"]),
        new("bd-disorder-sni", StrategyClass.Disorder, ["-d1+s"]),
        new("bd-disorder-2", StrategyClass.Disorder, ["-d1", "-d3+s"]),
        new("bd-tlsrec-sni", StrategyClass.TlsRec, ["-r1+s"]),
        new("bd-tlsrec-split", StrategyClass.TlsRec, ["-r1+s", "-s1"]),
        new("bd-tlsrec-disorder", StrategyClass.TlsRec, ["-r1+s", "-d1"]),
        new("bd-oob", StrategyClass.Oob, ["-o1"]),
        new("bd-disoob-sni", StrategyClass.Oob, ["-q1+s"]),
        new("bd-fake-disorder", StrategyClass.FakeSplit, ["-d1", "-f1+s", "-t5"]),
        new("bd-fake-tlsrec", StrategyClass.FakeSplit, ["-r1+s", "-f1+s", "-t5"]),
        new("bd-fake-ttl", StrategyClass.Fake, ["-f1+s", "-t5"]),
        new("bd-fake-md5sig", StrategyClass.Fake, ["-f1+s", "-S"]),
    ];
}
