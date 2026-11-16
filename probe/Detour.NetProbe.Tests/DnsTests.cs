using System.Net;

namespace Detour.NetProbe.Tests;

public class DnsTests
{
    [Test]
    public async Task Query_has_header_question_and_type_A()
    {
        var q = UdpDns.BuildQuery(0x1234, "ya.ru");
        byte[] expected =
        [
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            2, (byte)'y', (byte)'a', 2, (byte)'r', (byte)'u', 0,
            0, 1, 0, 1,
        ];
        await Assert.That(q).IsEquivalentTo(expected);
    }

    /// <summary>The query turned into a reply with the given answers; names in answers are compression pointers.</summary>
    private static byte[] Reply(ushort id, string host, int rcode, params (int Type, byte[] Data)[] answers)
    {
        var q = UdpDns.BuildQuery(id, host);
        q[2] = 0x81;
        q[3] = (byte)(0x80 | rcode);
        q[7] = (byte)answers.Length;
        var p = new List<byte>(q);
        foreach (var (type, data) in answers)
        {
            p.AddRange([0xC0, 0x0C, 0, (byte)type, 0, 1, 0, 0, 0, 60, 0, (byte)data.Length]);
            p.AddRange(data);
        }
        return [.. p];
    }

    [Test]
    public async Task Parses_A_records_and_skips_others()
    {
        var cname = new byte[] { 3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x0C };
        var packet = Reply(7, "example.com", 0, (5, cname), (1, [93, 184, 216, 34]), (1, [10, 0, 0, 1]));
        var answer = UdpDns.Parse(packet, 7);
        await Assert.That(answer).IsNotNull();
        await Assert.That(answer!.Rcode).IsEqualTo(0);
        await Assert.That(answer.Addresses.Select(a => a.ToString())).IsEquivalentTo(["93.184.216.34", "10.0.0.1"]);
    }

    [Test]
    public async Task Rejects_wrong_id_and_truncated_packets()
    {
        var packet = Reply(7, "example.com", 0, (1, [1, 2, 3, 4]));
        await Assert.That(UdpDns.Parse(packet, 8)).IsNull();
        await Assert.That(UdpDns.Parse(packet.AsSpan(0, packet.Length - 3), 7)).IsNull();
        await Assert.That(UdpDns.Parse(UdpDns.BuildQuery(7, "example.com"), 7)).IsNull(); // a query, not a reply
    }

    [Test]
    public async Task Nxdomain_rcode()
    {
        var answer = UdpDns.Parse(Reply(9, "rutracker.org", 3), 9);
        await Assert.That(UdpDns.Classify(answer, [])).IsEqualTo(Outcome.NxDomain);
    }

    [Test]
    [Arguments("10.10.34.36", Outcome.Stub)]
    [Arguments("127.0.0.1", Outcome.Stub)]
    [Arguments("100.64.1.1", Outcome.Stub)]
    [Arguments("1.2.3.4", Outcome.Ok)]
    [Arguments("95.167.13.50", Outcome.Diff)]
    public async Task Classifies_isp_answer_against_doh(string isp, string expected)
    {
        IPAddress[] doh = [IPAddress.Parse("1.2.3.4"), IPAddress.Parse("1.2.3.5")];
        var answer = new DnsAnswer(0, [IPAddress.Parse(isp)]);
        await Assert.That(UdpDns.Classify(answer, doh)).IsEqualTo(expected);
    }

    [Test]
    public async Task Silence_empty_and_servfail()
    {
        await Assert.That(UdpDns.Classify(null, [])).IsEqualTo(Outcome.Timeout);
        await Assert.That(UdpDns.Classify(new DnsAnswer(0, []), [])).IsEqualTo(Outcome.None);
        await Assert.That(UdpDns.Classify(new DnsAnswer(2, []), [])).IsEqualTo(Outcome.Error);
    }

    [Test]
    public async Task Doh_json_answer()
    {
        const string json = """{"Status":0,"Answer":[{"name":"a.","type":5,"data":"b."},{"name":"b.","type":1,"data":"1.2.3.4"}]}""";
        var ips = DohResolver.ParseAnswer(json);
        await Assert.That(ips!.Select(i => i.ToString())).IsEquivalentTo(["1.2.3.4"]);
        await Assert.That(DohResolver.ParseAnswer("""{"Status":3}""")).IsEmpty();
        await Assert.That(DohResolver.ParseAnswer("<html>")).IsNull();
    }
}
