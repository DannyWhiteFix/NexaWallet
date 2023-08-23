// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netaddress.h"
#include "netbase.h"
#include "test/test_nexa.h"

#include <string>

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(netbase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(netbase_networks)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetNetwork() == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("::1").GetNetwork() == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("8.8.8.8").GetNetwork() == NET_IPV4);
    BOOST_CHECK(CNetAddr("2001::8888").GetNetwork() == NET_IPV6);
}

BOOST_AUTO_TEST_CASE(netbase_properties)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::FFFF:192.168.1.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::1").IsIPv6());
    BOOST_CHECK(CNetAddr("10.0.0.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("192.168.1.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("172.31.255.255").IsRFC1918());
    BOOST_CHECK(CNetAddr("2001:0DB8::").IsRFC3849());
    BOOST_CHECK(CNetAddr("169.254.1.1").IsRFC3927());
    BOOST_CHECK(CNetAddr("2002::1").IsRFC3964());
    BOOST_CHECK(CNetAddr("FC00::").IsRFC4193());
    BOOST_CHECK(CNetAddr("2001::2").IsRFC4380());
    BOOST_CHECK(CNetAddr("2001:10::").IsRFC4843());
    BOOST_CHECK(CNetAddr("FE80::").IsRFC4862());
    BOOST_CHECK(CNetAddr("64:FF9B::").IsRFC6052());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsLocal());
    BOOST_CHECK(CNetAddr("::1").IsLocal());
    BOOST_CHECK(CNetAddr("8.8.8.8").IsRoutable());
    BOOST_CHECK(CNetAddr("2001::1").IsRoutable());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsValid());
}

bool static TestSplitHost(string test, string host, int port)
{
    string hostOut;
    int portOut = -1;
    SplitHostPort(test, portOut, hostOut);
    return hostOut == host && port == portOut;
}

BOOST_AUTO_TEST_CASE(netbase_splithost)
{
    BOOST_CHECK(TestSplitHost("www.nexa.org", "www.nexa.org", -1));
    BOOST_CHECK(TestSplitHost("[www.nexa.org]", "www.nexa.org", -1));
    BOOST_CHECK(TestSplitHost("www.nexa.org:80", "www.nexa.org", 80));
    BOOST_CHECK(TestSplitHost("[www.nexa.org]:80", "www.nexa.org", 80));
    BOOST_CHECK(TestSplitHost("127.0.0.1", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("127.0.0.1:7228", "127.0.0.1", 7228));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]:7228", "127.0.0.1", 7228));
    BOOST_CHECK(TestSplitHost("::ffff:127.0.0.1", "::ffff:127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[::ffff:127.0.0.1]:7228", "::ffff:127.0.0.1", 7228));
    BOOST_CHECK(TestSplitHost("[::]:7228", "::", 7228));
    BOOST_CHECK(TestSplitHost("::7228", "::7228", -1));
    BOOST_CHECK(TestSplitHost(":7228", "", 7228));
    BOOST_CHECK(TestSplitHost("[]:7228", "", 7228));
    BOOST_CHECK(TestSplitHost("", "", -1));
}

bool static TestParse(string src, string canon)
{
    CService addr;
    if (!LookupNumeric(src.c_str(), addr, 65535))
        return canon == "";
    return canon == addr.ToString();
}

BOOST_AUTO_TEST_CASE(netbase_lookupnumeric)
{
    BOOST_CHECK(TestParse("127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("127.0.0.1:7228", "127.0.0.1:7228"));
    BOOST_CHECK(TestParse("::ffff:127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("::", "[::]:65535"));
    BOOST_CHECK(TestParse("[::]:7228", "[::]:7228"));
    BOOST_CHECK(TestParse("[127.0.0.1]", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse(":::", ""));
}

BOOST_AUTO_TEST_CASE(subnet_test)
{
    BOOST_CHECK(CSubNet("1.2.3.0/24") == CSubNet("1.2.3.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24") != CSubNet("1.2.4.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.2.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4/32").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.3.4").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(!CSubNet("1.2.3.4/32").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(CSubNet("::ffff:127.0.0.1").Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:0/112").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("192.168.0.1/24").Match(CNetAddr("192.168.0.2")));
    BOOST_CHECK(CSubNet("192.168.0.20/29").Match(CNetAddr("192.168.0.18")));
    BOOST_CHECK(CSubNet("1.2.2.1/24").Match(CNetAddr("1.2.2.4")));
    BOOST_CHECK(CSubNet("1.2.2.110/31").Match(CNetAddr("1.2.2.111")));
    BOOST_CHECK(CSubNet("1.2.2.20/26").Match(CNetAddr("1.2.2.63")));
    // All-Matching IPv6 Matches arbitrary IPv4 and IPv6
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    // Can not match from one network type to another (IPV6 to IPV4)
    BOOST_CHECK(!CSubNet("::/0").Match(CNetAddr("1.2.3.4")));
    // All-Matching IPv4 does not Match IPv6
    BOOST_CHECK(!CSubNet("0.0.0.0/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    // Invalid subnets Match nothing (not even invalid addresses)
    BOOST_CHECK(!CSubNet().Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("").Match(CNetAddr("4.5.6.7")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("0.0.0.0")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("hab")));
    // Check valid/invalid
    BOOST_CHECK(CSubNet("1.2.3.0/0").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/-1").IsValid());
    BOOST_CHECK(CSubNet("1.2.3.0/32").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/33").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/0").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/33").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/-1").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/128").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/129").IsValid());
    BOOST_CHECK(!CSubNet("fuzzy").IsValid());

    // CNetAddr constructor test
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).IsValid());
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(!CSubNet(CNetAddr("127.0.0.1")).Match(CNetAddr("127.0.0.2")));
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).ToString() == "127.0.0.1/32");

    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).IsValid());
    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).ToString() == "1:2:3:4:5:6:7:8/128");

    CSubNet subnet = CSubNet("1.2.3.4/255.255.255.255");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/32");
    subnet = CSubNet("1.2.3.4/255.255.255.254");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/31");
    subnet = CSubNet("1.2.3.4/255.255.255.252");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/30");
    subnet = CSubNet("1.2.3.4/255.255.255.248");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/29");
    subnet = CSubNet("1.2.3.4/255.255.255.240");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/28");
    subnet = CSubNet("1.2.3.4/255.255.255.224");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/27");
    subnet = CSubNet("1.2.3.4/255.255.255.192");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/26");
    subnet = CSubNet("1.2.3.4/255.255.255.128");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/25");
    subnet = CSubNet("1.2.3.4/255.255.255.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/24");
    subnet = CSubNet("1.2.3.4/255.255.254.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.2.0/23");
    subnet = CSubNet("1.2.3.4/255.255.252.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/22");
    subnet = CSubNet("1.2.3.4/255.255.248.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/21");
    subnet = CSubNet("1.2.3.4/255.255.240.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/20");
    subnet = CSubNet("1.2.3.4/255.255.224.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/19");
    subnet = CSubNet("1.2.3.4/255.255.192.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/18");
    subnet = CSubNet("1.2.3.4/255.255.128.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/17");
    subnet = CSubNet("1.2.3.4/255.255.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/16");
    subnet = CSubNet("1.2.3.4/255.254.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/15");
    subnet = CSubNet("1.2.3.4/255.252.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/14");
    subnet = CSubNet("1.2.3.4/255.248.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/13");
    subnet = CSubNet("1.2.3.4/255.240.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/12");
    subnet = CSubNet("1.2.3.4/255.224.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/11");
    subnet = CSubNet("1.2.3.4/255.192.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/10");
    subnet = CSubNet("1.2.3.4/255.128.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/9");
    subnet = CSubNet("1.2.3.4/255.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/8");
    subnet = CSubNet("1.2.3.4/254.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/7");
    subnet = CSubNet("1.2.3.4/252.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/6");
    subnet = CSubNet("1.2.3.4/248.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/5");
    subnet = CSubNet("1.2.3.4/240.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/4");
    subnet = CSubNet("1.2.3.4/224.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/3");
    subnet = CSubNet("1.2.3.4/192.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/2");
    subnet = CSubNet("1.2.3.4/128.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/1");
    subnet = CSubNet("1.2.3.4/0.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/0");

    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1:2:3:4:5:6:7:8/128");
    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:0000:0000:0000:0000:0000:0000:0000");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1::/16");
    subnet = CSubNet("1:2:3:4:5:6:7:8/0000:0000:0000:0000:0000:0000:0000:0000");
    BOOST_CHECK_EQUAL(subnet.ToString(), "::/0");
    subnet = CSubNet("1.2.3.4/255.255.232.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/255.255.232.0");
    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ff0f");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1:2:3:4:5:6:7:8/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ff0f");
}

BOOST_AUTO_TEST_CASE(netbase_getgroup)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetGroup() == (std::vector<unsigned char>{0})); // Local -> !Routable()
    BOOST_CHECK(CNetAddr("257.0.0.1").GetGroup() == (std::vector<unsigned char>{0})); // !Valid -> !Routable()
    BOOST_CHECK(CNetAddr("10.0.0.1").GetGroup() == (std::vector<unsigned char>{0})); // RFC1918 -> !Routable()
    BOOST_CHECK(CNetAddr("169.254.1.1").GetGroup() == (std::vector<unsigned char>{0})); // RFC3927 -> !Routable()
    BOOST_CHECK(CNetAddr("1.2.3.4").GetGroup() == (std::vector<unsigned char>{NET_IPV4, 1, 2})); // IPv4
    // RFC6145
    BOOST_CHECK(CNetAddr("::FFFF:0:102:304").GetGroup() == (std::vector<unsigned char>{NET_IPV4, 1, 2}));
    // RFC6052
    BOOST_CHECK(CNetAddr("64:FF9B::102:304").GetGroup() == (std::vector<unsigned char>{NET_IPV4, 1, 2}));
    // RFC3964
    BOOST_CHECK(
        CNetAddr("2002:102:304:9999:9999:9999:9999:9999").GetGroup() == (std::vector<unsigned char>{NET_IPV4, 1, 2}));
    // RFC4380
    BOOST_CHECK(
        CNetAddr("2001:0:9999:9999:9999:9999:FEFD:FCFB").GetGroup() == (std::vector<unsigned char>{NET_IPV4, 1, 2}));
    // he.net
    BOOST_CHECK(CNetAddr("2001:470:abcd:9999:9999:9999:9999:9999").GetGroup() ==
                (std::vector<unsigned char>{NET_IPV6, 32, 1, 4, 112, 175}));
    // IPv6
    BOOST_CHECK(CNetAddr("2001:2001:9999:9999:9999:9999:9999:9999").GetGroup() ==
                (std::vector<unsigned char>{NET_IPV6, 32, 1, 32, 1}));
}

// Since CNetAddr (un)ser is tested separately in net_tests.cpp here we only
// try a few edge cases for port, service flags and time.

static const std::vector<CAddress> fixture_addresses({CAddress(CService(CNetAddr(in6addr_loopback), 0 /* port */),
                                                          NODE_NONE,
                                                          0x4966bc61U /* Fri Jan  9 02:54:25 UTC 2009 */
                                                          ),
    CAddress(CService(CNetAddr(in6addr_loopback), 0x00f1 /* port */),
        NODE_NETWORK,
        0x83766279U /* Tue Nov 22 11:22:33 UTC 2039 */
        ),
    CAddress(CService(CNetAddr(in6addr_loopback), 0xf1f2 /* port */),
        NODE_NETWORK_LIMITED,
        0xffffffffU /* Sun Feb  7 06:28:15 UTC 2106 */
        )});

/* clang-format off */

// fixture_addresses should equal to this when serialized in V1 format.
// When this is unserialized from V1 format it should equal to fixture_addresses.
// note that time is not serialized in addrv1
static constexpr const char *stream_addrv1_hex =
    "03" // number of entries

    //"61bc6649" // time, Fri Jan  9 02:54:25 UTC 2009
    "0000000000000000" // service flags, NODE_NONE
    "00000000000000000000000000000001" // address, fixed 16 bytes (IPv4 embedded in IPv6)
    "0000" // port

    //"79627683" // time, Tue Nov 22 11:22:33 UTC 2039
    "0100000000000000" // service flags, NODE_NETWORK
    "00000000000000000000000000000001" // address, fixed 16 bytes (IPv6)
    "00f1" // port

    //"ffffffff" // time, Sun Feb  7 06:28:15 UTC 2106
    "0004000000000000" // service flags, NODE_NETWORK_LIMITED
    "00000000000000000000000000000001" // address, fixed 16 bytes (IPv6)
    "f1f2"; // port

// fixture_addresses should equal to this when serialized in V2 format.
// When this is unserialized from V2 format it should equal to fixture_addresses.
static constexpr const char *stream_addrv2_hex =
    "03" // number of entries

    "61bc6649" // time, Fri Jan  9 02:54:25 UTC 2009
    "00" // service flags, COMPACTSIZE(NODE_NONE)
    "02" // network id, IPv6
    "10" // address length, COMPACTSIZE(16)
    "00000000000000000000000000000001" // address
    "0000" // port

    "79627683" // time, Tue Nov 22 11:22:33 UTC 2039
    "01" // service flags, COMPACTSIZE(NODE_NETWORK)
    "02" // network id, IPv6
    "10" // address length, COMPACTSIZE(16)
    "00000000000000000000000000000001" // address
    "00f1" // port

    "ffffffff" // time, Sun Feb  7 06:28:15 UTC 2106
    "fd0004" // service flags, COMPACTSIZE(NODE_NETWORK_LIMITED)
    "02" // network id, IPv6
    "10" // address length, COMPACTSIZE(16)
    "00000000000000000000000000000001" // address
    "f1f2"; // port

/* clang-format on */

BOOST_AUTO_TEST_CASE(caddress_serialize_v1)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << fixture_addresses;
    BOOST_CHECK_EQUAL(HexStr(s), stream_addrv1_hex);
}

BOOST_AUTO_TEST_CASE(caddress_unserialize_v1)
{
    CDataStream s(ParseHex(stream_addrv1_hex), SER_NETWORK, PROTOCOL_VERSION);
    std::vector<CAddress> addresses_unserialized;

    s >> addresses_unserialized;
    BOOST_CHECK(fixture_addresses == addresses_unserialized);
}

BOOST_AUTO_TEST_CASE(caddress_serialize_v2)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);

    s << fixture_addresses;
    BOOST_CHECK_EQUAL(HexStr(s), stream_addrv2_hex);
}

BOOST_AUTO_TEST_CASE(caddress_unserialize_v2)
{
    CDataStream s(ParseHex(stream_addrv2_hex), SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    std::vector<CAddress> addresses_unserialized;

    s >> addresses_unserialized;
    BOOST_CHECK(fixture_addresses == addresses_unserialized);
}

BOOST_AUTO_TEST_SUITE_END()
