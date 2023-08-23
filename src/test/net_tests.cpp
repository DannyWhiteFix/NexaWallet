// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addrman.h"
#include "chainparams.h"
#include "hashwrapper.h"
#include "net.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>
#include <string>

extern CTweak<int> maxConnections;

bool AttemptToEvictConnection(const unsigned int nMaxInbound);
void CleanupDisconnectedNodes();

// Simulate a graceful disconnect has occurred
static void GracefulDisconnect(std::vector<CNode *> &_vNodes)
{
    for (auto pnode : _vNodes)
    {
        if (pnode->fDisconnectRequest)
        {
            pnode->fDisconnect = true;
        }
    }
}

using namespace std;

// BOOST_CHECK_EXCEPTION predicates to check the specific validation error
class HasReason
{
public:
    HasReason(const std::string &reason) : m_reason(reason) {}
    bool operator()(const std::runtime_error &e) const
    {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };

private:
    const std::string m_reason;
};

class CAddrManSerializationMock : public CAddrMan
{
public:
    virtual void Serialize(CDataStream &s) const = 0;

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        insecure_rand = FastRandomContext(true);
    }
};

class CAddrManUncorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const { CAddrMan::Serialize(s); }
};

class CAddrManCorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const
    {
        // Produces corrupt output that claims addrman has 20 addrs when it only has one addr.
        unsigned char nVersion = 1;
        s << nVersion;
        s << uint8_t(32);
        s << nKey;
        s << 10; // nNew
        s << 10; // nTried

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
        s << nUBuckets;

        CAddress addr = CAddress(CService("252.1.1.1", 7777));
        CAddrInfo info = CAddrInfo(addr, CNetAddr("252.2.2.2"));
        s << info;
    }
};

CDataStream AddrmanToStream(CAddrManSerializationMock &_addrman)
{
    CDataStream ssPeersIn(SER_DISK, CLIENT_VERSION);
    ssPeersIn << FLATDATA(Params().MessageStart());
    ssPeersIn << _addrman;
    std::string str = ssPeersIn.str();
    std::vector<uint8_t> vchData(str.begin(), str.end());
    return CDataStream(vchData, SER_DISK, CLIENT_VERSION);
}

BOOST_FIXTURE_TEST_SUITE(net_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(caddrdb_read)
{
    CAddrManUncorrupted addrmanUncorrupted;
    addrmanUncorrupted.MakeDeterministic();

    CService addr1 = CService("250.7.1.1", 7228);
    CService addr2 = CService("250.7.2.2", 9999);
    CService addr3 = CService("250.7.3.3", 9999);

    // Add three addresses to new table.
    addrmanUncorrupted.Add(CAddress(addr1), CService("252.5.1.1", 7228));
    addrmanUncorrupted.Add(CAddress(addr2), CService("252.5.1.1", 7228));
    addrmanUncorrupted.Add(CAddress(addr3), CService("252.5.1.1", 7228));

    // Test that the de-serialization does not throw an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanUncorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;

    BOOST_CHECK(addrman1.size() == 0);
    try
    {
        uint8_t pchMsgTmp[4];
        ssPeers1 >> FLATDATA(pchMsgTmp);
        ssPeers1 >> addrman1;
    }
    catch (const std::exception &e)
    {
        exceptionThrown = true;
    }

    BOOST_CHECK(addrman1.size() == 3);
    BOOST_CHECK(exceptionThrown == false);

    // Test that CAddrDB::Read creates an addrman with the correct number of addrs.
    CDataStream ssPeers2 = AddrmanToStream(addrmanUncorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    adb.Read(addrman2, ssPeers2);
    BOOST_CHECK(addrman2.size() == 3);
}


BOOST_AUTO_TEST_CASE(caddrdb_read_corrupted)
{
    CAddrManCorrupted addrmanCorrupted;
    addrmanCorrupted.MakeDeterministic();

    // Test that the de-serialization of corrupted addrman throws an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanCorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;
    BOOST_CHECK(addrman1.size() == 0);
    try
    {
        uint8_t pchMsgTmp[4];
        ssPeers1 >> FLATDATA(pchMsgTmp);
        ssPeers1 >> addrman1;
    }
    catch (const std::exception &e)
    {
        exceptionThrown = true;
    }
    // Even through de-serialization failed addrman is not left in a clean state.
    BOOST_CHECK(addrman1.size() == 1);
    BOOST_CHECK(exceptionThrown);

    // Test that CAddrDB::Read leaves addrman in a clean state if de-serialization fails.
    CDataStream ssPeers2 = AddrmanToStream(addrmanCorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    adb.Read(addrman2, ssPeers2);
    BOOST_CHECK(addrman2.size() == 0);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    SOCKET hSocket = INVALID_SOCKET;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest = "";
    bool fInboundIn = false;

    // Test that fFeeler is false by default.
    std::unique_ptr<CNode> pnode1(new CNode(hSocket, addr, pszDest, fInboundIn));
    BOOST_CHECK(pnode1->fInbound == false);
    BOOST_CHECK(pnode1->fFeeler == false);

    fInboundIn = true;
    std::unique_ptr<CNode> pnode2(new CNode(hSocket, addr, pszDest, fInboundIn));
    BOOST_CHECK(pnode2->fInbound == true);
    BOOST_CHECK(pnode2->fFeeler == false);

    // NodeRef checks and refcount checks.
    BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);

    // Check null pointers are good
    {
        CNodeRef ref; // Default constructor
        BOOST_CHECK(!ref); // operator bool
        ref = 0;
        BOOST_CHECK(!ref);
    }

    // get()
    {
        CNodeRef ref1(pnode1.get());
        CNodeRef ref2;
        BOOST_CHECK(ref1.get() == pnode1.get());
        BOOST_CHECK(ref2.get() == nullptr);
    }

    // Plain constructor and copy constructor
    {
        CNodeRef ref1(pnode1.get());
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);

        {
            CNodeRef ref2(ref1);
            BOOST_CHECK_EQUAL(pnode1->nRefCount, 2);
        }

        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
    }
    BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);

    // Assignment operator
    {
        CNodeRef ref1;

        ref1 = pnode1.get();
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
        ref1 = ref1;
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
        ref1 = nullptr;
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);
    }
    BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    std::vector<CNetAddr> vAddr;

    // IPv4, INADDR_ANY
    BOOST_REQUIRE(LookupHost("0.0.0.0", vAddr, 1, false));
    BOOST_REQUIRE(!vAddr[0].IsValid());
    BOOST_REQUIRE(vAddr[0].IsIPv4());

    BOOST_CHECK(vAddr[0].IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(vAddr[0].ToString(), "0.0.0.0");

    // IPv4, INADDR_NONE
    vAddr.clear();
    BOOST_REQUIRE(LookupHost("255.255.255.255", vAddr, 1, false));
    BOOST_REQUIRE(!vAddr[0].IsValid());
    BOOST_REQUIRE(vAddr[0].IsIPv4());

    BOOST_CHECK(vAddr[0].IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(vAddr[0].ToString(), "255.255.255.255");

    // IPv4, casual
    vAddr.clear();
    BOOST_REQUIRE(LookupHost("12.34.56.78", vAddr, 1, false));
    BOOST_REQUIRE(vAddr[0].IsValid());
    BOOST_REQUIRE(vAddr[0].IsIPv4());

    BOOST_CHECK(vAddr[0].IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(vAddr[0].ToString(), "12.34.56.78");

    // IPv6, in6addr_any
    vAddr.clear();
    BOOST_REQUIRE(LookupHost("::", vAddr, 1, false));
    BOOST_REQUIRE(!vAddr[0].IsValid());
    BOOST_REQUIRE(vAddr[0].IsIPv6());

    BOOST_CHECK(vAddr[0].IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(vAddr[0].ToString(), "::");

    // IPv6, casual
    vAddr.clear();
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", vAddr, 1, false));
    BOOST_REQUIRE(vAddr[0].IsValid());
    BOOST_REQUIRE(vAddr[0].IsIPv6());

    BOOST_CHECK(vAddr[0].IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(vAddr[0].ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");
    vAddr.clear();

    // TORv3
    CNetAddr addr_tor3;
    const char *torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr_tor3.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr_tor3.IsValid());
    BOOST_REQUIRE(addr_tor3.IsTor3());

    BOOST_CHECK(!addr_tor3.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr_tor3.ToString(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr_tor3.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr_tor3.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(
        !addr_tor3.SetSpecial(std::string{"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr_tor3.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr_tor3.SetSpecial(std::string{"mf*g zak.onion"}));

    // Internal
    CNetAddr addr;
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    std::vector<CNetAddr> vAddr;
    CNetAddr addr;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", vAddr, 1, false));
    s << vAddr[0];
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    vAddr.clear();
    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", vAddr, 1, false));
    s << vAddr[0];
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_CHECK_EQUAL(addr.SetSpecial("6hzph5hv6337r6p2.onion"), false);

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

// The ip field is a fixed length in BU so the HexStr for v2 serialization will
// be longer than would be with a dynamic sized ip field
// the compact size will always be 0x20 and non-32 byte addresses will
// have an extra bytes of 0's at the end
BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    std::vector<CNetAddr> vAddr;
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", vAddr, 1, false));
    s << vAddr[0];
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();
    vAddr.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", vAddr, 1, false));
    s << vAddr[0];
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_CHECK_EQUAL(addr.SetSpecial("6hzph5hv6337r6p2.onion"), false);

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    std::vector<uint8_t> vHex = ParseHex("01" // network type (IPv4)
                                         "04" // address length
                                         "01020304"); // address
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    vHex = ParseHex("01" // network type (IPv4)
                    "04" // address length
                    "0102"); // address
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    vHex = ParseHex("01" // network type (IPv4)
                    "05" // address length
                    "01020304"); // address
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(
        s >> addr, std::ios_base::failure, HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    vHex = ParseHex("01" // network type (IPv4)
                    "fd0102" // address length (513 as CompactSize)
                    "01020304"); // address
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    vHex = ParseHex("02" // network type (IPv6)
                    "10" // address length
                    "0102030405060708090a0b0c0d0e0f10"); // address
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    vHex = ParseHex("02" // network type (IPv6)
                    "10" // address length
                    "fd6b88c08724ca978112ca1bbdcafac2"); // address: 0xfd + sha256("bitcoin")[0:5] +
                                                         // sha256(name)[0:10]
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    vHex = ParseHex("02" // network type (IPv6)
                    "04" // address length
                    "00"); // address
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(
        s >> addr, std::ios_base::failure, HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    vHex = ParseHex("02" // network type (IPv6)
                    "10" // address length
                    "00000000000000000000ffff01020304"); // address
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    vHex = ParseHex("04" // network type (TORv3)
                    "20" // address length
                    "79bcc625184b05194975c28b66b66b04" // address
                    "69f7f6556fb1ac3189a79b40dda32f1f");
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor3());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    vHex = ParseHex("04" // network type (TORv3)
                    "00" // address length
                    "00" // address
    );
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(
        s >> addr, std::ios_base::failure, HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    vHex = ParseHex("05" // network type (I2P)
                    "20" // address length
                    "a2894dabaec08c0051a481a6dac88b64" // address
                    "f98232ae42d4b6fd2fa81952dfe36a87");
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    vHex = ParseHex("05" // network type (I2P)
                    "03" // address length
                    "00" // address
    );
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(
        s >> addr, std::ios_base::failure, HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    vHex = ParseHex("06" // network type (CJDNS)
                    "10" // address length
                    "fc000001000200030004000500060007" // address
    );
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    vHex = ParseHex("06" // network type (CJDNS)
                    "01" // address length
                    "00" // address
    );
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(
        s >> addr, std::ios_base::failure, HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    vHex = ParseHex("aa" // network type (unknown)
                    "fe00000002" // address length (CompactSize's MAX_SIZE)
                    "01020304050607" // address
    );
    s << CFlatData(vHex);
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    vHex = ParseHex("aa" // network type (unknown)
                    "04" // address length
                    "01020304" // address
    );
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    vHex = ParseHex("aa" // network type (unknown)
                    "00" // address length
                    "" // address
    );
    s << CFlatData(vHex);
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}


BOOST_AUTO_TEST_CASE(test_userAgent)
{
    const std::vector<std::string> uacomments{"A very nice comment"};
    int temp = 0;
    int *ptemp = &temp;
    std::string arch = (sizeof(ptemp) == 4) ? "32bit" : "64bit";
    mapArgs["-uacomment"] = uacomments[0];
    std::string client_name(CLIENT_NAME);

    std::string versionMessage = "/" + client_name + ":" + std::to_string(CLIENT_VERSION_MAJOR) + "." +
                                 std::to_string(CLIENT_VERSION_MINOR) + "." + std::to_string(CLIENT_VERSION_REVISION);

    if (std::to_string(CLIENT_VERSION_BUILD) != "0")
    {
        versionMessage = versionMessage + "." + std::to_string(CLIENT_VERSION_BUILD);
    }
    versionMessage = versionMessage + "(" + uacomments[0] + "; " + arch + ")/";

    BOOST_CHECK_EQUAL(FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments), versionMessage);
}

BOOST_AUTO_TEST_CASE(test_attemptToEvict)
{
    LOCK(cs_vNodes);
    auto vNodesCopy = vNodes;
    vNodes.clear();

    int nMaxConnectionsCopy = maxConnections.Value();

    // Setup test nodes
    CAddress addr1(ipaddress(0xa0b0c001, 10000));
    CAddress addr2(ipaddress(0xa0b0c002, 10001));
    CAddress addr3(ipaddress(0xa0b0c003, 10002));
    CAddress addr4(ipaddress(0xa0b0c004, 10003));
    CAddress addr5(ipaddress(0xa0b0c005, 10004));
    CAddress addr6(ipaddress(0xa0b0c005, 10004));
    CAddress addr7(ipaddress(0xa0b0c005, 10004));
    CAddress addr8(ipaddress(0xa0b0c005, 10004));
    CAddress addr9(ipaddress(0xa0b0c005, 10004));
    CAddress addr10(ipaddress(0xa0b0c005, 10004));
    CAddress addr11(ipaddress(0xa0b0c005, 10004));
    CAddress addr12(ipaddress(0xa0b0c005, 10004));
    CAddress addr13(ipaddress(0xa0b0c005, 10004));
    CAddress addr14(ipaddress(0xa0b0c005, 10004));
    CAddress addr15(ipaddress(0xa0b0c005, 10004));
    CAddress addr16(ipaddress(0xa0b0c005, 10004));
    CAddress addr17(ipaddress(0xa0b0c005, 10004));
    CAddress addr18(ipaddress(0xa0b0c005, 10004));
    CAddress addr19(ipaddress(0xa0b0c005, 10004));
    CAddress addr20(ipaddress(0xa0b0c005, 10004));

    // Setup Inbound Network Nodes
    CNode *node1 = new CNode(INVALID_SOCKET, addr1, "", true);
    node1->nTimeConnected = GetTime();
    node1->fWhitelisted = false;
    node1->fInbound = true;
    node1->fClient = false;
    node1->nActivityBytes = 1000;
    node1->fDisconnect = false;

    CNode *node2 = new CNode(INVALID_SOCKET, addr2, "", true);
    node2->nTimeConnected = GetTime();
    node2->fWhitelisted = false;
    node2->fInbound = true;
    node2->fClient = false;
    node2->fDisconnect = false;
    node2->nActivityBytes = 2000;

    CNode *node3 = new CNode(INVALID_SOCKET, addr3, "", true);
    node3->nTimeConnected = GetTime();
    node3->fWhitelisted = false;
    node3->fInbound = true;
    node3->fClient = false;
    node3->fDisconnect = false;
    node3->nActivityBytes = 3000;

    CNode *node4 = new CNode(INVALID_SOCKET, addr4, "", true);
    node4->nTimeConnected = GetTime();
    node4->fWhitelisted = false;
    node4->fInbound = true;
    node4->fClient = false;
    node4->fDisconnect = false;
    node4->nActivityBytes = 4000;

    CNode *node5 = new CNode(INVALID_SOCKET, addr5, "", true);
    node5->nTimeConnected = GetTime();
    node5->fWhitelisted = false;
    node5->fInbound = true;
    node5->fClient = false;
    node5->fDisconnect = false;
    node5->nActivityBytes = 5000;

    CNode *node6 = new CNode(INVALID_SOCKET, addr6, "", true);
    node6->nTimeConnected = GetTime();
    node6->fWhitelisted = false;
    node6->fInbound = true;
    node6->fClient = false;
    node6->fDisconnect = false;
    node6->nActivityBytes = 6000;

    CNode *node7 = new CNode(INVALID_SOCKET, addr7, "", true);
    node7->nTimeConnected = GetTime();
    node7->fWhitelisted = false;
    node7->fInbound = true;
    node7->fClient = false;
    node7->fDisconnect = false;
    node7->nActivityBytes = 7000;

    CNode *node8 = new CNode(INVALID_SOCKET, addr8, "", true);
    node8->nTimeConnected = GetTime();
    node8->fWhitelisted = false;
    node8->fInbound = true;
    node8->fClient = false;
    node8->fDisconnect = false;
    node8->nActivityBytes = 8000;

    CNode *node9 = new CNode(INVALID_SOCKET, addr9, "", true);
    node9->nTimeConnected = GetTime();
    node9->fWhitelisted = false;
    node9->fInbound = true;
    node9->fClient = false;
    node9->fDisconnect = false;
    node9->nActivityBytes = 9000;

    CNode *node10 = new CNode(INVALID_SOCKET, addr10, "", true);
    node10->nTimeConnected = GetTime();
    node10->fWhitelisted = false;
    node10->fInbound = true;
    node10->fClient = false;
    node10->fDisconnect = false;
    node10->nActivityBytes = 10000;

    // Setup outbound Network nodes
    CNode *node11 = new CNode(INVALID_SOCKET, addr11, "", true);
    node11->nTimeConnected = GetTime();
    node11->fWhitelisted = false;
    node11->fInbound = false;
    node11->fClient = false;
    node11->fDisconnect = false;
    node11->nActivityBytes = 110;

    CNode *node12 = new CNode(INVALID_SOCKET, addr12, "", true);
    node12->nTimeConnected = GetTime();
    node12->fWhitelisted = false;
    node12->fInbound = false;
    node12->fClient = false;
    node12->fDisconnect = false;
    node12->nActivityBytes = 120;

    CNode *node13 = new CNode(INVALID_SOCKET, addr13, "", true);
    node13->nTimeConnected = GetTime();
    node13->fWhitelisted = false;
    node13->fInbound = false;
    node13->fClient = false;
    node13->fDisconnect = false;
    node13->nActivityBytes = 130;

    CNode *node14 = new CNode(INVALID_SOCKET, addr14, "", true);
    node14->nTimeConnected = GetTime();
    node14->fWhitelisted = false;
    node14->fInbound = false;
    node14->fClient = false;
    node14->fDisconnect = false;
    node14->nActivityBytes = 140;

    CNode *node15 = new CNode(INVALID_SOCKET, addr15, "", true);
    node15->nTimeConnected = GetTime();
    node15->fWhitelisted = false;
    node15->fInbound = false;
    node15->fClient = false;
    node15->fDisconnect = false;
    node15->nActivityBytes = 15000;

    // Setup fClients
    CNode *node16 = new CNode(INVALID_SOCKET, addr16, "", true);
    node16->nTimeConnected = GetTime();
    node16->fWhitelisted = false;
    node16->fInbound = true;
    node16->fClient = true;
    node16->fDisconnect = false;
    node16->nActivityBytes = 16;

    CNode *node17 = new CNode(INVALID_SOCKET, addr17, "", true);
    node17->nTimeConnected = GetTime();
    node17->fWhitelisted = false;
    node17->fInbound = true;
    node17->fClient = true;
    node17->fDisconnect = false;
    node17->nActivityBytes = 17;

    CNode *node18 = new CNode(INVALID_SOCKET, addr18, "", true);
    node18->nTimeConnected = GetTime();
    node18->fWhitelisted = false;
    node18->fInbound = true;
    node18->fClient = true;
    node18->fDisconnect = false;
    node18->nActivityBytes = 18;

    CNode *node19 = new CNode(INVALID_SOCKET, addr19, "", true);
    node19->nTimeConnected = GetTime();
    node19->fWhitelisted = false;
    node19->fInbound = true;
    node19->fClient = true;
    node19->fDisconnect = false;
    node19->nActivityBytes = 19;

    CNode *node20 = new CNode(INVALID_SOCKET, addr20, "", true);
    node20->nTimeConnected = GetTime();
    node20->fWhitelisted = false;
    node20->fInbound = true;
    node20->fClient = true;
    node20->fDisconnect = false;
    node20->nActivityBytes = 20;

    /** Setup the basic network configuration of 3 outbound and 7 inbound network nodes */
    // Add outbound network nodes.
    vNodes.push_back(node11);
    vNodes.push_back(node12);
    vNodes.push_back(node13);
    // Add inbound network nodes
    vNodes.push_back(node1);
    vNodes.push_back(node2);
    vNodes.push_back(node3);
    vNodes.push_back(node4);
    vNodes.push_back(node5);
    vNodes.push_back(node6);
    vNodes.push_back(node7);


    int64_t nStartTime = GetTime();

    /**
     *  Check basic eviction scenarios
     */

    // Set the time so that we are over the time guarantee for Clients and so can be evicted by activity.
    // Further down we'll reset this and verify the time guarantee works.
    SetMockTime(nStartTime + 60);

    // Network slots "not" full: basic check - all network nodes.
    // We should be starting with 10 network nodes in vNodes (3 outbound, 7 inbound)
    // Result: Nothing should be evicted.
    int nMaxInbound = 8;
    maxConnections.Set(11);
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, false); // peer with lowest activity should not be disconnected

    // Network slots full: basic check - all network nodes
    // We should be starting with 10 network nodes in vNodes (3 outbound, 7 inbound)
    // Although max connections is one greater than the size of vNodes, the max inbound matches
    // the total inbound so there should be one eviction.
    // Result: The configured outbound nodes have lower activity but we only evict inbound ones.
    //         So only one inbound should be evicted.
    nMaxInbound = 7;
    maxConnections.Set(11);
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, true); // the peer with lowest activity should be disconnected
    node1->fDisconnect = false; // reset the flag

    // Network slots full: basic check - all network nodes
    // We should be starting with 10 network nodes in vNodes (3 outbound, 7 inbound)
    // Result: one should be evicted.
    nMaxInbound = 7;
    maxConnections.Set(10);
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, true); // the peer with lowest activity should be disconnected
    node1->fDisconnect = false; // reset the flag

    // Add a client until the client slots are full.
    // This should evict network nodes
    nMaxInbound = 8;
    maxConnections.Set(11);
    vNodes.push_back(node16); // add client
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 11UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, true); // the peer with lowest activity should be disconnected
    BOOST_CHECK_EQUAL(node16->fDisconnect, false); // the client has lowest activity but should NOT be disconnected
    node1->fDisconnect = false; // reset the flag

    // Try to evict a whiltelisted node. It should not be possible.
    nMaxInbound = 8;
    maxConnections.Set(11);
    node1->fWhitelisted = true;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 11UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node2->fDisconnect, true); // the lowest activity "non-whitelisted" peer should be disconnected
    BOOST_CHECK_EQUAL(node16->fDisconnect, false); // the client has lowest activity but should NOT be disconnected
    node2->fDisconnect = false; // reset the flag
    node1->fWhitelisted = false; // reset

    // Add more clients beyond the number that would be protected and make one of them
    // the lowest activity.
    // Result: the lowest activity peer that happens to be a client will get disconnected.
    nMaxInbound = 9;
    maxConnections.Set(12);
    vNodes.push_back(node17); // add client
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 12UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, false); // the network peer with lowest activity will not be disconnected
    BOOST_CHECK_EQUAL(node16->fDisconnect, true); // the client has lowest activity will be disconnected
    node16->fDisconnect = false; // reset the flag

    // Add more clients beyond the number that would be protected and make the clients
    // have the higher activity.
    // Result: the lowest activity network node will get disconnected.
    vNodes.push_back(node18); // add client
    nMaxInbound = 10;
    maxConnections.Set(13);
    node16->nActivityBytes = 1001;
    node17->nActivityBytes = 2000;
    node18->nActivityBytes = 100000;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 13UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, true); // the network peer with lowest activity will not be disconnected
    BOOST_CHECK_EQUAL(node16->fDisconnect, false); // the client has highest activity will not be disconnected
    BOOST_CHECK_EQUAL(node17->fDisconnect, false); // the client has highest activity will not be disconnected
    node1->fDisconnect = false; // reset the flag
    node16->nActivityBytes = 16; // reset
    node17->nActivityBytes = 17; // reset
    node17->nActivityBytes = 18; // reset


    /** Check the time guarantee for Client connections.  With the time guarantee a client
     *  can not get bumped by any peer during the time guarantee period, even if it has low activity.
     *
     *  Use up all the connections we have.  This should give us 2 guaranteed slots for clients
     *  and three non guaranteed.
     */
    SetMockTime(nStartTime);

    vNodes.push_back(node8);
    vNodes.push_back(node9);
    vNodes.push_back(node10);
    vNodes.push_back(node14);
    vNodes.push_back(node15);
    vNodes.push_back(node19);
    vNodes.push_back(node20);

    // Let the time guarantee for a client expire
    nMaxInbound = 15;
    maxConnections.Set(20);
    node16->nTimeConnected = nStartTime - 60;
    node17->nTimeConnected = nStartTime - 59;
    node18->nTimeConnected = nStartTime - 59;
    node19->nTimeConnected = nStartTime - 59;
    node20->nTimeConnected = nStartTime - 59;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL); // vnodes will not change yet, only the fDisconnect flag will be set->
    BOOST_CHECK_EQUAL(node16->fDisconnect, true);
    node16->fDisconnect = false;

    nMaxInbound = 15;
    maxConnections.Set(20);
    node16->nTimeConnected = nStartTime - 59;
    node17->nTimeConnected = nStartTime - 60;
    node18->nTimeConnected = nStartTime - 59;
    node19->nTimeConnected = nStartTime - 59;
    node20->nTimeConnected = nStartTime - 59;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node17->fDisconnect, true);
    node17->fDisconnect = false;

    nMaxInbound = 15;
    maxConnections.Set(20);
    node16->nTimeConnected = nStartTime - 59;
    node17->nTimeConnected = nStartTime - 60;
    node18->nTimeConnected = nStartTime - 60;
    node19->nTimeConnected = nStartTime - 59;
    node20->nTimeConnected = nStartTime - 59;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node17->fDisconnect, true);
    node17->fDisconnect = false;

    nMaxInbound = 15;
    maxConnections.Set(20);
    node16->nTimeConnected = nStartTime - 60;
    node17->nTimeConnected = nStartTime - 61;
    node18->nTimeConnected = nStartTime - 61;
    node19->nTimeConnected = nStartTime - 59;
    node20->nTimeConnected = nStartTime - 59;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node16->fDisconnect, true);
    node16->fDisconnect = false;

    node16->nTimeConnected = nStartTime;
    node17->nTimeConnected = nStartTime;
    node18->nTimeConnected = nStartTime;

    // Test no clients have expired.  A network node should get bumped.
    nMaxInbound = 15;
    maxConnections.Set(20);
    node16->nTimeConnected = nStartTime - 59;
    node17->nTimeConnected = nStartTime - 0;
    node18->nTimeConnected = nStartTime - 44;
    node19->nTimeConnected = nStartTime - 59;
    node20->nTimeConnected = nStartTime - 59;
    BOOST_CHECK_EQUAL(AttemptToEvictConnection(nMaxInbound), true);
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL); // vnodes will not change yet, only the fDisconnect flag will be set.
    BOOST_CHECK_EQUAL(node1->fDisconnect, true);
    node1->fDisconnect = false;

    // Test the disconnection of nodes if max connections is reduced via the associated tweak.
    // The first call to CleanupDisconnectedNodes will only set the fDisconnect flag to true.
    // The second call to CleanupDisconnectedNodes finally removes the node from vNodes.
    //
    // Add a reference for each vNode entry. Otherwise we will assert when we try to remove the peers
    for (auto pnode : vNodes)
        pnode->AddRef();

    BOOST_CHECK_EQUAL(vNodes.size(), 20UL);
    maxConnections.Set(19);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 20UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 19UL);

    maxConnections.Set(10);
    BOOST_CHECK_EQUAL(vNodes.size(), 19UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 19UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL);

    maxConnections.Set(1);
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 10UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 1UL);

    maxConnections.Set(0);
    BOOST_CHECK_EQUAL(vNodes.size(), 1UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 1UL);
    GracefulDisconnect(vNodes);
    CleanupDisconnectedNodes();
    BOOST_CHECK_EQUAL(vNodes.size(), 0UL);

    // restore vNodes.
    vNodes = vNodesCopy;
    maxConnections.Set(nMaxConnectionsCopy);
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
