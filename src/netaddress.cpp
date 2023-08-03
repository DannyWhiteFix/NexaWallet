// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netaddress.h"

#include "crypto/sha3.h"
#include "hashwrapper.h"
#include "netbase.h"
#include "tinyformat.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <string_view>

// do not remove this clang format toggle, formatting Checksum() breaks compilation
/* clang-format off */
namespace torv3
{
// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
inline constexpr size_t CHECKSUM_LEN = 2;
inline constexpr std::array<uint8_t, 1> VERSION = {{3}};
inline constexpr size_t TOTAL_LEN = ADDR_TORV3_SIZE + CHECKSUM_LEN + VERSION.size();
inline constexpr size_t onion_checksum_size = 15;
std::array<uint8_t, CHECKSUM_LEN> static Checksum(const uint8_t *addr_pubkey, const size_t &addr_pubkey_size)
{
    using namespace std::string_view_literals;
    // TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    SHA3_256 hasher;

    auto strChecksum = ".onion checksum"sv;
    const uint8_t *onion_checksum = reinterpret_cast<const uint8_t *>(strChecksum.data());

    hasher.Write(onion_checksum, onion_checksum_size);
    hasher.Write(addr_pubkey, addr_pubkey_size);
    hasher.Write(VERSION.data(), VERSION.size());

    uint8_t checksum_full[SHA3_256::OUTPUT_SIZE];
    hasher.Finalize(checksum_full);

    std::array<uint8_t, CHECKSUM_LEN> ret;
    static_assert(SHA3_256::OUTPUT_SIZE >= ret.size());
    std::copy_n(&checksum_full[0], ret.size(), ret.begin());
    return ret;
}
}; // namespace torv3
/* clang-format on */

CNetAddr::BIP155Network CNetAddr::GetBIP155Network() const
{
    switch (_net_type)
    {
    case NET_IPV4:
        return BIP155Network::IPV4;
    case NET_IPV6:
        return BIP155Network::IPV6;
    case NET_TOR2:
        return BIP155Network::TORV2;
    case NET_TOR3:
        return BIP155Network::TORV3;
    case NET_I2P:
        return BIP155Network::I2P;
    case NET_CJDNS:
        return BIP155Network::CJDNS;
    case NET_INTERNAL: // should have been handled before calling this function
    case NET_UNROUTABLE: // _net_type is never and should not be set to NET_UNROUTABLE
    case NET_MAX: // _net_type is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

bool CNetAddr::SetNetFromBIP155Network(uint8_t possible_bip155_net, uint64_t address_size)
{
    switch (possible_bip155_net)
    {
    case BIP155Network::IPV4:
        if (address_size == ADDR_IPV4_SIZE)
        {
            _net_type = NET_IPV4;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv4 address with length %u (should be %u)", address_size, ADDR_IPV4_SIZE));
    case BIP155Network::IPV6:
        if (address_size == ADDR_IPV6_SIZE)
        {
            _net_type = NET_IPV6;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 IPv6 address with length %u (should be %u)", address_size, ADDR_IPV6_SIZE));
    case BIP155Network::TORV2:
        if (address_size == ADDR_TORV2_SIZE)
        {
            _net_type = NET_TOR2;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv2 address with length %u (should be %u)", address_size, ADDR_TORV2_SIZE));
    case BIP155Network::TORV3:
        if (address_size == ADDR_TORV3_SIZE)
        {
            _net_type = NET_TOR3;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 TORv3 address with length %u (should be %u)", address_size, ADDR_TORV3_SIZE));
    case BIP155Network::I2P:
        if (address_size == ADDR_I2P_SIZE)
        {
            _net_type = NET_I2P;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 I2P address with length %u (should be %u)", address_size, ADDR_I2P_SIZE));
    case BIP155Network::CJDNS:
        if (address_size == ADDR_CJDNS_SIZE)
        {
            _net_type = NET_CJDNS;
            return true;
        }
        throw std::ios_base::failure(
            strprintf("BIP155 CJDNS address with length %u (should be %u)", address_size, ADDR_CJDNS_SIZE));
    }
    // Don't throw on addresses with unknown network ids (maybe from the future).
    // Instead silently drop them and have the unserialization code consume
    // subsequent ones which may be known to us.
    return false;
}

CNetAddr::CNetAddr() { Init(); }
CNetAddr::CNetAddr(const struct in_addr &ipv4Addr)
{
    Init();
    static_assert(sizeof(ipv4Addr) == ADDR_IPV4_SIZE, "struct in_addr must be exactly ADDR_IPV4_SIZE bytes (4)");
    ip.assign((const uint8_t *)&ipv4Addr, (const uint8_t *)&ipv4Addr + ADDR_IPV4_SIZE);
    _net_type = NET_IPV4;
}

CNetAddr::CNetAddr(const struct in6_addr &ipv6Addr, const uint32_t scope)
{
    Init();
    static_assert(sizeof(ipv6Addr) == ADDR_IPV6_SIZE, "struct in6_addr must be exactly ADDR_IPV6_SIZE bytes (16)");
    SetLegacy((const uint8_t *)&ipv6Addr);
    scopeId = scope;
}

CNetAddr::CNetAddr(const char *pszIp)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (LookupHost(pszIp, vIP, 1, false))
    {
        SetIP(vIP[0]);
    }
}

CNetAddr::CNetAddr(const std::string &strIp)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (LookupHost(strIp.c_str(), vIP, 1, false))
    {
        SetIP(vIP[0]);
    }
}

void CNetAddr::Init()
{
    // set ip to all 0s
    ip.assign(ADDR_IPV6_SIZE, 0);
    // TODO : change this to NET_UNROUTABLE, requires test edits
    _net_type = NET_IPV6;
    scopeId = 0;
}

void CNetAddr::SetIP(const CNetAddr &ipIn)
{
    ip.assign(ipIn.ip.begin(), ipIn.ip.end());
    _net_type = ipIn._net_type;
    scopeId = ipIn.scopeId;
}

void CNetAddr::SetLegacy(const uint8_t *ip_in)
{
    // on the network v1 format has addresses in ipv6 but in memory storage we no longer do this
    // for simplicity with v2
    if (std::memcmp(ip_in, IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size()) == 0)
    {
        _net_type = NET_IPV4;
        ip.assign(ip_in + IPV4_IN_IPV6_PREFIX.size(), ip_in + IPV4_IN_IPV6_PREFIX.size() + ADDR_IPV4_SIZE);
    }
    else if (std::memcmp(ip_in, TORV2_IN_IPV6_PREFIX.data(), TORV2_IN_IPV6_PREFIX.size()) == 0)
    {
        _net_type = NET_TOR2;
        ip.assign(ip_in + TORV2_IN_IPV6_PREFIX.size(), ip_in + TORV2_IN_IPV6_PREFIX.size() + ADDR_TORV2_SIZE);
    }
    else if (std::memcmp(ip_in, INTERNAL_IN_IPV6_PREFIX.data(), INTERNAL_IN_IPV6_PREFIX.size()) == 0)
    {
        _net_type = NET_INTERNAL;
        ip.assign(ip_in + INTERNAL_IN_IPV6_PREFIX.size(), ip_in + INTERNAL_IN_IPV6_PREFIX.size() + ADDR_INTERNAL_SIZE);
    }
    else // IPV6
    {
        _net_type = NET_IPV6;
        ip.assign(ip_in, ip_in + V1_SERIALIZATION_SIZE);
    }
}

bool CNetAddr::SetSpecial(const std::string &strName)
{
    // malicious address check
    if (strName.find_first_of('\0') != std::string::npos)
    {
        return false;
    }
    if (strName.size() > 6 && strName.substr(strName.size() - 6, 6) == ".onion")
    {
        bool invalid = false;
        std::vector<uint8_t> vchAddr = DecodeBase32(strName.substr(0, strName.size() - 6).c_str(), &invalid);
        if (invalid)
        {
            return false;
        }
        if (vchAddr.size() == ADDR_TORV2_SIZE) // torv2
        {
            if (vchAddr.size() != 16 - TORV2_IN_IPV6_PREFIX.size())
            {
                return false;
            }
            static_assert(ADDR_TORV2_SIZE <= LARGEST_ADDR_SIZE);
            ip.clear();
            ip.assign(vchAddr.begin(), vchAddr.end());
            _net_type = NET_TOR2;
            return true;
        }
        else if (vchAddr.size() == torv3::TOTAL_LEN) // torv3
        {
            // input_checksum has length torv3::CHECKSUM_LEN (2)
            uint8_t *input_checksum = vchAddr.data() + ADDR_TORV3_SIZE;
            // input_version has length torv3::VERSION.size() (1)
            uint8_t *input_version = vchAddr.data() + ADDR_TORV3_SIZE + torv3::CHECKSUM_LEN;
            // validate version
            if (std::memcmp(input_version, torv3::VERSION.data(), torv3::VERSION.size()) != 0)
            {
                return false;
            }
            auto calculated_checksum = torv3::Checksum(vchAddr.data(), ADDR_TORV3_SIZE);
            // validate checksum
            if (std::memcmp(input_checksum, calculated_checksum.data(), torv3::CHECKSUM_LEN) != 0)
            {
                return false;
            }
            ip.clear();
            // when we set the ip, chop off the checksum and version bytes
            ip.assign(vchAddr.begin(), vchAddr.begin() + ADDR_TORV3_SIZE);
            _net_type = NET_TOR3;
            return true;
        }
    }
    return false;
}

bool CNetAddr::SetInternal(const std::string &name)
{
    if (name.empty())
    {
        return false;
    }
    Init();
    _net_type = NET_INTERNAL;
    uint8_t hash[32] = {};
    CSHA256().Write(reinterpret_cast<const uint8_t *>(name.data()), name.size()).Finalize(hash);
    static_assert(ADDR_INTERNAL_SIZE <= LARGEST_ADDR_SIZE);
    ip.assign(hash, hash + ADDR_INTERNAL_SIZE);
    return true;
}

size_t CNetAddr::GetAddrSize()
{
    switch (_net_type)
    {
    case NET_IPV4:
        return ADDR_IPV4_SIZE;
    case NET_IPV6:
        return ADDR_IPV6_SIZE;
    case NET_TOR2:
        return ADDR_TORV2_SIZE;
    case NET_TOR3:
        return ADDR_TORV3_SIZE;
    case NET_I2P:
        return ADDR_I2P_SIZE;
    case NET_CJDNS:
        return ADDR_CJDNS_SIZE;
    case NET_INTERNAL:
        return ADDR_INTERNAL_SIZE;
    case NET_UNROUTABLE: // _net_type is never and should not be set to NET_UNROUTABLE
    case NET_MAX: // _net_type is never and should not be set to NET_MAX
        assert(false);
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

bool CNetAddr::IsIPv4() const { return (_net_type == NET_IPV4); }

bool CNetAddr::IsIPv6() const { return (_net_type == NET_IPV6); }

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() &&
           (ip[0] == 10 || (ip[0] == 192 && ip[1] == 168) || (ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)));
}

bool CNetAddr::IsRFC2544() const { return IsIPv4() && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19); }
bool CNetAddr::IsRFC3927() const { return IsIPv4() && (ip[0] == 169 && ip[1] == 254); }
bool CNetAddr::IsRFC6598() const { return IsIPv4() && ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127; }
bool CNetAddr::IsRFC5737() const
{
    return IsIPv4() && ((ip[0] == 192 && ip[1] == 0 && ip[2] == 2) || (ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
                           (ip[0] == 203 && ip[1] == 0 && ip[2] == 113));
}

bool CNetAddr::IsRFC3849() const
{
    return IsIPv6() && (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0D && ip[3] == 0xB8);
}

bool CNetAddr::IsRFC3964() const { return IsIPv6() && (ip[0] == 0x20 && ip[1] == 0x02); }
bool CNetAddr::IsRFC6052() const
{
    static const unsigned char pchRFC6052[] = {0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0};
    return IsIPv6() && (std::memcmp(ip.data(), pchRFC6052, sizeof(pchRFC6052)) == 0);
}

bool CNetAddr::IsRFC4380() const { return IsIPv6() && (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0 && ip[3] == 0); }

bool CNetAddr::IsRFC4862() const
{
    static const unsigned char pchRFC4862[] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0};
    return IsIPv6() && (memcmp(ip.data(), pchRFC4862, sizeof(pchRFC4862)) == 0);
}

bool CNetAddr::IsRFC4193() const { return IsIPv6() && ((ip[0] & 0xFE) == 0xFC); }
bool CNetAddr::IsRFC6145() const
{
    static const unsigned char pchRFC6145[] = {0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0};
    return IsIPv6() && (memcmp(ip.data(), pchRFC6145, sizeof(pchRFC6145)) == 0);
}

bool CNetAddr::IsRFC4843() const
{
    return IsIPv6() && (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && (ip[3] & 0xF0) == 0x10);
}

bool CNetAddr::IsTor2() const
{
    // return (memcmp(&ip[0], TORV2_IN_IPV6_PREFIX, sizeof(TORV2_IN_IPV6_PREFIX)) == 0);
    return _net_type == NET_TOR2;
}

bool CNetAddr::IsTor3() const { return _net_type == NET_TOR3; }

bool CNetAddr::IsI2P() const { return _net_type == NET_I2P; }

bool CNetAddr::IsCJDNS() const { return _net_type == NET_CJDNS; }

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback
    if (IsIPv4() && (ip[0] == 127 || ip[0] == 0))
        return true;

    // IPv6 loopback (::1/128)
    static const unsigned char pchLocal[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(&ip[0], pchLocal, 16) == 0)
        return true;

    return false;
}

bool CNetAddr::IsMulticast() const { return (IsIPv4() && (ip[0] & 0xF0) == 0xE0) || (ip[0] == 0xFF); }
bool CNetAddr::IsValid() const
{
    // unspecified IPv6 address (::/128)
    unsigned char _ipNone[16] = {};
    if (IsIPv6() && memcmp(ip.data(), _ipNone, 16) == 0)
    {
        return false;
    }
    // documentation IPv6 address
    if (IsRFC3849())
    {
        return false;
    }
    if (IsInternal())
    {
        return false;
    }
    if (IsIPv4())
    {
        const uint32_t addr = ReadBE32(ip.data());
        if (addr == INADDR_ANY || addr == INADDR_NONE)
        {
            return false;
        }
    }
    return true;
}

bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737() ||
                            (IsRFC4193() && (!IsTor2() && !IsTor3())) || IsRFC4843() || IsLocal() || IsInternal());
}

bool CNetAddr::IsInternal() const { return _net_type == NET_INTERNAL; }

bool CNetAddr::IsAddrV1Compatible() const
{
    if (IsIPv4() || IsIPv6() || IsInternal())
    {
        return true;
    }
    else if (IsTor2())
    {
        return true;
    }
    return false;
}

enum Network CNetAddr::GetNetwork() const
{
    if (IsInternal())
    {
        return NET_INTERNAL;
    }
    if (!IsRoutable())
    {
        return NET_UNROUTABLE;
    }
    return _net_type;
}

std::string CNetAddr::ToStringIP() const
{
    if (IsIPv4())
    {
        return strprintf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    }
    if (IsIPv6() || IsCJDNS())
    {
        if (IsIPv6())
        {
            CService serv(*this, 0);
            struct sockaddr_storage sockaddr;
            socklen_t socklen = sizeof(sockaddr);
            if (serv.GetSockAddr((struct sockaddr *)&sockaddr, &socklen))
            {
                char name[1025] = "";
                if (!getnameinfo(
                        (const struct sockaddr *)&sockaddr, socklen, name, sizeof(name), nullptr, 0, NI_NUMERICHOST))
                {
                    return std::string(name);
                }
            }
        }
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x", ip[0] << 8 | ip[1], ip[2] << 8 | ip[3], ip[4] << 8 | ip[5],
            ip[6] << 8 | ip[7], ip[8] << 8 | ip[9], ip[10] << 8 | ip[11], ip[12] << 8 | ip[13], ip[14] << 8 | ip[15]);
    }
    if (IsTor2())
    {
        return EncodeBase32(ip.data(), ADDR_TORV2_SIZE) + ".onion";
    }
    if (IsTor3())
    {
        auto checksum = torv3::Checksum(ip.data(), ADDR_TORV3_SIZE);
        // TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
        std::array<uint8_t, torv3::TOTAL_LEN> address;
        std::memcpy(address.data(), ip.data(), ADDR_TORV3_SIZE);
        std::memcpy(address.data() + ADDR_TORV3_SIZE, checksum.data(), checksum.size());
        std::memcpy(address.data() + ADDR_TORV3_SIZE + checksum.size(), torv3::VERSION.data(), torv3::VERSION.size());
        return EncodeBase32(address.data(), torv3::TOTAL_LEN) + ".onion";
    }
    if (IsInternal())
    {
        return EncodeBase32(ip.data(), ADDR_INTERNAL_SIZE) + ".internal";
    }
    if (IsI2P())
    {
        return EncodeBase32(ip.data(), ADDR_I2P_SIZE, false) + ".b32.i2p";
    }
    return {};
}

std::string CNetAddr::ToString() const { return ToStringIP(); }
bool operator==(const CNetAddr &a, const CNetAddr &b) { return a.ip == b.ip; }
bool operator!=(const CNetAddr &a, const CNetAddr &b) { return a.ip != b.ip; }
bool operator<(const CNetAddr &a, const CNetAddr &b) { return a.ip < b.ip; }
bool CNetAddr::GetInAddr(struct in_addr *pipv4Addr) const
{
    if (!IsIPv4())
    {
        return false;
    }
    std::memcpy(pipv4Addr, ip.data(), ADDR_IPV4_SIZE);
    return true;
}

bool CNetAddr::GetIn6Addr(struct in6_addr *pipv6Addr) const
{
    if (!IsIPv6())
    {
        return false;
    }
    std::memcpy(pipv6Addr, ip.data(), ADDR_IPV6_SIZE);
    return true;
}

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
std::vector<unsigned char> CNetAddr::GetGroup() const
{
    std::vector<unsigned char> vchRet;
    int nClass = NET_IPV6;
    int nStartByte = 0;
    int nBits = 16;

    if (IsInternal())
    {
        nClass = NET_INTERNAL;
        nBits = ADDR_INTERNAL_SIZE * 8;
    }
    // all unroutable addresses belong to the same group
    // this also covers IsLocal() addresses
    else if (!IsRoutable())
    {
        nClass = NET_UNROUTABLE;
        nBits = 0;
    }
    // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
    // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
    else if (IsIPv4())
    {
        nClass = NET_IPV4;
        nStartByte = 0;
    }
    else if (IsRFC6145() || IsRFC6052())
    {
        nClass = NET_IPV4;
        nStartByte = 12;
    }
    // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
    else if (IsRFC3964())
    {
        nClass = NET_IPV4;
        nStartByte = 2;
    }
    // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
    else if (IsRFC4380())
    {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(ip[12] ^ 0xFF);
        vchRet.push_back(ip[13] ^ 0xFF);
        return vchRet;
    }
    else if (IsTor2())
    {
        nClass = NET_TOR2;
        nStartByte = 0;
        nBits = 4;
    }
    else if (IsTor3())
    {
        nClass = NET_TOR3;
        nStartByte = 0;
        nBits = 4;
    }
    else if (IsI2P())
    {
        nClass = NET_I2P;
        nStartByte = 0;
        nBits = 4;
    }
    else if (IsCJDNS())
    {
        nClass = NET_CJDNS;
        nStartByte = 0;
        nBits = 4;
    }
    // for he.net, use /36 groups
    else if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x04 && ip[3] == 0x70)
    {
        nBits = 36;
    }
    // for the rest of the IPv6 network, use /32 groups
    else
    {
        nBits = 32;
    }
    vchRet.push_back(nClass);
    while (nBits >= 8)
    {
        vchRet.push_back(ip[nStartByte]);
        nStartByte++;
        nBits -= 8;
    }
    if (nBits > 0)
    {
        vchRet.push_back(ip[nStartByte] | ((1 << (8 - nBits)) - 1));
    }
    return vchRet;
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(&ip[0], &ip[16]);
    uint64_t nRet;
    std::memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == nullptr)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability
    {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable() || IsInternal())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch (theirNet)
    {
    case NET_IPV4:
        switch (ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_IPV4:
            return REACH_IPV4;
        }
    case NET_IPV6:
        switch (ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case NET_IPV4:
            return REACH_IPV4;
        case NET_IPV6:
            return fTunnel ? REACH_IPV6_WEAK :
                             REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_TOR2:
    case NET_TOR3:
        switch (ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_IPV4:
            return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_TOR2:
        case NET_TOR3:
            return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch (ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case NET_IPV6:
            return REACH_IPV6_WEAK;
        case NET_IPV4:
            return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case NET_UNROUTABLE:
    default:
        switch (ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case NET_IPV6:
            return REACH_IPV6_WEAK;
        case NET_IPV4:
            return REACH_IPV4;
        case NET_TOR2:
        case NET_TOR3:
            return REACH_PRIVATE; // either from Tor, or don't care about our address
        }
    }
}

CService::CService() : port(0) {}
CService::CService(const CNetAddr &cip, unsigned short portIn) : CNetAddr(cip), port(portIn) {}
CService::CService(const struct in_addr &ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn) {}
CService::CService(const struct in6_addr &ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn) {}
CService::CService(const struct sockaddr_in &addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr)
    : CNetAddr(addr.sin6_addr, addr.sin6_scope_id), port(ntohs(addr.sin6_port))
{
    assert(addr.sin6_family == AF_INET6);
}

CService::CService(const char *pszIpPort) : port(0)
{
    CService _ip;
    if (Lookup(pszIpPort, _ip, 0, false))
        *this = _ip;
}

CService::CService(const char *pszIpPort, int portDefault) : port(0)
{
    CService _ip;
    if (Lookup(pszIpPort, _ip, portDefault, false))
        *this = _ip;
}

CService::CService(const std::string &strIpPort) : port(0)
{
    CService _ip;
    if (Lookup(strIpPort.c_str(), _ip, 0, false))
        *this = _ip;
}

CService::CService(const std::string &strIpPort, int portDefault) : port(0)
{
    CService _ip;
    if (Lookup(strIpPort.c_str(), _ip, portDefault, false))
        *this = _ip;
}

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family)
    {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in *)paddr);
        return true;
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6 *)paddr);
        return true;
    default:
        return false;
    }
}

unsigned short CService::GetPort() const { return port; }
bool operator==(const CService &a, const CService &b) { return (CNetAddr)a == (CNetAddr)b && a.port == b.port; }
bool operator!=(const CService &a, const CService &b) { return (CNetAddr)a != (CNetAddr)b || a.port != b.port; }
bool operator<(const CService &a, const CService &b)
{
    return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
}

bool CService::GetSockAddr(struct sockaddr *paddr, socklen_t *addrlen) const
{
    if (IsIPv4())
    {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in *)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
    if (IsIPv6())
    {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6 *)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_scope_id = scopeId;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
    return false;
}

std::vector<unsigned char> CService::GetKey() const
{
    std::vector<uint8_t> vKey;
    if (IsIPv4() || IsIPv6() || IsInternal() || IsTor2())
    {
        vKey.resize(18);
        if (IsIPv4())
        {
            std::memcpy(&vKey[0], IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size());
            std::memcpy(&vKey[0] + IPV4_IN_IPV6_PREFIX.size(), ip.data(), ADDR_IPV4_SIZE);
        }
        else if (IsIPv6())
        {
            memcpy(&vKey[0], &ip[0], 16);
        }
        else if (IsInternal())
        {
            std::memcpy(&vKey[0], INTERNAL_IN_IPV6_PREFIX.data(), INTERNAL_IN_IPV6_PREFIX.size());
            std::memcpy(&vKey[0] + INTERNAL_IN_IPV6_PREFIX.size(), ip.data(), ADDR_INTERNAL_SIZE);
        }
        else if (IsTor2())
        {
            std::memcpy(&vKey[0], TORV2_IN_IPV6_PREFIX.data(), TORV2_IN_IPV6_PREFIX.size());
            std::memcpy(&vKey[0] + TORV2_IN_IPV6_PREFIX.size(), ip.data(), ADDR_TORV2_SIZE);
        }
        vKey[16] = port / 0x100;
        vKey[17] = port & 0x0FF;
    }
    else
    {
        std::memcpy(&vKey[0], ip.data(), GetNetAddrSize(*((CNetAddr *)this)));
    }
    return vKey;
}

std::string CService::ToStringPort() const { return strprintf("%u", port); }
std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor2())
    {
        return ToStringIP() + ":" + ToStringPort();
    }
    else
    {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const { return ToStringIPPort(); }
void CService::SetPort(unsigned short portIn) { port = portIn; }
CSubNet::CSubNet() : valid(false) { memset(netmask, 0, sizeof(netmask)); }
CSubNet::CSubNet(const std::string &strSubnet)
{
    size_t slash = strSubnet.find_last_of('/');
    std::vector<CNetAddr> vIP;

    valid = true;
    // Default to /32 (IPv4) or /128 (IPv6), i.e. match single address
    memset(netmask, 255, sizeof(netmask));

    std::string strAddress = strSubnet.substr(0, slash);
    if (LookupHost(strAddress.c_str(), vIP, 1, false))
    {
        network = vIP[0];
        const size_t addrSize = network.GetAddrSize();
        if (slash != strSubnet.npos)
        {
            std::string strNetmask = strSubnet.substr(slash + 1);
            int32_t n;
            if (ParseInt32(strNetmask, &n)) // If valid number, assume /24 symtex
            {
                if (n >= 0 && (size_t)n <= (addrSize * 8)) // Only valid if in range of bits of address
                {
                    size_t m = 0;
                    while (m < addrSize)
                    {
                        const uint8_t bits = n < 8 ? n : 8;
                        netmask[m] = 0xFFu << (8u - bits);
                        n -= bits;
                        ++m;
                    }
                }
                else
                {
                    valid = false;
                }
            }
            else // If not a valid number, try full netmask syntax
            {
                if (LookupHost(strNetmask.c_str(), vIP, 1, false)) // Never allow lookup for netmask
                {
                    for (size_t x = 0; x < addrSize; ++x)
                    {
                        netmask[x] = vIP[0].ip[x];
                    }
                }
                else
                {
                    valid = false;
                }
            }
        }
    }
    else
    {
        valid = false;
    }

    // Normalize network according to netmask
    for (size_t x = 0; x < network.GetAddrSize(); ++x)
    {
        network.ip[x] &= netmask[x];
    }
}

CSubNet::CSubNet(const CNetAddr &addr) : valid(addr.IsValid())
{
    memset(netmask, 255, sizeof(netmask));
    network = addr;
}

bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid())
    {
        return false;
    }
    if (network._net_type != addr._net_type)
    {
        return false;
    }
    const size_t addrSize = GetNetAddrSize(network);
    for (size_t x = 0; x < addrSize; ++x)
    {
        if ((addr.ip[x] & netmask[x]) != network.ip[x])
        {
            return false;
        }
    }
    return true;
}

static inline int NetmaskBits(uint8_t x)
{
    switch (x)
    {
    case 0x00:
        return 0;
        break;
    case 0x80:
        return 1;
        break;
    case 0xc0:
        return 2;
        break;
    case 0xe0:
        return 3;
        break;
    case 0xf0:
        return 4;
        break;
    case 0xf8:
        return 5;
        break;
    case 0xfc:
        return 6;
        break;
    case 0xfe:
        return 7;
        break;
    case 0xff:
        return 8;
        break;
    default:
        return -1;
        break;
    }
}

std::string CSubNet::ToString() const
{
    /* Parse binary 1{n}0{N-n} to see if mask can be represented as /n */
    int cidr = 0;
    bool valid_cidr = true;
    const size_t addrSize = GetNetAddrSize(network);
    uint32_t n = 0;
    for (; n < addrSize && netmask[n] == 0xff; ++n)
    {
        cidr += 8;
    }
    if (n < addrSize)
    {
        int bits = NetmaskBits(netmask[n]);
        if (bits < 0)
        {
            valid_cidr = false;
        }
        else
        {
            cidr += bits;
        }
        ++n;
    }
    for (; n < addrSize && valid_cidr; ++n)
    {
        if (netmask[n] != 0x00)
        {
            valid_cidr = false;
        }
    }
    /* Format output */
    std::string strNetmask;
    if (valid_cidr)
    {
        strNetmask = strprintf("%u", cidr);
    }
    else
    {
        if (network.IsIPv4())
            strNetmask = strprintf("%u.%u.%u.%u", netmask[0], netmask[1], netmask[2], netmask[3]);
        else
            strNetmask =
                strprintf("%x:%x:%x:%x:%x:%x:%x:%x", netmask[0] << 8 | netmask[1], netmask[2] << 8 | netmask[3],
                    netmask[4] << 8 | netmask[5], netmask[6] << 8 | netmask[7], netmask[8] << 8 | netmask[9],
                    netmask[10] << 8 | netmask[11], netmask[12] << 8 | netmask[13], netmask[14] << 8 | netmask[15]);
    }
    return network.ToString() + "/" + strNetmask;
}

bool CSubNet::IsValid() const { return valid; }
bool operator==(const CSubNet &a, const CSubNet &b)
{
    return a.valid == b.valid && a.network == b.network && !memcmp(a.netmask, b.netmask, 16);
}

bool operator!=(const CSubNet &a, const CSubNet &b) { return !(a == b); }
bool operator<(const CSubNet &a, const CSubNet &b)
{
    return (a.network < b.network || (a.network == b.network && memcmp(a.netmask, b.netmask, 16) < 0));
}

size_t GetNetAddrSize(const CNetAddr &addr)
{
    if (addr.IsIPv4())
    {
        return ADDR_IPV4_SIZE;
    }
    else if (addr.IsIPv6())
    {
        return ADDR_IPV6_SIZE;
    }
    else if (addr.IsTor2())
    {
        return ADDR_TORV2_SIZE;
    }
    else if (addr.IsTor3())
    {
        return ADDR_TORV3_SIZE;
    }
    else if (addr.IsI2P())
    {
        return ADDR_I2P_SIZE;
    }
    else if (addr.IsCJDNS())
    {
        return ADDR_CJDNS_SIZE;
    }
    else if (addr.IsInternal())
    {
        return ADDR_INTERNAL_SIZE;
    }
    // default return max addr size
    return LARGEST_ADDR_SIZE;
}
