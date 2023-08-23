// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_NETADDRESS_H
#define NEXA_NETADDRESS_H

#include <array>
#include <cstring>
#include <stdint.h>
#include <string>
#include <vector>

#if defined(HAVE_CONFIG_H)
#include "nexa-config.h"
#endif

#include "compat.h" // socklen_t
#include "serialize.h"
#include "tinyformat.h"

enum
{
    IPV6_ADDR_SCOPE_RESERVED = 0x0,
#ifndef IPV6_ADDR_SCOPE_GLOBAL // Already defined on Android platforms
    IPV6_ADDR_SCOPE_GLOBAL = 0x0e,
#endif
};


/**
 * A flag that is ORed into the protocol version to designate that addresses
 * should be serialized in (unserialized from) v2 format (BIP155).
 * Make sure that this does not collide with any of the values in `version.h`.
 */
inline constexpr int ADDRV2_FORMAT = 0x20000000;

enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_TOR3,
    NET_I2P,
    NET_CJDNS,
    /// A set of addresses that represent the hash of a string or FQDN. We use
    /// them in CAddrMan to keep track of which DNS seeds were used.
    NET_INTERNAL,

    NET_MAX,
};

/// Size of IPv4 address (in bytes).
inline constexpr size_t ADDR_IPV4_SIZE = 4;

/// Size of IPv6 address (in bytes).
inline constexpr size_t ADDR_IPV6_SIZE = 16;

/// Size of TORv3 address (in bytes). This is the length of just the address
/// as used in BIP155, without the checksum and the version byte.
inline constexpr size_t ADDR_TORV3_SIZE = 32;

/// Size of I2P address (in bytes).
inline constexpr size_t ADDR_I2P_SIZE = 32;

/// Size of CJDNS address (in bytes).
inline constexpr size_t ADDR_CJDNS_SIZE = 16;

/// Size of "internal" (NET_INTERNAL) address (in bytes).
inline constexpr size_t ADDR_INTERNAL_SIZE = 10;

// Equivalent to the largest sized address as defined above, currently ADDR_TORV3_SIZE
inline constexpr size_t LARGEST_ADDR_SIZE = 32;

/// Prefix of an IPv6 address when it contains an embedded IPv4 address.
/// Used when (un)serializing addresses in ADDRv1 format (pre-BIP155).
inline constexpr std::array<uint8_t, 12> IPV4_IN_IPV6_PREFIX = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/// Prefix of an IPv6 address when it contains an embedded "internal" address.
/// Used when (un)serializing addresses in ADDRv1 format (pre-BIP155).
/// The prefix comes from 0xFD + SHA256("bitcoin")[0:5].
/// Such dummy IPv6 addresses are guaranteed to not be publicly routable as they
/// fall under RFC4193's fc00::/7 subnet allocated to unique-local addresses.
inline constexpr std::array<uint8_t, 6> INTERNAL_IN_IPV6_PREFIX = {0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24};


class CNetAddr
{
private:
    /**
     * Size of CNetAddr when serialized as ADDRv1 (pre-BIP155) (in bytes).
     */
    static constexpr size_t V1_SERIALIZATION_SIZE = ADDR_IPV6_SIZE;

    /**
     * Maximum size of an address as defined in BIP155 (in bytes).
     * This is only the size of the address, not the entire CNetAddr object
     * when serialized.
     */
    static constexpr size_t MAX_ADDRV2_SIZE = 512;

    /**
     * BIP155 network ids recognized by this software.
     */
    enum BIP155Network : uint8_t
    {
        IPV4 = 1,
        IPV6 = 2,
        TORV2 = 3,
        TORV3 = 4,
        I2P = 5,
        CJDNS = 6
    };

protected:
    std::vector<uint8_t> ip;
    Network _net_type;
    uint32_t scopeId; // for scoped/link-local ipv6 addresses

private:
    BIP155Network GetBIP155Network() const;
    bool SetNetFromBIP155Network(uint8_t possible_bip155_net, uint64_t address_size);

public:
    CNetAddr();
    CNetAddr(const struct in_addr &ipv4Addr);
    CNetAddr(const struct in6_addr &pipv6Addr, const uint32_t scope = IPV6_ADDR_SCOPE_RESERVED);
    explicit CNetAddr(const char *pszIp);
    explicit CNetAddr(const std::string &strIp);
    void Init();
    void SetIP(const CNetAddr &ip);

    void SetLegacy(const uint8_t *data);

    bool SetSpecial(const std::string &strName); // for Tor addresses
    bool SetInternal(const std::string &name);
    size_t GetAddrSize();
    bool IsIPv4() const; // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
    bool IsIPv6() const; // IPv6 address (not mapped IPv4, not Tor)
    bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
    bool IsRFC2544() const; // IPv4 inter-network communcations (192.18.0.0/15)
    bool IsRFC6598() const; // IPv4 ISP-level NAT (100.64.0.0/10)
    bool IsRFC5737() const; // IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
    bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
    bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
    bool IsRFC4193() const; // IPv6 unique local (FC00::/7)
    bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
    bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
    bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
    bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
    bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
    bool IsTor3() const;
    bool IsI2P() const;
    bool IsCJDNS() const;
    bool IsLocal() const;
    bool IsRoutable() const;
    bool IsInternal() const;
    bool IsValid() const;
    bool IsMulticast() const;
    /**
     * Check if the current object can be serialized in pre-ADDRv2/BIP155 format.
     */
    bool IsAddrV1Compatible() const;

    enum Network GetNetwork() const;
    std::string ToString() const;
    std::string ToStringIP() const;
    uint64_t GetHash() const;
    bool GetInAddr(struct in_addr *pipv4Addr) const;
    uint8_t GetNetClass() const;

    //! For IPv4, mapped IPv4, SIIT translated IPv4, Teredo, 6to4 tunneled addresses, return the relevant IPv4 address
    //! as a uint32.
    uint32_t GetLinkedIPv4() const;
    //! Whether this address has a linked IPv4 address (see GetLinkedIPv4()).
    bool HasLinkedIPv4() const;

    // The AS on the BGP path to the node we use to diversify
    // peers in AddrMan bucketing based on the AS infrastructure.
    // The ip->AS mapping depends on how asmap is constructed.
    uint32_t GetMappedAS(const std::vector<bool> &asmap) const;

    std::vector<unsigned char> GetGroup() const;

    int GetReachabilityFrom(const CNetAddr *paddrPartner = nullptr) const;

    bool GetIn6Addr(struct in6_addr *pipv6Addr) const;

    friend bool operator==(const CNetAddr &a, const CNetAddr &b);
    friend bool operator!=(const CNetAddr &a, const CNetAddr &b);
    friend bool operator<(const CNetAddr &a, const CNetAddr &b);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        // version 2
        if (s.GetVersion() & ADDRV2_FORMAT)
        {
            if (ser_action.ForRead()) // read
            {
                uint8_t bip155_net;
                s >> bip155_net;

                uint64_t address_size;
                s >> COMPACTSIZE(address_size);

                if (address_size > MAX_ADDRV2_SIZE)
                {
                    throw std::ios_base::failure(strprintf("Address too long: %u > %u", address_size, MAX_ADDRV2_SIZE));
                }
                scopeId = 0;

                // the max bip155 address size is 512 bytes but we do not support any addresses over LARGEST_ADDR_SIZE
                // if address_size > LARGEST_ADDR_SIZE we can use a default constructed CNetAddr and move on
                if (address_size > LARGEST_ADDR_SIZE)
                {
                    _net_type = NET_IPV6;
                    ip.assign(ADDR_IPV6_SIZE, 0);
                    return;
                }

                if (SetNetFromBIP155Network(bip155_net, address_size))
                {
                    ip.resize(address_size);
                    CFlatData ipData(ip.data(), ip.data() + address_size);
                    s >> ipData;
                    if (_net_type != NET_IPV6)
                    {
                        return;
                    }
                    // Do some special checks on IPv6 addresses.

                    // Recognize NET_INTERNAL embedded in IPv6, such addresses are not
                    // gossiped but could be coming from addrman, when unserializing from
                    // disk.
                    if (std::memcmp(ip.data(), INTERNAL_IN_IPV6_PREFIX.data(), INTERNAL_IN_IPV6_PREFIX.size()) == 0)
                    {
                        _net_type = NET_INTERNAL;
                        ip.erase(ip.begin(), ip.begin() + INTERNAL_IN_IPV6_PREFIX.size());
                        return;
                    }
                    if (std::memcmp(ip.data(), IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size()) != 0)
                    {
                        return;
                    }
                    // IPv4 is not supposed to be embedded in IPv6 (like in V1
                    // encoding). Unserialize as !IsValid(), thus ignoring them.
                }
                else
                {
                    // If we receive an unknown BIP155 network id (from the future?) then
                    // ignore the address - unserialize as !IsValid().
                    s.ignore(address_size);
                }

                // Mimic a default-constructed CNetAddr object which is !IsValid() and thus
                // will not be gossiped, but continue reading next addresses from the stream.
                ip.assign(ADDR_IPV6_SIZE, 0);
                _net_type = NET_IPV6;
            }
            else // write
            {
                if (IsInternal())
                {
                    // Serialize NET_INTERNAL as embedded in IPv6. We need to
                    // serialize such addresses from addrman.
                    s << static_cast<uint8_t>(BIP155Network::IPV6);
                    WriteCompactSize(s, ADDR_IPV6_SIZE);
                    uint8_t data[V1_SERIALIZATION_SIZE] = {0};
                    std::copy(INTERNAL_IN_IPV6_PREFIX.data(), INTERNAL_IN_IPV6_PREFIX.data() + 6, data);
                    std::copy(ip.begin(), ip.end(), data + INTERNAL_IN_IPV6_PREFIX.size());
                    READWRITE(FLATDATA(data));
                    return;
                }
                s << static_cast<uint8_t>(GetBIP155Network());
                s << ip;
            }
        }
        else // version 1
        {
            if (ser_action.ForRead()) // read
            {
                uint8_t data[V1_SERIALIZATION_SIZE] = {0};
                READWRITE(FLATDATA(data));
                SetLegacy(data);
            }
            else // write
            {
                uint8_t data[V1_SERIALIZATION_SIZE] = {0};
                switch (_net_type)
                {
                case NET_UNROUTABLE:
                case NET_MAX:
                {
                    assert(false);
                    break;
                }
                case NET_IPV4:
                {
                    std::memcpy(data, IPV4_IN_IPV6_PREFIX.data(), IPV4_IN_IPV6_PREFIX.size());
                    std::memcpy(data + IPV4_IN_IPV6_PREFIX.size(), ip.data(), ADDR_IPV4_SIZE);
                    break;
                }
                case NET_IPV6:
                {
                    std::memcpy(data, ip.data(), V1_SERIALIZATION_SIZE);
                    break;
                }
                case NET_INTERNAL:
                {
                    std::memcpy(data, INTERNAL_IN_IPV6_PREFIX.data(), INTERNAL_IN_IPV6_PREFIX.size());
                    std::memcpy(data + INTERNAL_IN_IPV6_PREFIX.size(), ip.data(), ADDR_INTERNAL_SIZE);
                    break;
                }
                case NET_TOR3:
                case NET_I2P:
                case NET_CJDNS:
                {
                    // intentionally do nothing
                }
                    // no default case to force missing cases compiler warnings
                }
                READWRITE(FLATDATA(data));
            }
        }
    }

    friend class CSubNet;
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
protected:
    uint16_t port; // host order

public:
    CService();
    CService(const CNetAddr &ip, unsigned short port);
    CService(const struct in_addr &ipv4Addr, unsigned short port);
    CService(const struct sockaddr_in &addr);
    CService(const struct in6_addr &ipv6Addr, unsigned short port);
    CService(const struct sockaddr_in6 &addr);
    explicit CService(const char *pszIpPort, int portDefault);
    explicit CService(const char *pszIpPort);
    explicit CService(const std::string &strIpPort, int portDefault);
    explicit CService(const std::string &strIpPort);

    void SetPort(unsigned short portIn);
    unsigned short GetPort() const;
    bool GetSockAddr(struct sockaddr *paddr, socklen_t *addrlen) const;
    bool SetSockAddr(const struct sockaddr *paddr);
    friend bool operator==(const CService &a, const CService &b);
    friend bool operator!=(const CService &a, const CService &b);
    friend bool operator<(const CService &a, const CService &b);
    std::vector<unsigned char> GetKey() const;
    std::string ToString() const;
    std::string ToStringPort() const;
    std::string ToStringIPPort() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CNetAddr *)this);
        uint16_t portN = htons(port);
        READWRITE(FLATDATA(portN));
        if (ser_action.ForRead())
            port = ntohs(portN);
    }
};

class CSubNet
{
protected:
    /// Network (base) address
    CNetAddr network;
    /// Netmask, in network byte order
    uint8_t netmask[16];
    /// Is this value valid? (only used to signal parse errors)
    bool valid;

public:
    CSubNet();
    explicit CSubNet(const std::string &strSubnet);

    // constructor for single ip subnet (<ipv4>/32 or <ipv6>/128)
    explicit CSubNet(const CNetAddr &addr);

    bool Match(const CNetAddr &addr) const;

    std::string ToString() const;
    bool IsValid() const;

    friend bool operator==(const CSubNet &a, const CSubNet &b);
    friend bool operator!=(const CSubNet &a, const CSubNet &b);
    friend bool operator<(const CSubNet &a, const CSubNet &b);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(network);
        READWRITE(FLATDATA(netmask));
        READWRITE(FLATDATA(valid));
    }
};

size_t GetNetAddrSize(const CNetAddr &addr);

#endif
