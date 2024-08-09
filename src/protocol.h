// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (C) 2020 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef NEXA_PROTOCOL_H
#define NEXA_PROTOCOL_H

#include "netbase.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

#define MESSAGE_START_SIZE 4

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];
    CMessageHeader()
    {
        nMessageSize = 0;
        msgCookie = 0;
        memset(pchMessageStart, 0, sizeof(pchMessageStart));
        memset(pchCommand, 0, sizeof(pchCommand));
    }
    CMessageHeader(const MessageStartChars &pchMessageStartIn, uint32_t msgCookie);
    CMessageHeader(const MessageStartChars &pchMessageStartIn,
        const char *pszCommand,
        uint32_t msgCookie,
        unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid(const MessageStartChars &messageStart) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(msgCookie);
    }

    // TODO: make private (improves encapsulation)
public:
    enum
    {
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = sizeof(int),
        CHECKSUM_SIZE = sizeof(int),

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int msgCookie;
};

/**
 * Bitcoin protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in protocol.cpp.
 */
namespace NetMsgType
{
/**
 * The version message provides information about the transmitting node to the
 * receiving node at the beginning of a connection.
 * @see https://bitcoin.org/en/developer-reference#version
 */
extern const char *VERSION;
/**
 * The verack message acknowledges a previously-received version message,
 * informing the connecting node that it can begin to send other messages.
 * @see https://bitcoin.org/en/developer-reference#verack
 */
extern const char *VERACK;
/**
 * The addr (IP address) message relays connection information for peers on the
 * network.
 * @see https://bitcoin.org/en/developer-reference#addr
 */
extern const char *ADDR;
/**
 * The addrv2 message relays connection information for peers on the network just
 * like the addr message, but is extended to allow gossiping of longer node
 * addresses (see BIP155).
 */
extern const char *ADDRV2;
/**
 * The inv message (inventory message) transmits one or more inventories of
 * objects known to the transmitting peer.
 * @see https://bitcoin.org/en/developer-reference#inv
 */
extern const char *INV;
/**
 * The getdata message requests one or more data objects from another node.
 * @see https://bitcoin.org/en/developer-reference#getdata
 */
extern const char *GETDATA;
/**
 * The extgetdata message requests one or more data objects from another node using
 * a variable length byte vector to store the hash.
 */
extern const char *EXTGETDATA;
/**
 * The merkleblock message is a reply to a getdata message which requested a
 * block using the inventory type MSG_MERKLEBLOCK.
 * @since protocol version 70001 as described by BIP37.
 * @see https://bitcoin.org/en/developer-reference#merkleblock
 */
extern const char *MERKLEBLOCK;
/**
 * The getblocks message requests an inv message that provides block header
 * hashes starting from a particular point in the block chain.
 * @see https://bitcoin.org/en/developer-reference#getblocks
 */
extern const char *GETBLOCKS;
/**
 * The getheaders message requests a headers message that provides block
 * headers starting from a particular point in the block chain.
 * @see https://bitcoin.org/en/developer-reference#getheaders
 */
extern const char *GETHEADERS;
/**
 * The tx message transmits a single transaction.
 * @see https://bitcoin.org/en/developer-reference#tx
 */
extern const char *TX;
/**
 * The headers message sends one or more block headers to a node which
 * previously requested certain headers with a getheaders message.
 * @see https://bitcoin.org/en/developer-reference#headers
 */
extern const char *HEADERS;
/**
 * The block message transmits a single serialized block.
 * @see https://bitcoin.org/en/developer-reference#block
 */
extern const char *BLOCK;
/**
 * BUIP010 Xtreme Thinblocks: The thinblock message transmits a single serialized thinblock.
 */
extern const char *THINBLOCK;
/**
 * BUIP010 Xtreme Thinblocks: The xthinblock message transmits a single serializexd xthinblock.
 */
extern const char *XTHINBLOCK;
/**
 * BUIP010 Xtreme Thinblocks: The xblocktx message transmits a single serialized xblocktx.
 */
extern const char *XBLOCKTX;
/**
 * BUIP010 Xtreme Thinblocks: The get_xblocktx message transmits a single serialized get_xblocktx.
 */
extern const char *GET_XBLOCKTX;
/**
 * BUIP010 Xtreme Thinblocks: The get_xthin message transmits a single serialized get_xthin.
 */
extern const char *GET_XTHIN;
/**
 * The get_thin message is a request for a thinblock with the full 256 bit tx hashes.
 */
extern const char *GET_THIN;
/**
 * The grapheneblock message transmits a single serialized graphene block.
 */
extern const char *GRAPHENEBLOCK;
/**
 * The graphenetx message transmits a single serialized grblktx.
 */
extern const char *GRAPHENETX;
/**
 * The get_graphenetx message transmits a single serialized get_grblktx.
 */
extern const char *GET_GRAPHENETX;
/**
 * The get_graphene message transmits a single serialized get_grblk.
 */
extern const char *GET_GRAPHENE;
/**
 * The get_graphene_recovery message transmits a single serialized
 * RequestGrapheneReceiverRecover object.
 */
extern const char *GET_GRAPHENE_RECOVERY;
/**
 * The graphene_recovery message transmits a single serialized
 * CGrapheneReceiverRecover object.
 */
extern const char *GRAPHENE_RECOVERY;
/**
 * The mempoolsync message transmits a single serialized get_memsync.
 */
extern const char *MEMPOOLSYNC;
/**
 * The mempoolsynctx message transmits a single serialized get_memsynctx.
 */
extern const char *MEMPOOLSYNCTX;
/**
 * The get_mempoolsync message transmits a single serialized get_memsync.
 */
extern const char *GET_MEMPOOLSYNC;
/**
 * The get_mempoolsynctx message transmits a single serialized get_memsynctx.
 */
extern const char *GET_MEMPOOLSYNCTX;

/**
 * The getaddr message requests an addr message from the receiving node,
 * preferably one with lots of IP addresses of other receiving nodes.
 * @see https://bitcoin.org/en/developer-reference#getaddr
 */
extern const char *GETADDR;
/**
 * The mempool message requests the TXIDs of transactions that the receiving
 * node has verified as valid but which have not yet appeared in a block.
 * @since protocol version 60002.
 * @see https://bitcoin.org/en/developer-reference#mempool
 */
extern const char *MEMPOOL;
/**
 * The ping message is sent periodically to help confirm that the receiving
 * peer is still connected.
 * @see https://bitcoin.org/en/developer-reference#ping
 */
extern const char *PING;
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 * @see https://bitcoin.org/en/developer-reference#pong
 */
extern const char *PONG;
/**
 * The notfound message is a reply to a getdata message which requested an
 * object the receiving node does not have available for relay.
 * @since protocol version 70001.
 * @see https://bitcoin.org/en/developer-reference#notfound
 */
extern const char *NOTFOUND;
/**
 * The filterload message tells the receiving peer to filter all relayed
 * transactions and requested merkle blocks through the provided filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterload
 */
extern const char *FILTERLOAD;
/**
 * The filteradd message tells the receiving peer to add a single element to a
 * previously-set bloom filter, such as a new public key.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filteradd
 */
extern const char *FILTERADD;
/**
 * The filterclear message tells the receiving peer to remove a previously-set
 * bloom filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterclear
 */
extern const char *FILTERCLEAR;
/**
 * The filtersizexthin message tells the receiving peer the maximum xthin bloom
 * filter size that it will accept.
 */
extern const char *FILTERSIZEXTHIN;
/**
 * The reject message informs the receiving node that one of its previous
 * messages has been rejected.
 * @since protocol version 70002 as described by BIP61.
 * @see https://bitcoin.org/en/developer-reference#reject
 */
extern const char *REJECT;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 * @see https://bitcoin.org/en/developer-reference#sendheaders
 */
extern const char *SENDHEADERS;

/**
 * Indicates that a node prefers to receive new block announcements
 * and transactions directly without INVs
 * @since protocol version 80000.
 */
extern const char *XPEDITEDREQUEST;

/**
 * Block or transactions sent without explicit solicitation
 * @since protocol version 80000.
 */
extern const char *XPEDITEDBLK;
/**
 * Block or transactions sent without explicit solicitation
 * @since protocol version 80000.
 */
extern const char *XPEDITEDTXN;

/**
 * Indicates that a node accepts Compact Blocks and provides version and
 * configuration information.
 * @since protocol version 70014.
 * @see https://bitcoin.org/en/developer-reference#sendcmpct
 *
 */
extern const char *SENDCMPCT;

/**
 * Cash specific version information extending NetMsgType::VERSION
 * @since protocol version FIXME.
 */
extern const char *EXTVERSION;

extern const char *XUPDATE;

/**
 * Contains a CBlockHeaderAndShortTxIDs object - providing a header and
 * list of "short txids".
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *CMPCTBLOCK;
/**
 * Contains a BlockTransactionsRequest
 * Peer should respond with "blocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *GETBLOCKTXN;
/**
 * Contains a BlockTransactions.
 * Sent in response to a "getblocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *BLOCKTXN;

/**
 * Requests a headers path
 *
 * @since protocol version 80004
 */
extern const char *GETHEADERPATH;

/**
 * Contains a headers path between two blocks.
 * Sent in response to a "getblockpath" message.
 * @since protocol version 80004
 */
extern const char *HEADERPATH;

/**
 * Double spend proof
 */
extern const char *DSPROOF;

/**
 * Contains a request to get validation information about a tx
 * A p2p message for the validaterawtransaction rpc request
 */
extern const char *REQTXVAL;

/**
 * Contains a response with validation information about a tx
 * A p2p message for the validaterawtransaction rpc response
 */
extern const char *RESTXVAL;

/** all CAPD messages have this prefix
 * NOT AN ACTUAL MESSAGE
 */
extern const char *CAPDPREFIX;

/**
 * Contains CAPD message notifications
 * only if XVERSION capd enabled
 * This is a seperate message from normal INV so that it can be de-prioritized
 */
extern const char *CAPDINV;
/**
 * Request CAPD messages by hash only if EXTVERSION capd enabled
 */
extern const char *CAPDGETMSG;
/**
 * Contains CAPD messages, only if EXTVERSION capd enabled
 */
extern const char *CAPDMSG;
/**
 * Request info about the capd pool only if EXTVERSION capd enabled
 */
extern const char *CAPDGETINFO;
/**
 * Provide info about the capd pool only if EXTVERSION capd enabled
 */
extern const char *CAPDINFO;
/**
 * Search for matching messages only if EXTVERSION capd enabled
 */
extern const char *CAPDQUERY;
/**
 * Reply with matching messages only if EXTVERSION capd enabled
 */
extern const char *CAPDQUERYREPLY;
/**
 * Remove an installed notification only if EXTVERSION capd enabled
 */
extern const char *CAPDREMOVENOTIFY;

/**
 * Token info sent with explicit solicitation from a GETDATA of MSG_TOKENINFO type
 * @since protocol version 80006.
 */
extern const char *TOKENINFO;

}; // namespace NetMsgType

/* Get a vector of all valid message types (see above) */
const std::vector<std::string> &getAllNetMessageTypes();

/** nServices flags */
enum
{
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the complete block chain. It is currently
    // set by all Bitcoin Unlimited nodes, and is unset by SPV clients or other peers that just want
    // network services but don't provide them.
    NODE_NETWORK = (1 << 0),

    // 1<<1 is currently not used

    NODE_BLOOM = (1 << 2),

    // NODE_XTHIN means the node supports Xtreme Thinblocks
    // If this is turned off then the node will not service xthin requests nor
    // make xthin requests
    NODE_XTHIN = (1 << 4),

    // 1<<5 is currently not used

    // NODE_GRAPHENE means the node supports Graphene blocks
    // If this is turned off then the node will not service graphene requests nor
    // make graphene requests
    NODE_GRAPHENE = (1 << 6),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // Bitcoin Unlimited devevelopement team. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BUIP process.

    NODE_WEAKBLOCKS = (1 << 7),

    // NODE_CF indicates the node is capable of serving compact block filters to SPV clients.
    NODE_CF = (1 << 8),

    // 1<<9 is currently not used

    // NODE_NETWORK_LIMITED means the same as NODE_NETWORK with the limitation
    // of only serving a small subset of the blockchain
    // See BIP159 for details on how this is implemented.
    NODE_NETWORK_LIMITED = (1 << 10),

    // indicates if node is using extversion
    NODE_EXTVERSION = (1 << 11),
};

/** A CService with information about it as peer */
class CAddress : public CService
{
public:
    CAddress();
    CAddress(CService ipIn, uint64_t nServicesIn = NODE_NETWORK);
    CAddress(CService ipIn, uint64_t nServicesIn, uint32_t nTimeIn);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        if (ser_action.ForRead())
        {
            Init();
        }
        int nVersion = s.GetVersion();
        if (s.GetType() & SER_DISK)
        {
            READWRITE(nVersion);
        }
        if (s.GetType() & SER_DISK || ((nVersion & ADDRV2_FORMAT) && !(s.GetType() & SER_GETHASH)))
        {
            // The only time we serialize a CAddress object without nTime is in
            // the initial VERSION messages which contain two CAddress records.
            // At that point, the serialization version is INIT_PROTO_VERSION.
            // After the version handshake, serialization version is >=
            // MIN_PEER_PROTO_VERSION and all ADDR messages are serialized with
            // nTime.
            // Note: The extversion phase (optional) of protocol negotiation
            // uses INIT_PROTO_VERSION. Currently extversion in BCHN does not
            // send CAddress instances in the extversion message, but if it
            // were to do so in some hypothetical future change, then it should
            // take into account the behavior here, and be sure not to use
            // INIT_PROTO_VERSION if it wished to serialize nTime.
            READWRITE(nTime);
        }
        if (nVersion & ADDRV2_FORMAT)
        {
            if (ser_action.ForRead()) // reading
            {
                nServices = ReadCompactSizeWithLimit(s, std::numeric_limits<uint64_t>::max());
            }
            else // writing
            {
                WriteCompactSize(s, nServices);
            }
        }
        else
        {
            READWRITE(nServices);
        }
        READWRITE(*(CService *)this);
    }

    // TODO: make private (improves encapsulation)
public:
    uint64_t nServices;

    // disk and network only
    unsigned int nTime;
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(int typeIn, const uint256 &hashIn);
    CInv(const std::string &strType, const uint256 &hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv &a, const CInv &b);

    /// returns true if this inv is one of any of the inv types ever used.
    bool IsKnownType() const;
    const char *GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

class CInv2
{
public:
    CInv2();
    CInv2(uint8_t typeIn, const uint256 &hashIn);
    CInv2(const std::string &strType, const uint256 &hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv2 &a, const CInv2 &b);

    /// returns true if this inv is one of any of the inv types ever used.
    bool IsKnownType() const;
    const char *GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    uint8_t type;
    uint256 hash;
};

// Extended Inv messages store a byte vector rather than a uint256 and so
// can hold smaller or larger values and thus have more flexibility when needed.
class CExtInv
{
public:
    CExtInv();
    CExtInv(uint8_t typeIn, const std::vector<uint8_t> &hashIn);
    CExtInv(const std::string &strType, const std::vector<uint8_t> &hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    /// returns true if this extinv is one of any of the extinv types ever used.
    bool IsKnownType() const;
    const char *GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    uint8_t type;
    std::vector<uint8_t> hash;
};

enum
{
    // CInv types
    MSG_TX = 1,
    MSG_BLOCK = 2,
    // Nodes may always request a MSG_FILTERED_BLOCK/MSG_CMPCT_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK/MSG_CMPCT_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK = 3,
    MSG_CMPCT_BLOCK = 4,

    // MSG_XTHINBLOCK, MSG_GRAPHENEBLOCK and MSG_THINBLOCK are not strictly necessary but they do make
    // creating and validating the requestManager tests much easier.
    MSG_XTHINBLOCK = 5,
    MSG_GRAPHENEBLOCK = 6,
    // With the introduction of compact blocks, this is being deprecated in favor of using the get_thin p2p
    // message, which solves the conflict with MSG_THINBLOCK and MSG_CMPCT_BLOCK.
    MSG_THINBLOCK = MSG_CMPCT_BLOCK,

    MSG_DOUBLESPENDPROOF = 7,

    // CExtInv types.  They begin at 100 to allow room to add more CInv types without affect CExtInv types.
    MSG_TOKENINFO = 100
};

#endif // NEXA_PROTOCOL_H
