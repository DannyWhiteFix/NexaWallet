// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqpublishnotifier.h"
#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "main.h"
#include "util.h"

static std::multimap<std::string, CZMQAbstractPublishNotifier *> mapPublishNotifiers;

// Internal function to send multipart message
static int zmq_send_multipart(void *sock, const void *data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            va_end(args);
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void *);

        rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            va_end(args);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    va_end(args);
    return 0;
}

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier *>::iterator i = mapPublishNotifiers.find(address);

    if (i == mapPublishNotifiers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }

        int rc = zmq_bind(psocket, address.c_str());
        if (rc != 0)
        {
            zmqError("Failed to bind address");
            return false;
        }

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LOG(ZMQ, "zmq: Reusing socket for address %s\n", address);

        psocket = i->second->psocket;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    // If Initialize did not succeed, or was never called, then shutdown may be called with psocket == nullptr
    if (psocket != nullptr)
    {
        int count = mapPublishNotifiers.count(address);

        // remove this notifier from the list of publishers using this address
        typedef std::multimap<std::string, CZMQAbstractPublishNotifier *>::iterator iterator;
        std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

        for (iterator it = iterpair.first; it != iterpair.second; ++it)
        {
            if (it->second == this)
            {
                mapPublishNotifiers.erase(it);
                break;
            }
        }

        if (count <= 1)
        {
            LOG(ZMQ, "Close socket at address %s\n", address);
            int linger = 0;
            zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(psocket);
        }

        psocket = nullptr;
    }
}

bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LOG(ZMQ, "zmq: Publish hashblock %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    int rc = zmq_send_multipart(psocket, "hashblock", (size_t)9, data, (size_t)32, nullptr);
    return rc == 0;
}

bool CZMQPublishHashTransactionNotifier::NotifyTransaction(const CTransactionRef &ptx)
{
    int rc;

    {
        uint256 hash = ptx->GetId();
        LOG(ZMQ, "zmq: Publish txid %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc = zmq_send_multipart(psocket, "txid", (size_t)4, data, (size_t)32, nullptr);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish txidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc |= zmq_send_multipart(psocket, "txidem", (size_t)6, data, (size_t)32, nullptr);
    }

    return rc == 0;
}

bool CZMQPublishHashDoubleSpendNotifier::NotifyDoubleSpend(const CTransactionRef ptx)
{
    int rc;
    {
        uint256 hash = ptx->GetId();
        LOG(ZMQ, "zmq: Publish dsid %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc = zmq_send_multipart(psocket, "dsid", (size_t)4, data, (size_t)32, nullptr);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish dsidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc |= zmq_send_multipart(psocket, "dsidem", (size_t)6, data, (size_t)32, nullptr);
        return rc == 0;
    }
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    LOG(ZMQ, "zmq: Publish rawblock %s\n", pindex->GetBlockHash().GetHex());

    const Consensus::Params &consensusParams = Params().GetConsensus();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    {
        LOCK(cs_main);
        const ConstCBlockRef pblock = ReadBlockFromDisk(pindex, consensusParams);
        if (!pblock)
        {
            zmqError("Can't read block from disk");
            return false;
        }

        ss << *pblock;
    }

    int rc = zmq_send_multipart(psocket, "rawblock", (size_t)8, &(*ss.begin()), ss.size(), nullptr);
    return rc == 0;
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransactionRef &ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawtx %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *ptx;
    int rc = zmq_send_multipart(psocket, "rawtx", (size_t)5, &(*ss.begin()), ss.size(), nullptr);
    return rc == 0;
}

bool CZMQPublishRawDoubleSpendNotifier::NotifyDoubleSpend(const CTransactionRef ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawds %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ptx;
    int rc = zmq_send_multipart(psocket, "rawds", (size_t)5, &(*ss.begin()), ss.size(), nullptr);
    return rc == 0;
}
