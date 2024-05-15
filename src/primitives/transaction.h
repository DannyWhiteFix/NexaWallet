// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_PRIMITIVES_TRANSACTION_H
#define NEXA_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "crypto/sha256.h"
#include "hashwrapper.h"
#include "satoshiTransaction.h"
#include "script/script.h"
#include "serialize.h"
#include "tweak.h"
#include "util.h"

#include <atomic>
#include <memory>

extern CTweak<uint32_t> dustThreshold;


class COutPoint
{
public:
    uint256 hash;

    COutPoint() { SetNull(); }
    explicit COutPoint(uint256 outpointHashIn) { hash = outpointHashIn; }

    COutPoint(uint256 txIdemIn, uint32_t outIdx)
    {
        CSHA256Writer sha;
        sha << txIdemIn << outIdx;
        hash = sha.GetHash();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(hash);
    }

    void SetNull() { hash.SetNull(); }
    bool IsNull() const { return hash.IsNull(); }
    friend bool operator<(const COutPoint &a, const COutPoint &b) { return (a.hash < b.hash); }

    friend bool operator==(const COutPoint &a, const COutPoint &b) { return (a.hash == b.hash); }
    friend bool operator!=(const COutPoint &a, const COutPoint &b) { return !(a == b); }
    std::string ToString() const;

    /** Returns an ascii-hex representation of a binary serialization of this object
        this representation can also be used to deserialize the same object
     */
    std::string GetHex() const;
};


/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    enum
    {
        UTXO = 0,
    };
    uint8_t type = UTXO; // Can also be used as versioning
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CAmount amount = -1; // Must == nValue in the corresponding prevout

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn() { nSequence = SEQUENCE_FINAL; }
    explicit CTxIn(COutPoint prevoutIn,
        CAmount amountIn,
        CScript scriptSigIn = CScript(),
        uint32_t nSequenceIn = SEQUENCE_FINAL);
    CTxIn(uint256 hashPrevTx,
        uint32_t nOut,
        CAmount amountIn,
        CScript scriptSigIn = CScript(),
        uint32_t nSequenceIn = SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(prevout);
        if (!(s.GetType() & SER_GETIDEM))
        {
            READWRITE(*(CScriptBase *)(&scriptSig));
            if (ser_action.ForRead())
            {
                scriptSig.type = ScriptType::PUSH_ONLY;
            }
        }
        READWRITE(nSequence);
        READWRITE(amount);
    }

    friend bool operator==(const CTxIn &a, const CTxIn &b)
    {
        return (
            a.prevout == b.prevout && a.scriptSig == b.scriptSig && a.nSequence == b.nSequence && a.amount == b.amount);
    }

    friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }
    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 * If you have a transaction, use tx.OutpointAt(...) to get the corresponding Outpoint.  This cannot be a member
 * function since the outpoint may rely on the transaction idem.
 */
class CTxOut
{
public:
    uint8_t type; // Can also be used as versioning
    enum
    {
        SATOSCRIPT = 0,
        TEMPLATE = 1,

        INFER = 0x8000 // Not a real type: implies the type should be infered from the script at construction time
    };

    static ScriptType ScriptTypeOf(uint8_t ctxoutType) { return ScriptType(ctxoutType & 1); }

    // version 0 is legacy mode: behave like BCH
    // version 1 is a general form: CScript is type/value data: Group, [group amount if Group size > 0],
    // constraintScriptHash, argsHash, indexed data... push OP_0 for empty field (for example no group or no args).
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut() { SetNull(); }
    CTxOut(const CAmount &nValueIn, CScript scriptPubKeyIn, uint16_t type = INFER);

    // Note, when storing a CTxOut in a Coin (UTXO), a different serialization is used, located in compressor.h
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(type);
        READWRITE(nValue);
        READWRITE(*(CScriptBase *)(&scriptPubKey));
        if (ser_action.ForRead())
        {
            scriptPubKey.type = ScriptTypeOf(type);
        }
    }

    void SetNull()
    {
        type = 0;
        nValue = -1;
        scriptPubKey.clear();
    }

    void SetScript(const CScript &script)
    {
        scriptPubKey = script;
        if (script.type == ScriptType::TEMPLATE)
            type = CTxOut::TEMPLATE;
        if (script.type == ScriptType::SATOSCRIPT)
            type = CTxOut::SATOSCRIPT;
    }

    bool IsNull() const { return (nValue == -1); }
    uint256 GetHash() const;

    CAmount GetDustThreshold() const
    {
        if (scriptPubKey.IsUnspendable())
            return (CAmount)0;

        return (CAmount)dustThreshold.Value();
    }
    bool IsDust() const { return (nValue < GetDustThreshold()); }
    friend bool operator==(const CTxOut &a, const CTxOut &b)
    {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    /** If true, this TxOut will not be added to the UTXO set */
    bool IsDataOnly() const { return ((nValue == 0) && (scriptPubKey.IsUnspendable())); }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) { return !(a == b); }
    std::string ToString() const;
};

/** Returns the same id if the tx has the same change to the blockchain state.  Used to make all malleated transactions
    spendable by the same children.  In this case, the satisfier scripts are not part of the hash since they do not
    affect UTXO state (except in a boolean "is the tx valid or not" fashion).
*/
template <class T>
uint256 GetTxIdem(const T &tx)
{
    return SerializeIdem(tx);
}


/** Returns a unique ID for these bytes in the transaction.  Used only in the block's merkle tree to commit to a
    particular set of transaction bytes.
*/
template <class T>
uint256 GetTxId(const T &tx)
{
    uint256 txidem = GetTxIdem(tx);
    CHashWriter satisfierScriptHash(SER_GETHASH, 0);
    satisfierScriptHash << (int32_t)tx.vin.size();
    uint8_t invalidopcode = OP_INVALIDOPCODE;
    for (const auto &i : tx.vin)
    {
        satisfierScriptHash.write((const char *)i.scriptSig.data(), i.scriptSig.size());
        satisfierScriptHash.write((const char *)&invalidopcode, 1);
    }
    CHashWriter ret;
    // auto num = satisfierScriptHash.GetNumBytesHashed();
    uint256 satHash = satisfierScriptHash.GetHash();
    // LOGA("tx idem %s sat hash %s (%d bytes hashed)", txidem.GetHex(), satHash.GetHex(), num);
    ret << txidem << satHash;
    return ret.GetHash();
}


struct CMutableTransaction;


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 id;
    const uint256 idem;
    void UpdateHash() const;
    mutable std::atomic<size_t> nTxSize; // Serialized transaction size in bytes.


public:
    // Default transaction version.
    static const uint8_t CURRENT_VERSION = 0;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const uint8_t nVersion;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    CTransaction(const CTransaction &tx);
    CTransaction &operator=(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*const_cast<uint8_t *>(&this->nVersion));
        READWRITE(*const_cast<std::vector<CTxIn> *>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut> *>(&vout));
        READWRITE(*const_cast<uint32_t *>(&nLockTime));
        if (ser_action.ForRead())
            UpdateHash();
    }

    template <typename Stream>
    CTransaction(deserialize_type, Stream &s) : CTransaction(CMutableTransaction(deserialize, s))
    {
    }

    bool IsNull() const { return vin.empty() && vout.empty(); }
    // True if only scriptSigs are different
    bool IsEquivalentTo(const CTransaction &tx) const;

    //* Return true if this transaction contains at least one OP_RETURN output.
    bool HasData() const;
    //* Return true if this transaction contains at least one OP_RETURN output, with the specified data ID
    // the data ID is defined as a 4 byte pushdata containing a little endian 4 byte integer.
    bool HasData(uint32_t dataID) const;

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nSize = 0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nSize = 0) const;

    bool IsCoinBase() const { return (vin.size() == 0); }
    friend bool operator==(const CTransaction &a, const CTransaction &b) { return a.id == b.id; }
    friend bool operator!=(const CTransaction &a, const CTransaction &b) { return a.id != b.id; }
    std::string ToString() const;

    // Return the size of the transaction in bytes.
    size_t GetTxSize() const;
    /** return this transaction as a hex string.  Useful for debugging and display */
    std::string HexStr() const;

    // Uses ID:
    // Block merkle tree
    // Tx Introspection (TX_ID)
    // Tx ordering in block
    // Block compression protocols
    // mempool access
    // walletdb id
    const uint256 &GetId() const
    {
#ifdef DEBUG // inefficient to check every time
        //    assert(id == GetTxId(*this));
#endif
        return id;
    }

    /** Returns the same id if the tx has the same change to the blockchain state (idem is latin for the same).
    Transactions are identified in outpoints (that is, how a transaction identifies how it is spent) with an idem.
    Used to make all malleated transactions spendable by the same children.  In this case, the satisfier scripts are
    not part of the hash since they do not affect UTXO state (except in a boolean "is the tx valid or not" fashion).

    Uses Idem:
    tx DAG (COutPoint)
    Network Bloom filters
    Tx Introspection (TX_IDEM)
    orphan pool
    wallet RPCs (tokens and native): when part of a dictionary, both are provided.  When the return value is a single
      hash, the idem is provided.  This is because wallet users do not generally care about malleation status.  They
      simply care whether money was sent or received.
    wallet notify calls
    walletdb tx storage
    */
    const uint256 &GetIdem() const
    {
#ifdef DEBUG // inefficient to check every time
        // assert(idem == GetTxIdem(*this));
#endif
        return idem;
    }

    /** Returns the outpoint that references the output at offset idx */
    COutPoint OutpointAt(size_t idx) const
    {
        DbgAssert(idx < vout.size(), return COutPoint());
        return COutPoint(GetIdem(), idx);
    }

    /** Returns the unsigned CTxIn required to spend an output */
    CTxIn SpendOutput(size_t idx, const CScript &satisfier = CScript()) const
    {
        DbgAssert(idx < vout.size(), return CTxIn());
        return CTxIn(OutpointAt(idx), vout[idx].nValue, satisfier);
    }

    /** Returns the output corresponding to the passed OutPoint.
        Inefficient because it does a search through all outputs.  */
    int PrevOutIdx(const COutPoint &prevout) const
    {
#ifdef DEBUG // inefficient to check every time
        assert(idem == GetTxIdem(*this));
#endif
        for (unsigned int i = 0; i < vout.size(); i++)
        {
            if (prevout == COutPoint(idem, i))
                return i;
        }
        return -1;
    }

    /** Returns the output corresponding to the passed OutPoint.
        Inefficient because it does a search through all outputs. */
    const CTxOut *PrevOut(const COutPoint &prevout) const
    {
        int idx = PrevOutIdx(prevout);
        if (idx < 0)
            return nullptr;
        return &vout[idx];
    }
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    uint8_t nVersion = CTransaction::CURRENT_VERSION;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    CMutableTransaction();
    CMutableTransaction(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s)
    {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    // uint256 GetHash() const;  // GetHash changed to GetId (exact bytes) or GetIdem (same effect).
    uint256 GetId() { return GetTxId(*this); }

    /** Returns the same id if the tx has the same change to the blockchain state (idem is latin for the same).
    Transactions are identified in outpoints (that is, how a transaction identifies how it is spent) with an idem.
    Used to make all malleated transactions spendable by the same children.  In this case, the satisfier scripts are
    not part of the hash since they do not affect UTXO state (except in a boolean "is the tx valid or not" fashion).
    */
    uint256 GetIdem() const { return GetTxIdem(*this); }

    /** Returns the outpoint that references the output at offset idx */
    COutPoint OutpointAt(size_t idx) const
    {
        DbgAssert(idx < vout.size(), return COutPoint());
        return COutPoint(GetIdem(), idx);
    }

    /** Returns the output corresponding to the passed OutPoint.
    Inefficient because it does a search through all outputs.  */
    int PrevOutIdx(const COutPoint &prevout) const
    {
        uint256 idem = GetIdem();
        for (unsigned int i = 0; i < vout.size(); i++)
        {
            if (prevout == COutPoint(idem, i))
                return i;
        }
        return -1;
    }

    /** Returns the unsigned CTxIn required to spend an output */
    CTxIn SpendOutput(size_t idx) const
    {
        DbgAssert(idx < vout.size(), return CTxIn());
        return CTxIn(OutpointAt(idx), vout[idx].nValue);
    }

    /** Returns the output corresponding to the passed OutPoint.
        Inefficient because it does a search through all outputs. */
    const CTxOut *PrevOut(const COutPoint &prevout) const
    {
        int idx = PrevOutIdx(prevout);
        if (idx < 0)
            return nullptr;
        return &vout[idx];
    }

    /** return this transaction as a hex string.  Useful for debugging and display */
    std::string HexStr() const;
    /** return a human-readable representation */
    std::string ToString() const;
};


/** Properties of a transaction that are discovered during tx evaluation */
class CTxProperties
{
public:
    uint64_t countWithAncestors = 0;
    uint64_t sizeWithAncestors = 0;
    uint64_t countWithDescendants = 0;
    uint64_t sizeWithDescendants = 0;
    CTxProperties() {}
    CTxProperties(uint64_t ancestorCount, uint64_t ancestorSize, uint64_t descendantCount, uint64_t descendantSize)
        : countWithAncestors(ancestorCount), sizeWithAncestors(ancestorSize), countWithDescendants(descendantCount),
          sizeWithDescendants(descendantSize)
    {
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<const CTransaction>(); }
template <typename Tx>
static inline CTransactionRef MakeTransactionRef(Tx &&txIn)
{
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}
#endif // NEXA_PRIMITIVES_TRANSACTION_H
