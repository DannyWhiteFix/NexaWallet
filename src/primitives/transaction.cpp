// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hashwrapper.h"
#include "policy/policy.h"
#include "streams.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

const std::string CTxIn::UTXO_TYPE_STR = "UTXO(0)";
const std::string CTxIn::READONLY_TYPE_STR = "READONLY(1)";
const std::string CTxIn::INVALID_TYPE_STR = "INVALID";


std::string SatoshiOutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0, 10), n);
}
std::string COutPoint::ToString() const { return strprintf("COutPoint(%s)", hash.GetHex()); }
std::string COutPoint::GetHex() const { return hash.GetHex(); }

SatoshiTxIn::SatoshiTxIn(SatoshiOutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

SatoshiTxIn::SatoshiTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = SatoshiOutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}


CTxIn::CTxIn(COutPoint prevoutIn, CAmount amountIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    type = UTXO;
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
    amount = amountIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CAmount amountIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    type = UTXO;
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
    amount = amountIn;
}


std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += "type:" + std::to_string(this->type) + ", ";
    str += prevout.ToString();
    str += strprintf(", scriptSig=%s", HexStr(scriptSig));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount &nValueIn, CScript scriptPubKeyIn, uint16_t typeIn)
{
    if ((typeIn & INFER) > 0)
        type = (scriptPubKeyIn.type == ScriptType::TEMPLATE) ? CTxOut::TEMPLATE : CTxOut::SATOSCRIPT;
    else
        type = (uint8_t)typeIn;
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const { return SerializeHash(*this); }
std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d sat, scriptPubKey=%s)", nValue, HexStr(scriptPubKey));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
}

uint256 MutableSatoshiTransaction::GetHash() const { return SerializeHash(*this); }

std::string CMutableTransaction::ToString() const { return CTransaction(*this).ToString(); }

void SatoshiTransaction::UpdateHash() const { *const_cast<uint256 *>(&hash) = SerializeHash(*this); }
void CTransaction::UpdateHash() const
{
    *const_cast<uint256 *>(&id) = GetTxId(*this);
    *const_cast<uint256 *>(&idem) = GetTxIdem(*this);
}
CTransaction::CTransaction() : nTxSize(0), nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0) {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

CTransaction::CTransaction(CMutableTransaction &&tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

CTransaction::CTransaction(const CTransaction &tx)
    : nTxSize(tx.nTxSize.load()), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
};

CTransaction &CTransaction::operator=(const CTransaction &tx)
{
    nTxSize.store(tx.nTxSize);
    *const_cast<uint8_t *>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxIn> *>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut> *>(&vout) = tx.vout;
    *const_cast<unsigned int *>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256 *>(&id) = tx.id;
    *const_cast<uint256 *>(&idem) = tx.idem;
    return *this;
}

SatoshiTransaction &SatoshiTransaction::operator=(const SatoshiTransaction &tx)
{
    nTxSize.store(tx.nTxSize);
    *const_cast<int *>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<SatoshiTxIn> *>(&vin) = tx.vin;
    *const_cast<std::vector<SatoshiTxOut> *>(&vout) = tx.vout;
    *const_cast<unsigned int *>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256 *>(&hash) = tx.hash;
    return *this;
}

bool CTransaction::IsEquivalentTo(const CTransaction &tx) const
{
    CMutableTransaction tx1 = *this;
    CMutableTransaction tx2 = tx;
    for (unsigned int i = 0; i < tx1.vin.size(); i++)
        tx1.vin[i].scriptSig = CScript();
    for (unsigned int i = 0; i < tx2.vin.size(); i++)
        tx2.vin[i].scriptSig = CScript();
    return CTransaction(tx1) == CTransaction(tx2);
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}
CAmount CTransaction::GetValueIn() const
{
    CAmount amount = 0;
    for (const auto &i : vin)
    {
        if (!i.IsReadOnly())
        {
            amount += i.amount;
            if (!MoneyRange(i.amount) || !MoneyRange(amount))
                throw std::runtime_error("CTransaction::GetValueIn(): value out of range");
        }
    }
    return amount;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nSize) const
{
    nSize = CalculateModifiedSize(nSize);
    if (nSize == 0)
        return 0.0;

    return dPriorityInputs / nSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nSize == 0)
        nSize = GetTxSize();
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nSize > offset)
            nSize -= offset;
    }
    return nSize;
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(id=%s, idem=%d, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetId().GetHex(), GetIdem().GetHex(), nVersion, vin.size(), vout.size(), nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += strprintf("   In %d: %s\n", i, vin[i].ToString());
    for (unsigned int i = 0; i < vout.size(); i++)
        str += strprintf("   Out %d %s: %s\n", i, OutpointAt(i).hash.GetHex(), vout[i].ToString());
    return str;
}

size_t CTransaction::GetTxSize() const
{
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, CTransaction::CURRENT_VERSION);
    return nTxSize;
}


bool CTransaction::HasData() const
{
    for (auto &out : vout)
    {
        if ((out.scriptPubKey.size() >= 1) && (out.scriptPubKey[0] == OP_RETURN))
            return true;
    }
    return false;
}

bool CTransaction::HasData(uint32_t dataID) const
{
    for (auto &out : vout)
    {
        if ((out.scriptPubKey.size() >= 6) && (out.scriptPubKey[0] == OP_RETURN) &&
            (out.scriptPubKey[1] == 4)) // IDs must be 4 bytes so check that the pushdata opcode is correct
        {
            uint32_t thisProto = ReadLE32(&out.scriptPubKey[2]);
            if (thisProto == dataID)
                return true;
        }
    }
    return false;
}


std::string CMutableTransaction::HexStr(void) const
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << *this;
    return ::HexStr(ssTx.begin(), ssTx.end());
}

std::string CTransaction::HexStr(void) const
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << *this;
    return ::HexStr(ssTx.begin(), ssTx.end());
}


SatoshiTransaction::SatoshiTransaction()
    : nTxSize(0), nVersion(SatoshiTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0)
{
}

SatoshiTransaction::SatoshiTransaction(const MutableSatoshiTransaction &tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

SatoshiTransaction::SatoshiTransaction(MutableSatoshiTransaction &&tx)
    : nTxSize(0), nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime)
{
    UpdateHash();
}

SatoshiTransaction::SatoshiTransaction(const SatoshiTransaction &tx)
    : nTxSize(tx.nTxSize.load()), nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime)
{
    UpdateHash();
};
