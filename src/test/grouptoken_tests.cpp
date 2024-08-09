// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/grouptokens.h"
#include "consensus/merkle.h"
#include "main.h"
#include "miner.h"
#include "net_processing.h"
#include "protocol.h"
#include "script/sighashtype.h"
#include "test/test_nexa.h"
#include "test/testutil.h"
#include "txadmission.h"
#include "utilstrencodings.h"
#include "validation/validation.h"

#include "wallet/grouptokencache.h"

#ifdef ENABLE_WALLET
#include "wallet/grouptokenwallet.h"
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(grouptoken_tests, BasicTestingSetup)

VchType evec = VchType(); // Empty vector

CAmount authorityFlags(GroupAuthorityFlags f, uint64_t amt = 0)
{
    amt &= ~((uint64_t)GroupAuthorityFlags::ALL_FLAG_BITS);
    return (CAmount)(((uint64_t)f) | amt);
}

class QuickAddress
{
public:
    QuickAddress()
    {
        secret.MakeNewKey(true);
        pubkey = secret.GetPubKey();
        keyId = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(keyId);
        addr = ScriptTemplateDestination(P2pktOutput(pubkey));
    }
    QuickAddress(const CKey &k)
    {
        secret = k;
        pubkey = secret.GetPubKey();
        keyId = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(keyId);
        addr = ScriptTemplateDestination(P2pktOutput(pubkey));
    }
    QuickAddress(unsigned char key) // make a very simple key for testing only
    {
        secret.MakeNewKey(true);
        unsigned char *c = (unsigned char *)secret.begin();
        *c = key;
        c++;
        for (int i = 1; i < 32; i++, c++)
        {
            *c = 0;
        }
        pubkey = secret.GetPubKey();
        keyId = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(keyId);
        addr = ScriptTemplateDestination(P2pktOutput(pubkey));
    }

    CKey secret;
    CPubKey pubkey;
    CKeyID keyId; // 160 bit normal address
    ScriptTemplateDestination addr;
    uint256 eAddr; // 256 bit extended address
    CGroupTokenID grp; // Not really how groupIds are made, but this just creates a viable group Id from these bytes
};

// create a group pay to public key hash script
CScript cp2pk = CScript() << OP_FROMALTSTACK << OP_CHECKSIGVERIFY; // Commitment-pay-to-public-key
auto cp2pkHash = Hash160(cp2pk); // hash of the contract
auto cp2pkLongHash = VchHash(ToByteVector(cp2pk)); // hash of the contract
auto fakeArgs = VchHash160(ToByteVector(CScript() << VchType(20)));
CScript gp2pkh(const CGroupTokenID &group, const QuickAddress &dest, CAmount amt)
{
    // template will have the signature on the stack (from the satisfier), and the pubkey on the altstack (from the
    // constraint).  So pull the pubkey on top and try a CHECKSIG.
    CScript tArgs = CScript() << ToByteVector(dest.pubkey);
    CScript script = CScript(ScriptType::TEMPLATE)
                     << group.bytes() << SerializeAmount(amt) << Hash160(cp2pk) << Hash160(tArgs);
    return script;
}

VchType ArgsHash(VchType arg)
{
    CScript tArgs = CScript() << arg;
    return VchHash160(tArgs);
}
VchType ArgsHash(QuickAddress arg)
{
    CScript tArgs = CScript() << ToByteVector(arg.pubkey);
    return VchHash160(tArgs);
}

// create a group pay to public key hash script
CScript gp2pkh_variant(const CGroupTokenID &group, const QuickAddress &dest, CAmount amt)
{
    CScript templat = CScript() << OP_FROMALTSTACK << OP_CHECKSIG << OP_VERIFY;
    CScript tArgs = CScript() << ToByteVector(dest.pubkey);
    CScript script = CScript(ScriptType::TEMPLATE)
                     << group.bytes() << SerializeAmount(amt) << Hash160(templat) << Hash160(tArgs);
    return script;
}


// create a group pay to public key hash script
CScript p2pkh(const QuickAddress &dest)
{
    CScript templat = CScript() << OP_CHECKSIG;
    CScript tArgs = CScript() << ToByteVector(dest.pubkey);
    CScript script = CScript(ScriptType::TEMPLATE) << OP_0 << Hash160(templat) << Hash160(tArgs);
    return script;
}


std::vector<unsigned char> breakable_SerializeAmount(CAmount amt)
{
    uint64_t num = (uint64_t)amt;
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 256)
    {
        ser_writedata8(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata32(strm, num);
    }
    else
    {
        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}


CScript breakable_p2pkt(const CGroupTokenID &group, const QuickAddress &dest, CAmount amt)
{
    // template will have the signature on the stack (from the satisfier), and the pubkey on the altstack (from the
    // constraint).  So pull the pubkey on top and try a CHECKSIG.
    CScript tArgs = CScript() << ToByteVector(dest.pubkey);
    CScript script = CScript(ScriptType::TEMPLATE)
                     << group.bytes() << breakable_SerializeAmount(amt) << Hash160(cp2pk) << Hash160(tArgs);
    return script;
}

CScript breakable_p2pkt(std::vector<unsigned char> groupId, const ScriptTemplateDestination &dest, CAmount amt)
{
    // I have to parse this destination out so I can put it back together broken.
    std::vector<unsigned char> templateHash;
    std::vector<unsigned char> argsHash;
    CScript::const_iterator pcout = dest.toScript().begin();
    ScriptTemplateError err = GetScriptTemplate(dest.toScript(), nullptr, &templateHash, &argsHash, &pcout);
    assert(err == ScriptTemplateError::OK);

    CScript script = CScript(ScriptType::TEMPLATE)
                     << groupId << breakable_SerializeAmount(amt) << templateHash << argsHash;
    return script;
}


CScript breakable_ScriptTemplateOutput(const uint160 &scriptHash,
    const VchType &argsHash = VchType(),
    const VchType &visibleArgs = VchType(),
    const VchType &group = VchType(),
    CAmount grpQuantity = -1)
{
    CScript ret;
    if (group != NoGroup.bytes())
    {
        if (grpQuantity != -1)
        {
            ret = (CScript(ScriptType::TEMPLATE)
                      << group << breakable_SerializeAmount(grpQuantity) << scriptHash << argsHash) +
                  CScript(visibleArgs.begin(), visibleArgs.end());
        }
        else // Encodes an invalid quantity (for use within addresses)
        {
            ret = (CScript(ScriptType::TEMPLATE) << group << OP_0 << scriptHash << argsHash) +
                  CScript(visibleArgs.begin(), visibleArgs.end());
        }
    }
    else // Not grouped
    {
        ret = (CScript(ScriptType::TEMPLATE) << OP_0 << scriptHash << argsHash) +
              CScript(visibleArgs.begin(), visibleArgs.end());
    }
    return ret;
}


CScript breakable_ScriptTemplateOutput(const VchType &scriptHash,
    const VchType &argsHash,
    const VchType &visibleArgs,
    const VchType &group,
    const VchType &grpQuantity)
{
    CScript ret = (CScript(ScriptType::TEMPLATE) << group << grpQuantity << scriptHash << argsHash) +
                  CScript(visibleArgs.begin(), visibleArgs.end());
    return ret;
}


/*
std::string HexStrTx(const CMutableTransaction &tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}
*/


COutPoint AddUtxo(const CScript &script, uint64_t amount, CCoinsViewCache &coins)
{
    static arith_uint256 uniquifier;
    // This creates an unbalanced transaction but it doesn't matter because AddCoins doesn't validate the tx
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = ArithToUint256(uniquifier);
    tx.vin[0].amount = amount;
    uniquifier++;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = script;
    tx.vout[0].nValue = amount;
    if (script.type == ScriptType::TEMPLATE)
        tx.vout[0].type = CTxOut::TEMPLATE;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    int height = 1; // doesn't matter for our purposes
    AddCoins(coins, tx, height);
    return COutPoint(tx.GetIdem(), 0);
}

class InputData
{
public:
    const CTransaction &prevtx;
    int prevout;
    CKey key;
    InputData(const CTransaction &_prevTx, int _prevout, const CKey &_key)
        : prevtx(_prevTx), prevout(_prevout), key(_key)
    {
    }

    CScript createSatisfier(const VchType &sig) const
    {
        const CTxOut &prevtxout = prevtx.vout[prevout];
        txnouttype type;
        std::vector<VchType> solns;
        CGroupTokenInfo grp;
        if (prevtxout.type == CTxOut::TEMPLATE) // TODO add to solver
        {
            // TODO check that the script hash is gp2pkc rather than assuming
            // only one script is used right now: gp2pkc
            //                  script preimage        args preimage (just the pubkey)        satisfier args
            CScript argsScript = CScript() << ToByteVector(key.GetPubKey());
            return CScript() << ToByteVector(cp2pk) << ToByteVector(argsScript) << sig;
        }
        else
        {
            bool ok = ExtendedSolver(prevtxout.scriptPubKey, type, solns, grp);
            BOOST_CHECK(ok);
            if (type == TX_PUBKEY)
            {
                return CScript() << sig;
            }
            if ((type == TX_GRP_PUBKEYHASH) || (type == TX_PUBKEYHASH))
            {
                return CScript() << sig << ToByteVector(key.GetPubKey());
            }
            else
            {
                assert(0); // test malfunction
            }
        }
    }
};

class InputDataCopy : public InputData
{
public:
    CTransaction prevtxStorage;
    InputDataCopy(const CTransaction &prevTx, int _prevout, const CKey &_key)
        : InputData(prevtxStorage, _prevout, _key), prevtxStorage(prevTx)
    {
    }
};

typedef std::pair<CScript, CAmount> OutputData;

CTransaction tx(const std::vector<InputData> &in, const std::vector<OutputData> &out)
{
    CMutableTransaction tx;
    tx.vin.resize(in.size());
    int idx = 0;
    for (auto i : in)
    {
        tx.vin[idx] = i.prevtx.SpendOutput(i.prevout);
        idx++;
    }

    tx.vout.resize(out.size());
    idx = 0;
    for (auto o : out)
    {
        tx.vout[idx].scriptPubKey = o.first;
        tx.vout[idx].nValue = o.second;
        if (o.first.type == ScriptType::TEMPLATE)
            tx.vout[idx].type = CTxOut::TEMPLATE;
        idx++;
    }

    tx.nLockTime = 0;

    idx = 0;
    for (auto i : in)
    {
        std::vector<unsigned char> vchSig;
        CScript signedScriptCode;
        // the scriptcode is the executed template for this type of script
        if (i.prevtx.vout[i.prevout].scriptPubKey.type == ScriptType::TEMPLATE)
            signedScriptCode = cp2pk;
        else
            signedScriptCode = i.prevtx.vout[i.prevout].scriptPubKey;
        uint256 hash = SignatureHash(signedScriptCode, tx, idx, defaultSigHashType, i.prevtx.vout[i.prevout].nValue, 0);
        if (!i.key.SignSchnorr(hash, vchSig))
        {
            assert(0);
        }
        defaultSigHashType.appendToSig(vchSig);
        tx.vin[idx].scriptSig = i.createSatisfier(vchSig);
        idx++;
    }

    return tx;
}


CTransaction tx2x2(const InputData &in1,
    const InputData &in2,
    const CScript &txo0,
    CAmount amt0,
    const CScript &txo1,
    CAmount amt1)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = COutPoint(in1.prevtx.GetIdem(), in1.prevout);
    tx.vin[0].scriptSig = CScript();
    tx.vin[1].prevout = COutPoint(in2.prevtx.GetIdem(), in2.prevout);
    tx.vin[1].scriptSig = CScript();

    tx.vout.resize(2);
    tx.vout[0].SetScript(txo0);
    tx.vout[0].nValue = amt0;
    tx.vout[1].SetScript(txo1);
    tx.vout[1].nValue = amt1;

    tx.nLockTime = 0;

    SigHashType sigHashType = defaultSigHashType;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(
        in1.prevtx.vout[in1.prevout].scriptPubKey, tx, 0, sigHashType, in1.prevtx.vout[in1.prevout].nValue, 0);
    if (!in1.key.SignSchnorr(hash, vchSig))
    {
        assert(0);
    }
    sigHashType.appendToSig(vchSig);
    tx.vin[0].scriptSig = in1.createSatisfier(vchSig);

    std::vector<unsigned char> vchSig2;
    hash = SignatureHash(
        in2.prevtx.vout[in2.prevout].scriptPubKey, tx, 1, sigHashType, in2.prevtx.vout[in2.prevout].nValue, 0);
    if (!in2.key.SignSchnorr(hash, vchSig2))
    {
        assert(0);
    }
    sigHashType.appendToSig(vchSig);

    tx.vin[1].scriptSig = in2.createSatisfier(vchSig2);

    return tx;
}


CTransaction tx2x1(const COutPoint &utxo1, const COutPoint &utxo2, const CScript &txo, CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vout.resize(1);
    tx.vout[0].SetScript(txo);
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // CheckGroupTokens does not validate sig so anything in here
    tx.nLockTime = 0;
    return tx;
}

CTransaction tx3x1(const COutPoint &utxo1,
    const COutPoint &utxo2,
    const COutPoint &utxo3,
    const CScript &txo,
    CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(3);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vin[2].prevout = utxo3;
    tx.vout.resize(1);
    tx.vout[0].SetScript(txo);
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // CheckGroupTokens does not validate sig so anything in here
    tx.nLockTime = 0;
    return tx;
}

CTransaction tx2x2(const COutPoint &utxo1,
    const COutPoint &utxo2,
    const CScript &txo1,
    CAmount amt1,
    const CScript &txo2,
    CAmount amt2)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vin[0].prevout = utxo1;
    tx.vin[1].prevout = utxo2;
    tx.vout.resize(2);
    tx.vout[0].SetScript(txo1);
    tx.vout[0].nValue = amt1;
    tx.vin[0].scriptSig = CScript(); // CheckGroupTokens does not validate sig so anything in here
    tx.vout[1].SetScript(txo2);
    tx.vout[1].nValue = amt2;
    tx.vin[1].scriptSig = CScript(); // CheckGroupTokens does not validate sig so anything in here

    tx.nLockTime = 0;
    return tx;
}


CGroupTokenID MakeSubgroup(CGroupTokenID g, int xtra, int size = 0)
{
    int gsize = g.bytes().size();
    if (size == 0)
        size = gsize + 1; // 0 means default which is 1 byte bigger
    std::vector<unsigned char> sgbytes(gsize + size);
    for (int i = 0; i < gsize; i++)
        sgbytes[i] = g.bytes()[i];
    sgbytes[gsize] = xtra;
    for (int i = gsize + 1; i < size; i++)
        sgbytes[i] = 0; // just fill it out
    return CGroupTokenID(sgbytes);
}


BOOST_AUTO_TEST_CASE(grouptoken_covenantfunctions)
{
    // Create a utxo set that I can run tests against
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    QuickAddress u1;
    QuickAddress u2;

    CGroupTokenID cgrp1(1, GroupTokenIdFlags::COVENANT);
    CGroupTokenID cgrp2(2, GroupTokenIdFlags::COVENANT);
    CGroupTokenID cfgrp1(3, GroupTokenIdFlags::HOLDS_NEX | GroupTokenIdFlags::COVENANT);

    COutPoint bch1 = AddUtxo(p2pkh(u1), 10000, coins);
    COutPoint gutxo100 = AddUtxo(gp2pkh(cgrp1, u1, 100), 1000, coins);
    COutPoint gutxo200v = AddUtxo(gp2pkh_variant(cgrp1, u2, 200), 1000, coins);

    COutPoint cfutxo100 = AddUtxo(gp2pkh(cfgrp1, u1, 0), 100, coins);

    COutPoint cgrp1Mint =
        AddUtxo(gp2pkh(cgrp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1000, coins);
    COutPoint cgrp1Rescript = AddUtxo(
        gp2pkh(cgrp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT)), 1000, coins);
    COutPoint cgrp1RescriptMint = AddUtxo(
        gp2pkh(cgrp1, u1,
            toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::RESCRIPT)),
        1000, coins);

    COutPoint cfgrp1Mint =
        AddUtxo(gp2pkh(cfgrp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1000, coins);

    bool ok;
    CTransaction t;
    CValidationState state;

    // These tests use a p2pkh script as the covenant.  This does not make much sense, but that is not relevant within
    // the context of these tests.
    // A real covenant will be anyone-can-spend (so long as they fulfill other script constraints).  With templates, we
    // will be able to constrain the covenant to a particular FORM, allowing the holder to fill-in-the-blanks
    // (with their own address) in the simplest use.


    // REQ3.2.4.1

    // basic operation
    t = tx1x1(gutxo100, gp2pkh(cgrp1, u1, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // incorrect covenant
    t = tx1x1(gutxo100, gp2pkh_variant(cgrp1, u2, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // basic operation 2 outputs
    t = tx1x2(gutxo100, gp2pkh(cgrp1, u1, 50), 100, gp2pkh(cgrp1, u1, 50), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // incorrect covenant in 1 of the 2 outputs
    t = tx1x2(gutxo100, gp2pkh_variant(cgrp1, u1, 50), 100, gp2pkh(cgrp1, u2, 50), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Outputs must pay to first prevout script
    // If 2 inputs exist with different constraint scripts, the tx author can choose which one to use
    t = tx2x2(gutxo200v, gutxo100, gp2pkh_variant(cgrp1, u1, 150), 100, gp2pkh_variant(cgrp1, u2, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    t = tx2x2(gutxo100, gutxo200v, gp2pkh(cgrp1, u1, 150), 100, gp2pkh(cgrp1, u2, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // must pay to first prevout script (not the 2nd)
    t = tx2x2(gutxo200v, gutxo100, gp2pkh(cgrp1, u1, 150), 100, gp2pkh(cgrp1, u1, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // must pay to first prevout script (not the 2nd)
    t = tx2x2(gutxo100, gutxo200v, gp2pkh_variant(cgrp1, u2, 150), 100, gp2pkh_variant(cgrp1, u1, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Unless rescript authority is spent
    t = tx2x2(cgrp1Rescript, gutxo100, gp2pkh(cgrp1, u1, 50), 100, gp2pkh_variant(cgrp1, u2, 50), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    // Unless rescript authority is spent (swap order)
    t = tx2x2(gutxo200v, cgrp1Rescript, gp2pkh_variant(cgrp1, u1, 100), 100, gp2pkh(cgrp1, u2, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Invalid mint
    t = tx2x2(gutxo200v, cgrp1Rescript, gp2pkh_variant(cgrp1, u1, 440), 100, gp2pkh(cgrp1, u2, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Same as previous but mint included
    t = tx2x2(gutxo200v, cgrp1RescriptMint, gp2pkh_variant(cgrp1, u1, 440), 100, gp2pkh(cgrp1, u2, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Include multiple authorities to allow both mint and rescript
    t = tx2x2(cgrp1Mint, cgrp1Rescript, gp2pkh(cgrp1, u1, 440), 100, gp2pkh(cgrp1, u2, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Include multiple authorities to allow both mint and rescript
    t = tx3x1(cgrp1Mint, cgrp1Rescript, gutxo100, gp2pkh(cgrp1, u2, 200), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Invalid it melts and Include multiple authorities to allow both mint and rescript
    t = tx3x1(cgrp1Mint, cgrp1Rescript, gutxo100, gp2pkh(cgrp1, u2, 50), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Authorities are ignored when determining the covenant

    t = tx2x2(cgrp1Mint, gutxo100, gp2pkh(cgrp1, u1, 150), 100, gp2pkh(cgrp1, u1, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Its a mint so output might not balance, but STILL must match the covenant
    t = tx2x2(cgrp1Mint, gutxo100, gp2pkh(cgrp1, u1, 150), 100, gp2pkh(cgrp1, u1, 200), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    t = tx2x2(cgrp1Mint, gutxo100, gp2pkh_variant(cgrp1, u2, 150), 100, gp2pkh_variant(cgrp1, u1, 200), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // REQ3.2.4.2 (if no RESCRIPT and the first groupt non-authority does not exist, return INVALID
    t = tx1x1(cgrp1Mint, gp2pkh(cgrp1, u2, 150), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);


    // All the covenant stuff should work exactly the same for fenced NEX
    // Since it ought to be the same implementation, every case above is not checked

    t = tx1x1(cfutxo100, gp2pkh(cfgrp1, u1, 0), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // incorrect fenced group amount (must be 0)
    t = tx1x1(cfutxo100, gp2pkh(cfgrp1, u1, 100), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // incorrect covenant
    t = tx1x1(cfutxo100, gp2pkh(cgrp1, u2, 0), 100);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // basic operation 2 outputs
    t = tx1x2(cfutxo100, gp2pkh(cfgrp1, u1, 0), 25, gp2pkh(cfgrp1, u1, 0), 75);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // incorrect covenant in 1 of the 2 outputs
    t = tx1x2(cfutxo100, gp2pkh(cfgrp1, u1, 0), 25, gp2pkh_variant(cfgrp1, u2, 0), 75);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Its a mint so output might not balance, but STILL must match the covenant
    t = tx3x1(cfgrp1Mint, cfutxo100, bch1, gp2pkh(cfgrp1, u1, 0), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    // Invalid fenced mint authority but melting
    t = tx3x1(cfgrp1Mint, cfutxo100, bch1, gp2pkh(cfgrp1, u1, 0), 50);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // Invalid wrong script
    t = tx3x1(cfgrp1Mint, cfutxo100, bch1, gp2pkh_variant(cfgrp1, u2, 0), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
}


BOOST_AUTO_TEST_CASE(grouptoken_fencefunctions)
{
    // Create a utxo set that I can run tests against
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    QuickAddress u1;
    QuickAddress u2;

    CGroupTokenID fgrp1(1, GroupTokenIdFlags::HOLDS_NEX);
    CGroupTokenID fgrp2(2, GroupTokenIdFlags::HOLDS_NEX);

    COutPoint bch1 = AddUtxo(p2pkh(u1), 10000, coins);
    COutPoint fencedBch = AddUtxo(gp2pkh(fgrp1, u1, 0), 20000, coins);
    COutPoint fencedBch2 = AddUtxo(gp2pkh(fgrp1, u1, 0), 20, coins);

    COutPoint fencedGrp2Bch = AddUtxo(gp2pkh(fgrp2, u1, 0), 30, coins);

    COutPoint fenceMint =
        AddUtxo(gp2pkh(fgrp1, u2, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1000, coins);
    COutPoint fenceMelt =
        AddUtxo(gp2pkh(fgrp1, u2, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT)), 1000, coins);

    bool ok;
    CTransaction t;
    CValidationState state;

    // Fenced NEX cannot have a token quantity
    t = tx1x1(fenceMint, gp2pkh(fgrp1, u1, 100000), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Since mint authority spent, NEX can move into the group
    t = tx1x1(fenceMint, gp2pkh(fgrp1, u1, 0), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // NEX from other inputs can move into the group (but all of it does not have to)
    t = tx2x1(bch1, fenceMint, gp2pkh(fgrp1, u1, 0), 5000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Wrong authority, NEX cannot move into the group
    t = tx1x1(fenceMelt, gp2pkh(fgrp1, u1, 0), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // NEX moved out of the group (from the melt authority itself)
    t = tx1x1(fenceMelt, p2pkh(u1), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // NEX moved out of the group (from the melt authority and combined with another), plus some fees
    t = tx2x1(fenceMelt, bch1, p2pkh(u1), 10010);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // NEX moved out of the group (from the melt authority and combined with another), plus some fees
    t = tx2x1(fenceMelt, fencedBch, p2pkh(u1), 20010);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // only some NEX moved out of the group (from the melt authority and combined with another), plus some fees
    t = tx2x2(fenceMelt, fencedBch, p2pkh(u1), 10010, gp2pkh(fgrp1, u1, 0), 10900);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // incorrect NEX move into the group (no mint auth)
    t = tx1x1(bch1, gp2pkh(fgrp1, u1, 0), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // incorrect NEX move into the group (no mint auth)
    t = tx2x1(fenceMelt, bch1, gp2pkh(fgrp1, u1, 0), 1000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // correct NEX and fenced NEX move (atomic swap of unfenced and fenced NEX)
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 20000, p2pkh(u2), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    // incorrect NEX and fenced NEX move (bad group quantity)
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 1), 20000, p2pkh(u2), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // incorrect NEX and fenced NEX move (quantities cause melt)
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 19999, p2pkh(u2), 10001);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // incorrect NEX and fenced NEX move (quantities cause mint)
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 20001, p2pkh(u2), 9999);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);


    // correct fenced NEX split with big fee
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 10000, gp2pkh(fgrp1, u2, 0), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    // incorrect fenced NEX split with big fee
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 10001, gp2pkh(fgrp1, u2, 0), 10000);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // incorrect fenced NEX split with big fee
    t = tx2x2(bch1, fencedBch, gp2pkh(fgrp1, u1, 0), 10000, gp2pkh(fgrp1, u2, 0), 9999);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // correct fenced NEX join
    t = tx2x1(fencedBch2, fencedBch, gp2pkh(fgrp1, u1, 0), 20020);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);
    // incorrect fenced NEX join
    t = tx2x1(fencedBch2, fencedBch, gp2pkh(fgrp1, u1, 0), 20021);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // incorrect fenced NEX join
    t = tx2x1(fencedBch2, fencedBch, gp2pkh(fgrp1, u1, 0), 20019);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // 2 Fenced NEX groups cannot exchange NEX
    t = tx2x1(fencedGrp2Bch, fencedBch, gp2pkh(fgrp1, u1, 0), 20030);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // 2 Fenced NEX groups cannot exchange NEX
    t = tx2x1(fencedGrp2Bch, fencedBch, gp2pkh(fgrp2, u1, 0), 20030);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);

    // Fenced NEX group atomic exchange
    t = tx2x2(fencedGrp2Bch, fencedBch2, gp2pkh(fgrp1, u1, 0), 20, gp2pkh(fgrp2, u2, 0), 30);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(ok);

    // Incorrect Fenced NEX group atomic exchange
    t = tx2x2(fencedGrp2Bch, fencedBch2, gp2pkh(fgrp1, u1, 20), 0, gp2pkh(fgrp2, u2, 30), 0);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
    // Incorrect Fenced NEX group atomic exchange
    t = tx2x2(fencedGrp2Bch, fencedBch2, gp2pkh(fgrp1, u1, 20), 20, gp2pkh(fgrp2, u2, 30), 30);
    ok = CheckGroupTokens(t, state, coins);
    BOOST_CHECK(!ok);
}

#ifdef ENABLE_WALLET

void basicFunctionsTest(uint32_t scriptFlags)
{
    CKey secret;
    CPubKey pubkey;
    ScriptTemplateDestination addr;
    uint256 eAddr;
    secret.MakeNewKey(true);
    pubkey = secret.GetPubKey();
    addr = ScriptTemplateDestination(P2pktOutput(pubkey));
    eAddr = pubkey.GetHash();

    std::vector<unsigned char> goodArgsHash(VchHash160(ToByteVector(CScript() << ToByteVector(pubkey))));

    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(21);
        fakeGrp[10] = 1; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(19);
        fakeGrp[10] = 1; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(1);
        fakeGrp[0] = 234; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check incorrect group length
        std::vector<unsigned char> fakeGrp(31);
        fakeGrp[10] = 1; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }

    { // check incorrect group length (hash160 length)
        std::vector<unsigned char> fakeGrp(20);
        fakeGrp[10] = 1; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.isInvalid());
    }
    { // check correct group length
        std::vector<unsigned char> fakeGrp(32);
        fakeGrp[10] = 1; // Stop it from simplifying
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, goodArgsHash, evec, fakeGrp, 1000);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(!ret.isInvalid());
        BOOST_CHECK(ret == CGroupTokenInfo(CGroupTokenID(fakeGrp), GroupAuthorityFlags::NONE));

        // check correct group to string encoding
        std::string addrAsStr(EncodeGroupToken(ret.associatedGroup, Params()));
        BOOST_CHECK(addrAsStr == "nexa:tqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf0xf9lp4");
    }

    { // check CGroupTokenID handling of subgroups
        std::vector<unsigned char> fakeGrp(36);
        for (int i = 0; i < 36; i++)
            fakeGrp[i] = i;
        CGroupTokenID subgrp(fakeGrp);
        BOOST_CHECK(subgrp.isSubgroup());
        BOOST_CHECK(subgrp.parentGroup().bytes().size() == 32);
        CGroupTokenID parentgrp = subgrp.parentGroup();
        for (unsigned int i = 0; i < parentgrp.bytes().size(); i++)
            BOOST_CHECK(parentgrp.bytes()[i] == i);
    }


    { // check P2PKH
        CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY
                                   << OP_CHECKSIG;
        CGroupTokenInfo ret(script);
        BOOST_CHECK(!ret.isInvalid());
        BOOST_CHECK(ret == CGroupTokenInfo(NoGroup, GroupAuthorityFlags::NONE));
    }

    uint256 grpAddr;
    VchType longArgsHash(32);
    longArgsHash[31] = 123;
    for (CAmount qty = 0; qty < 257; qty += 1)
    { // check GP2PKH
        CScript script = P2pktOutput(goodArgsHash, grpAddr, qty);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret == CGroupTokenInfo(grpAddr, GroupAuthorityFlags::NONE, qty));

        CScript script2 = ScriptTemplateOutput(ToByteVector(cp2pkHash), longArgsHash, evec, grpAddr, qty);
        CGroupTokenInfo ret2(script2);
        BOOST_CHECK(ret2 == CGroupTokenInfo(grpAddr, GroupAuthorityFlags::NONE, qty));

        CScript script3 = ScriptTemplateOutput(ToByteVector(cp2pkLongHash), longArgsHash, evec, grpAddr, qty);
        CGroupTokenInfo ret3(script3);
        BOOST_CHECK(ret3 == CGroupTokenInfo(grpAddr, GroupAuthorityFlags::NONE, qty));

        CTxDestination resultDest;
        bool worked = ExtractDestination(script, resultDest);
        ScriptTemplateDestination resultAddr = *(std::get_if<ScriptTemplateDestination>(&resultDest));
        BOOST_CHECK(worked && (resultAddr == addr));

        // Verify that the script passes standard checks, especially the data coding
        Stack stack;
        ScriptError err = SCRIPT_ERR_OK;
        // bool r =
        EvalScript(stack, script, scriptFlags, MAX_OPS_PER_SCRIPT, ScriptImportedState(), &err);
        // BOOST_CHECK(r);  r will be false because the signature check will fail.  What's important here is that
        // minimaldata passes (which is a mandatory script flag so must be set).
        BOOST_CHECK(err != SCRIPT_ERR_MINIMALDATA);
    }

    // check invalid 1 character amount
    for (int i = 0; i < 256; i++)
    {
        std::vector<uint8_t> tmp(1);
        tmp[0] = i;
        CScript script =
            breakable_ScriptTemplateOutput(ToByteVector(cp2pkHash), VchType(20), evec, ToByteVector(grpAddr), tmp);
        CGroupTokenInfo ret(script);
        BOOST_CHECK(ret.invalid == true);
    }

    // Now test transaction balances
    {
        CGroupTokenID grp1(1);
        CGroupTokenID grp2(2);
        CGroupTokenID grp3(3);
        QuickAddress u1;
        QuickAddress u2;

        CGroupTokenID subgrp1a = MakeSubgroup(grp1, 1);
        CGroupTokenID subgrp1b = MakeSubgroup(grp1, 2);
        CGroupTokenID subgrp1c = MakeSubgroup(grp1, 2, GENESIS_MAX_SCRIPT_ELEMENT_SIZE);
        CGroupTokenID subgrp1cTooBig = MakeSubgroup(grp1, 2, GENESIS_MAX_SCRIPT_ELEMENT_SIZE + 1);

        // Create a utxo set that I can run tests against
        CCoinsView coinsDummy;
        CCoinsViewCache coins(&coinsDummy);
        CValidationState state;
        COutPoint gutxo = AddUtxo(gp2pkh(grp1, u1, 100), 1, coins);
        COutPoint gutxo_burnable = AddUtxo(gp2pkh(grp1, u1, 100), 2, coins);
        COutPoint mintctrl1 =
            AddUtxo(gp2pkh(grp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1, coins);
        COutPoint mintctrl1sg = AddUtxo(
            gp2pkh(grp1, u1,
                toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP | GroupAuthorityFlags::MINT)),
            1, coins);
        COutPoint mintChildAuth1sg = AddUtxo(gp2pkh(grp1, u1,
                                                 toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON |
                                                          GroupAuthorityFlags::SUBGROUP | GroupAuthorityFlags::MINT)),
            1, coins);
        COutPoint mintChildAuth1 = AddUtxo(
            gp2pkh(grp1, u1,
                toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::BATON)),
            1, coins);
        COutPoint rescriptChildAuth1 = AddUtxo(
            gp2pkh(grp1, u1,
                toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
            1, coins);
        COutPoint rescriptChildAuth1sg =
            AddUtxo(gp2pkh(grp1, u1,
                        toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP |
                                 GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
                1, coins);
        COutPoint mintctrl2 =
            AddUtxo(gp2pkh(grp2, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1, coins);
        COutPoint meltctrl1 =
            AddUtxo(gp2pkh(grp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT)), 1, coins);
        COutPoint meltctrl2 =
            AddUtxo(gp2pkh(grp2, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT)), 1, coins);
        COutPoint putxo = AddUtxo(p2pkh(u1), 1, coins);
        COutPoint putxo2 = AddUtxo(p2pkh(u1), 2, coins);

        {
            // check token creation tx
            CScript opretScript;
            uint64_t grpNonce = 0;
            CGroupTokenID grpID = findGroupId(
                putxo, opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);
            CScript script =
                GetScriptForDestination(u1.addr, grpID, (CAmount)GroupAuthorityFlags::ACTIVE_FLAG_BITS | grpNonce);
            CTransaction t = tx1x1(putxo, script, 1);
            bool ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok); // REQ3.2.1.5

            // check token creation tx, reduced authority bits
            grpNonce = 0;
            grpID = findGroupId(putxo, opretScript, GroupTokenIdFlags::NONE,
                GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID, grpNonce);
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok); // REQ3.2.1.5

            // check token creation tx, big nonce
            grpNonce = (~((uint64_t)GroupAuthorityFlags::ALL_FLAG_BITS)) - 100;
            grpID = findGroupId(putxo, opretScript, GroupTokenIdFlags::NONE,
                GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID, grpNonce);
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok); // REQ3.2.1.5

            // check token creation tx, big nonce does not leak into authority flags
            grpNonce = (uint64_t)~GroupAuthorityFlags::ALL_FLAG_BITS;
            grpID = findGroupId(putxo, opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::AUTHORITY, grpNonce);
            BOOST_CHECK(
                (grpNonce & (uint64_t)GroupAuthorityFlags::ALL_FLAG_BITS) == (uint64_t)GroupAuthorityFlags::AUTHORITY);
            script = GetScriptForDestination(u1.addr, grpID, grpNonce);
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok); // REQ3.2.1.5

            // check token creation tx, no authority flag
            grpNonce = 0;
            grpID = findGroupId(putxo, opretScript, GroupTokenIdFlags::NONE,
                GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID, grpNonce);
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok); // REQ3.2.1.5

            // script has bad nonce
            grpID = findGroupId(
                putxo, opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);
            script = GetScriptForDestination(
                u1.addr, grpID, (CAmount)GroupAuthorityFlags::ACTIVE_FLAG_BITS | (grpNonce + 1));
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok); // REQ3.2.1.5

            // flag bits changed
            grpID = findGroupId(
                putxo, opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID,
                (CAmount)GroupAuthorityFlags::AUTHORITY | (CAmount)GroupAuthorityFlags::MINT | (grpNonce + 1));
            t = tx1x1(putxo, script, 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok); // REQ3.2.1.5

            // Check that OP_RETURN is included in group calc
            std::vector<unsigned char> data{'a', 'b', 'c'};
            opretScript = CScript() << OP_RETURN << data;
            grpID =
                findGroupId(putxo, CScript(), GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID, (CAmount)GroupAuthorityFlags::ACTIVE_FLAG_BITS | grpNonce);
            t = tx2x2(putxo, putxo2, script, 1, opretScript, 0);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // Check that OP_RETURN is included in group calc
            grpID = findGroupId(
                putxo, opretScript, GroupTokenIdFlags::NONE, GroupAuthorityFlags::ACTIVE_FLAG_BITS, grpNonce);
            script = GetScriptForDestination(u1.addr, grpID, (CAmount)GroupAuthorityFlags::ACTIVE_FLAG_BITS | grpNonce);
            t = tx2x2(putxo, putxo2, script, 1, opretScript, 0);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // check mint tx

            // without mint authority
            t = tx2x1(putxo2, putxo, gp2pkh(grp1, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // same, grouped
            t = tx2x1(putxo2, putxo, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // with an authority that does not include minting
            t = tx2x1(meltctrl1, putxo, gp2pkh(grp1, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // with minting authority
            t = tx2x1(mintctrl1, putxo, gp2pkh(grp1, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            // same, grouped
            t = tx2x1(mintctrl1, putxo, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1c, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // this works because the size limitation enforced during script execution only.
            // token subgroups have no max size...
            t = tx2x1(mintctrl1sg, putxo, gp2pkh(subgrp1cTooBig, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 2 utxos
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1, 100000), 1, gp2pkh(grp1, u2, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1, 100000), 1, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx1x2(mintctrl1, gp2pkh(subgrp1b, u1, 100000), 1, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx1x2(mintctrl1sg, gp2pkh(grp1, u1, 100000), 1, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            t = tx1x2(mintctrl1sg, gp2pkh(subgrp1b, u1, 100000), 1, gp2pkh(subgrp1a, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 1 utxos, 2 outputs
            t = tx1x2(mintctrl1, p2pkh(u1), 1, gp2pkh(grp1, u1, 100000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            // mint to 1 utxos, 2 outputs
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1, 100000), 1, p2pkh(u1), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // mint to 2 utxos, 1 group is wrong
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1, 100000), 1, gp2pkh(grp2, u2, 10000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // mint and create child, without auth
            t = tx1x2(mintctrl1, gp2pkh(grp1, u1, 100000), 1,
                gp2pkh(grp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // 2 input auths combine into 1 output utxo with both auths
            t = tx2x1(rescriptChildAuth1, mintChildAuth1,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT |
                             GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // Same but rescript is not subgroupable
            t = tx2x1(rescriptChildAuth1, mintChildAuth1sg,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT |
                             GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);
            t = tx2x1(rescriptChildAuth1, mintChildAuth1sg,
                gp2pkh(subgrp1a, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT |
                             GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(rescriptChildAuth1sg, mintChildAuth1sg,
                gp2pkh(subgrp1b, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT |
                             GroupAuthorityFlags::RESCRIPT | GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // 1 input has child auth, one does not, but output tries to claim both functions
            t = tx2x1(meltctrl1, mintChildAuth1,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT |
                             GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
            t = tx2x1(meltctrl1, mintChildAuth1,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // 2 input auths combine, but wrong output auth bits
            t = tx2x1(rescriptChildAuth1, mintChildAuth1,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::MELT |
                             GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);

            // mint and create child, with auth
            t = tx1x2(mintChildAuth1, gp2pkh(grp1, u1, 100000), 1,
                gp2pkh(grp1, u1, toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // mint and create child, with auth
            t = tx1x2(mintChildAuth1, gp2pkh(grp1, u1, 100000), 1,
                gp2pkh(grp1, u1,
                    toAmount(GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT | GroupAuthorityFlags::BATON)),
                1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);

            // double mint
            t = tx2x2(mintctrl1, mintctrl2, gp2pkh(grp1, u1, 100000), 1, gp2pkh(grp2, u2, 10000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(ok);


            // double mint 1 wrong group
            t = tx2x2(mintctrl1, mintctrl2, gp2pkh(grp1, u1, 100000), 1, gp2pkh(grp3, u2, 10000), 1);
            ok = CheckGroupTokens(t, state, coins);
            BOOST_CHECK(!ok);
        }

        // check same group 1 input 1 output
        CTransaction t = tx1x1(gutxo, gp2pkh(grp1, u1, 100), 1);
        bool ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // check same group 1 input 1 output, wrong value
        t = tx1x1(gutxo, gp2pkh(grp1, u1, 10), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);
        t = tx1x1(gutxo, gp2pkh(grp1, u1, 1000), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check different groups 1 input 1 output
        t = tx1x1(gutxo, gp2pkh(grp2, u1, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check mint, incorrect input group address
        t = tx1x1(putxo, gp2pkh(grp2, u1, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt but no authority
        t = tx1x1(gutxo, p2pkh(u2), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt with authority
        t = tx2x1(gutxo, meltctrl1, p2pkh(u1), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // check melt with wrong authority
        t = tx2x1(gutxo, mintctrl1, p2pkh(u1), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check melt with wrong group authority
        t = tx2x1(gutxo, meltctrl2, p2pkh(u1), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // check burnable utxo but not burning
        t = tx1x1(gutxo_burnable, gp2pkh(grp1, u1, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // Test multiple input/output transactions

        // send 1 coin and melt 100 tokens (with 1 satoshi) into output
        t = tx3x1(putxo, gutxo, meltctrl1, p2pkh(u2), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // this sends 2 satoshi into the fee so it works and melts tokens
        t = tx2x1(gutxo, meltctrl1, p2pkh(u2), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // send 1 coins and melt tokens, but incorrect amount
        // this will work because CheckGroupTokens does not enforce wallet balances
        t = tx3x1(putxo, meltctrl1, gutxo, p2pkh(u2), 300);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // partial melt
        t = tx2x2(gutxo, meltctrl1, gp2pkh(grp1, u1, 10), 1, gp2pkh(grp1, u1, 50), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // Exceed input without mint, but in separate outputs with melt authority so if outputs
        // are not combined correctly it would work.
        t = tx2x2(gutxo, meltctrl1, gp2pkh(grp1, u1, 60), 1, gp2pkh(grp1, u1, 50), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // atomic swap tokens
        COutPoint gutxo2 = AddUtxo(gp2pkh(grp2, u2, 100), 1, coins);

        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2, 100), 1, gp2pkh(grp2, u1, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // wrong amounts
        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2, 101), 1, gp2pkh(grp2, u1, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);
        t = tx2x2(gutxo, gutxo2, gp2pkh(grp1, u2, 100), 1, gp2pkh(grp2, u1, 99), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // group transaction with 50 sat fee
        COutPoint p100utxo = AddUtxo(p2pkh(u1), 100, coins);

        t = tx2x2(p100utxo, gutxo, p2pkh(u1), 50, gp2pkh(grp1, u2, 100), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(ok);

        // group transaction with group imbalance
        t = tx2x2(p100utxo, gutxo, p2pkh(u1), 50, gp2pkh(grp1, u2, 101), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);
        // group transaction with group imbalance
        t = tx2x2(p100utxo, gutxo, p2pkh(u1), 50, gp2pkh(grp1, u2, 99), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // Check overflow/underflow errors

        // Check overflow into negative number (2 inputs would sum to a negative)
        COutPoint gutxo3 = AddUtxo(gp2pkh(grp1, u1, std::numeric_limits<CAmount>::max() - 50), 1, coins);
        CAmount amt = std::numeric_limits<CAmount>::max();
        amt += 50;
        t = tx2x1(gutxo3, gutxo, breakable_p2pkt(grp1, u1, amt), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);
        // Check direct negative number in utxo
        t = tx2x1(gutxo3, gutxo, breakable_p2pkt(grp1, u1, -300), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // include enough valid utxos to overflow into a valid summed output that equals the input
        t = tx1x3(gutxo, gp2pkh(grp1, u1, std::numeric_limits<CAmount>::max()), 1,
            gp2pkh(grp1, u1, std::numeric_limits<CAmount>::max()), 1, gp2pkh(grp1, u1, 102), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);

        // Add enough positive inputs to overflow into a valid positive number
        COutPoint gutxo4 = AddUtxo(gp2pkh(grp1, u1, std::numeric_limits<CAmount>::max()), 1, coins);
        COutPoint gutxo5 = AddUtxo(gp2pkh(grp1, u1, std::numeric_limits<CAmount>::max()), 1, coins);
        COutPoint gutxo6 = AddUtxo(gp2pkh(grp1, u1, 3), 1, coins);
        // max*2 overflows into negative number + 3 -> 1
        t = tx3x1(gutxo4, gutxo5, gutxo6, gp2pkh(grp1, u1, 1), 1);
        ok = CheckGroupTokens(t, state, coins);
        BOOST_CHECK(!ok);
    }
}

BOOST_AUTO_TEST_CASE(grouptoken_basicfunctions)
{
    basicFunctionsTest(STANDARD_SCRIPT_VERIFY_FLAGS);
    basicFunctionsTest(POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS);
}
#endif


static bool tryBlock(const std::vector<CMutableTransaction> &txns,
    const CScript &scriptPubKey,
    CBlockRef &result,
    CValidationState &state)
{
    const CChainParams &chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlockRef pblock = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    pblock->vtx.resize(1);
    // If XValidation is true, we assume that the transactions have already been validated, defeating the purpose of
    // this test.
    pblock->fXVal = false;
    for (const CMutableTransaction &tx : txns)
        pblock->vtx.push_back(MakeTransactionRef(tx));
    // enfore LTOR ordering of transactions
    std::sort(pblock->vtx.begin() + 1, pblock->vtx.end(), NumericallyLessTxHashComparator());
    pblock->UpdateHeader(); // make sure the size field is properly calculated
    pblock->nonce.resize(7); // Try weird sizes
    bool worked = MineBlock(*pblock, 1UL << (7 * 8), chainparams.GetConsensus());
    assert(worked);

    bool ret;
    ret = ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL, false);
    result = pblock;
    return ret;
}

static bool tryMempool(const CTransaction &tx, CValidationState &state)
{
    bool inputsMissing = false;
    return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), true, &inputsMissing, false);
}

#ifdef ENABLE_WALLET
BOOST_FIXTURE_TEST_CASE(grouptoken_blockchain, TestChain100Setup)
{
    // fPrintToConsole = true;
    // LogToggleCategory(Logging::ALL, true);
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    std::vector<CMutableTransaction> txns;

    QuickAddress p2pkGrp(coinbaseKey);
    QuickAddress grp0(4);
    QuickAddress grp0AllAuth(5);
    QuickAddress grp1AllAuth(6);
    QuickAddress grp1(1);
    QuickAddress a1(2);
    QuickAddress a2(3);

    CValidationState state;
    CBlockRef blk1;
    CBlockRef tipblk;
    CBlockRef badblk; // If I'm expecting a failure, I stick the block in badblk so that I still have the chain tip

    // just regress making a block
    bool ret = tryBlock(txns, p2pkh(grp1), blk1, state);
    BOOST_CHECK(ret);
    if (!ret)
        return; // no subsequent test will work

    txns.push_back(CMutableTransaction()); // Make space for 1 tx in the vector

    {
        // Should fail: bad group size
        uint256 hash = blk1->vtx[0]->GetIdem();
        std::vector<unsigned char> fakeGrp(21);
        CScript script = breakable_ScriptTemplateOutput(cp2pkHash, ArgsHash(a1), VchType(), fakeGrp, 1);
        txns[0] = tx1x1(COutPoint(hash, 0), script, blk1->vtx[0]->vout[0].nValue);
        ret = tryBlock(txns, p2pkh(a2), badblk, state);
        BOOST_CHECK(!ret);
    }

    // Create group
    uint64_t nonce = 0;
    CGroupTokenID gid = findGroupId(COutPoint(coinbaseTxns[0].GetIdem(), 0), CScript(), GroupTokenIdFlags::NONE,
        GroupAuthorityFlags::ACTIVE_FLAG_BITS, nonce);
    txns[0] = tx1x1(COutPoint(coinbaseTxns[0].GetIdem(), 0), gp2pkh(gid, grp0AllAuth, nonce),
        coinbaseTxns[0].vout[0].nValue, coinbaseKey, coinbaseTxns[0].vout[0].scriptPubKey, false);
    ret = tryBlock(txns, p2pkh(a2), tipblk, state);
    if (!ret)
        printf("state: %d:%s, %s\n", state.GetRejectCode(), state.GetRejectReason().c_str(),
            state.GetDebugMessage().c_str());
    BOOST_CHECK(ret);


    // Mint tokens
    txns[0] = tx({InputData(coinbaseTxns[1], 0, coinbaseKey), InputData(*tipblk->vtx[1], 0, grp0AllAuth.secret)},
        {OutputData(gp2pkh(gid, grp0AllAuth, authorityFlags(GroupAuthorityFlags::ACTIVE_FLAG_BITS, nonce)), 10000),
            OutputData(gp2pkh(gid, a1, 1000), coinbaseTxns[1].vout[0].nValue - 10000)});
    ret = tryBlock(txns, p2pkh(a2), tipblk, state);
    CAmount grpInpAmt = coinbaseTxns[1].vout[0].nValue - 10000;
    CAmount grpInpTokAmt = 1000;
    CTransaction grpTx = txns[0];
    InputData grpInp(grpTx, 1, a1.secret);
    InputData grpAuth(grpTx, 0, grp0AllAuth.secret);
    BOOST_CHECK(ret);


    // Mint tokens without auth
    txns[0] = tx({InputData(coinbaseTxns[2], 0, coinbaseKey)},
        {OutputData(gp2pkh(gid, a1, 1000), coinbaseTxns[2].vout[0].nValue - 10000)});
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);

    // Useful printouts:
    // Note state response is broken due to state = CValidationState(); in main.cpp:ActivateBestChainStep
    // printf("state: %d:%s, %s\n", state.GetRejectCode(), state.GetRejectReason().c_str(),
    // state.GetDebugMessage().c_str())
    // printf("%s\n", CTransaction(txns[0]).ToString().c_str());
    // printf("%s\n", HexStr(txns[0]).c_str());
    // printf("state: %d:%s, %s\n", state.GetRejectCode(), state.GetRejectReason().c_str(),
    // state.GetDebugMessage().c_str());

    // Create another group, use different grp as 0 input tx (shouldn't matter)
    nonce = 0xfffffffffff00000ULL; // start anywhere
    CGroupTokenID gid1 = findGroupId(COutPoint(coinbaseTxns[3].GetIdem(), 0), CScript(), GroupTokenIdFlags::NONE,
        GroupAuthorityFlags::ACTIVE_FLAG_BITS, nonce);
    txns[0] = tx({InputData(coinbaseTxns[3], 0, coinbaseKey)},
        {OutputData(gp2pkh(gid1, grp1AllAuth, authorityFlags(GroupAuthorityFlags::ACTIVE_FLAG_BITS, nonce)), 1),
            OutputData(p2pkh(a2), coinbaseTxns[3].vout[0].nValue - 1)});
    ret = tryBlock(txns, p2pkh(a2), tipblk, state);
    BOOST_CHECK(ret);

    // Should fail: pay from group to non-groups
    txns[0] = tx({grpInp}, {OutputData(p2pkh(a2), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid, a2, grpInpTokAmt - 1), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid, a2, grpInpTokAmt + 1), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the correct group, wrong group qty
    txns[0] = tx({grpInp}, {
                               OutputData(gp2pkh(gid, a2, grpInpTokAmt - 1), grpInpAmt - 100),
                               OutputData(gp2pkh(gid, a1, 2), 10),
                           });
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);

    // now try the same but to the wrong group, correct qty
    txns[0] = tx({grpInp}, {OutputData(gp2pkh(gid1, a2, grpInpTokAmt), grpInpAmt - 10000)});
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(!ret);
    ret = tryBlock(txns, p2pkh(a2), badblk, state);
    BOOST_CHECK(!ret);


    // now correct group spend in various ways
    txns[0] = tx({grpInp}, {
                               OutputData(gp2pkh(gid, a2, grpInpTokAmt / 2), grpInpAmt - 100),
                               OutputData(gp2pkh(gid, a1, grpInpTokAmt / 2), 10),
                           });
    ret = tryMempool(txns[0], state);
    BOOST_CHECK(ret);

    InputDataCopy toks(txns[0], 0, a2.secret);
    ret = tryBlock(txns, p2pkh(a2), tipblk, state);
    BOOST_CHECK(ret);


    // To make sure blocks get accepted or rejected without the block's tx in the mempool, I
    // won't use the mempool for the rest of this test.

    // Melt (and lose the authority)
    txns[0] = tx({grpAuth, toks}, {OutputData(gp2pkh(gid, a1, 1), 2)});
    ret = tryBlock(txns, p2pkh(a2), tipblk, state);
    BOOST_CHECK(ret);


    // make a tokeninfo request
    CAddress addr1(ipaddress(0xa0b0c001, 10000));
    CDataStream vRecv1(SER_NETWORK, PROTOCOL_VERSION);

    vRecv1.clear();
    std::vector<CExtInv> vExtInv;

    CExtInv extinv(MSG_TOKENINFO, gid.bytes());
    vExtInv.push_back(extinv);

    CNode dummyNode1(INVALID_SOCKET, addr1, "", true);
    SetConnected(dummyNode1);
    vRecv1 << vExtInv;
    ProcessMessage(&dummyNode1, NetMsgType::EXTGETDATA, 0, vRecv1, GetStopwatchMicros());
    BOOST_CHECK_EQUAL(dummyNode1.vLowPrioritySendMsg.size(), 1);
}

BOOST_AUTO_TEST_CASE(grouptoken_descriptions)
{
    // Test that all labels can be encoded in OP_RETURN and retrieved successfully.
    std::string ticker = "NEXT";
    std::string name = "NexaToken";
    std::string url = "http://nexa.org";
    std::string urlZipFileHex = "e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436";
    std::string decimals = "4";

    UniValue params(UniValue::VARR);
    params.push_back(ticker);
    params.push_back(name);
    params.push_back(url);
    params.push_back(urlZipFileHex);
    params.push_back(decimals);
    unsigned int curparam = 0;
    auto desc = ParseGroupDescParams(params, curparam);

    CScript opretScript;
    opretScript = BuildTokenDescScript(desc);

    std::vector<std::string> vLabels;
    GetTokenDescription(opretScript, vLabels);
    BOOST_CHECK_EQUAL(ticker, vLabels[0]);
    BOOST_CHECK_EQUAL(name, vLabels[1]);
    BOOST_CHECK_EQUAL(url, vLabels[2]);
    BOOST_CHECK_EQUAL(urlZipFileHex, vLabels[3]);
    BOOST_CHECK_EQUAL(decimals, vLabels[4]);

    // Test that OP_RETURN must have 88888888 as group id or it will return empty labels
    // see https: github.com/bitcoincashorg/bitcoincash.org/blob/master/etc/protocols.csv
    uint32_t OpRetGroupId = 99999999;

    CScript ret1;
    ret1 << OP_RETURN << OpRetGroupId;
    for (auto &d : desc)
    {
        ret1 << d;
    }
    GetTokenDescription(ret1, vLabels);
    BOOST_CHECK(vLabels.empty());

    // Test that OP_RETURN must be present in the script
    OpRetGroupId = 88888888;

    CScript ret2;
    ret2 << OP_NOP << OpRetGroupId;
    for (auto &d : desc)
    {
        ret2 << d;
    }
    GetTokenDescription(ret2, vLabels);
    BOOST_CHECK(vLabels.empty());

    // Test that not data returns with a nulled description string
    OpRetGroupId = 88888888;

    CScript ret3;
    ret3 << OP_RETURN << OpRetGroupId;
    GetTokenDescription(ret3, vLabels);
    BOOST_CHECK_EQUAL(vLabels[0], "");
    BOOST_CHECK_EQUAL(vLabels[1], "");
    BOOST_CHECK_EQUAL(vLabels[2], "");
    BOOST_CHECK_EQUAL(vLabels[3], "");
    BOOST_CHECK_EQUAL(vLabels[4], "0");

    // Test that not data returns with only a partial description string
    OpRetGroupId = 88888888;
    std::vector<std::vector<unsigned char> > desc2;
    std::string label("AAA");
    desc2.push_back(std::vector<unsigned char>(label.begin(), label.end()));

    CScript ret4;
    ret4 << OP_RETURN << OpRetGroupId;
    for (auto &d : desc2)
    {
        ret4 << d;
    }

    GetTokenDescription(ret4, vLabels);
    BOOST_CHECK_EQUAL(vLabels.size(), 5);

    BOOST_CHECK_EQUAL(vLabels[0], "AAA");
    BOOST_CHECK_EQUAL(vLabels[1], "");
    BOOST_CHECK_EQUAL(vLabels[2], "");
    BOOST_CHECK_EQUAL(vLabels[3], "");
    BOOST_CHECK_EQUAL(vLabels[4], "0");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
