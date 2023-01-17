// Copyright (c) 2017-2018 The Bitcoin developers
// Copyright (c) 2017-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SIG_HASH_TYPE_H
#define NEXA_SIG_HASH_TYPE_H

#include "script/interpreter.h"
#include "serialize.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/** BTCBCH Signature hash types/flags */
enum
{
    BTCBCH_SIGHASH_ALL = 1,
    BTCBCH_SIGHASH_NONE = 2,
    BTCBCH_SIGHASH_SINGLE = 3,
    BTCBCH_SIGHASH_FORKID = 0x40,
    BTCBCH_SIGHASH_ANYONECANPAY = 0x80,
};

/** Signature hash type wrapper class */
class SigHashType
{
public:
    enum class Input : uint8_t
    {
        ALL = 0,
        FIRSTN = 1,
        THISIN = 2,
        LAST_VALID = THISIN, // end indicator
    };


    enum class Output : uint8_t
    {
        ALL = 0,
        FIRSTN = 1,
        TWO = 2,
        LAST_VALID = TWO, // end indicator
    };

protected: // tests need direct access
    bool valid = false;
    Input inp = SigHashType::Input::ALL;
    Output out = SigHashType::Output::ALL;
    std::vector<uint8_t> inpData;
    std::vector<uint8_t> outData;

public:
    enum
    {
        MAX_LEN = 4 // 1 type flag, 1 input data, 2 output data is the max sighashtype size
    };

    /** The default constructor creates a sighash that is the most restrictive -- it signs all inputs and outputs */
    explicit SigHashType() : valid(true) {}

    /** Grab sighashtype out of a signature */
    explicit SigHashType(const std::vector<unsigned char> &sig) { fromSig(sig); }

    /** Extract a sighashtype from a Schnorr signature passed as a byte vector, and set this object to that type
        @return this object  */
    SigHashType &fromSig(const std::vector<unsigned char> &sig);

    /** Extract a sighashtype from some offset in a raw array and set this object to that type
        @return this object  */
    SigHashType &fromBytes(const std::vector<unsigned char> &byteArray, int start = 0);

    /** Anyone can pay signs only the current input, so other entities can add addtl inputs to complete the partial tx
     */
    SigHashType &withAnyoneCanPay()
    {
        inp = Input::THISIN;
        inpData.resize(0);
        return *this;
    }

    bool isDefined() const { return valid == true; }
    bool isInvalid() const { return valid == false; }

    SigHashType &invalidate()
    {
        setAll();
        valid = false;
        return *this;
    }

    // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
    bool hasAnyoneCanPay() const { return inp == Input::THISIN; }

    bool hasNoInputs() const
    {
        // SIGHASH_ANYPREVOUT is specified as the "first N" outputs where N==0
        if (inp == Input::FIRSTN)
        {
            assert(inpData.size() == 1);
            return (inpData[0] == 0);
        }
        return false;
    }
    bool hasNoOutputs() const
    {
        // SIGHASH_NONE is specified as the "first N" outputs where N==0
        if (out == Output::FIRSTN)
        {
            assert(outData.size() == 1);
            return (outData[0] == 0);
        }
        return false;
    }
    bool hasAll() const { return ((inp == SigHashType::Input::ALL) && (out == SigHashType::Output::ALL)); }

    // set this sighashtype to the type that generates the longest sighashtype in bytes
    // (for use in calculating tx fees by tx length estimation).
    SigHashType &dummyLongest()
    {
        setFirstNIn(1);
        set2Outs(0, 1);
        return *this;
    }

    SigHashType &setAll()
    {
        valid = true;
        inp = SigHashType::Input::ALL;
        out = SigHashType::Output::ALL;
        inpData.resize(0);
        outData.resize(0);
        return *this;
    }

    SigHashType &setFirstNIn(uint8_t n)
    {
        valid = true;
        inp = SigHashType::Input::FIRSTN;
        inpData.resize(1);
        inpData[0] = n;
        return *this;
    }

    SigHashType &setFirstNOut(uint8_t n)
    {
        valid = true;
        out = SigHashType::Output::FIRSTN;
        outData.resize(1);
        outData[0] = n;
        return *this;
    }
    SigHashType &setNoOut() { return setFirstNOut(0); }


    SigHashType &set2Outs(uint8_t a, uint8_t b)
    {
        valid = true;
        out = SigHashType::Output::TWO;
        outData.resize(2);
        outData[0] = a;
        outData[1] = b;
        return *this;
    }

    /** Append this hash type to a signature (or any other vector) so that the resulting data describes what it signed.
        Returns false only if this sighashtype is invalid.
     */
    bool appendToSig(std::vector<unsigned char> &sig) const;

    /** return this sighashtype as a hex string.  Useful for test, debugging and display */
    std::string HexStr() const;

    /** load a human-readable representation of the sighash into an object.
        if flagStr is empty, or does not define a portion of the sighash, this object is unmodified in that portion.
        If the flagStr is incorrect, this object is set to in invalid sighash  */
    SigHashType &from(const std::string &flagStr);
    /** Convert to a human readable representation of the sighash */
    std::string ToString() const;

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        std::vector<uint8_t> sigHashBytes;
        appendToSig(sigHashBytes);
        ::Serialize(s, sigHashBytes);
    }

    friend bool SignatureHashNexaComponents(const CTransaction &txTo,
        unsigned int nIn,
        const SigHashType &sigHashType,
        uint256 &hashPrevouts,
        uint256 &hashSequence,
        uint256 &hashInputAmounts,
        uint256 &hashOutputs);
};

inline SigHashType::Input &operator++(SigHashType::Input &c)
{
    c = static_cast<SigHashType::Input>(static_cast<uint8_t>(c) + 1);
    return c;
}

inline SigHashType::Output &operator++(SigHashType::Output &c)
{
    c = static_cast<SigHashType::Output>(static_cast<uint8_t>(c) + 1);
    return c;
}

/** Calculate the hash that a signature of this transaction signs.  The algorithm depends on sigHashType,
    Both in determining whether to use the Bitcoin Cash or Bitcoin algorithm, and also the specific data and
    algorithm within those two families. */
uint256 SignatureHash(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    const CAmount &amount,
    size_t *nHashedOut = nullptr);

bool SignatureHashNexa(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    uint256 &result,
    size_t *nHashedOut = nullptr);

/** Given the components of the sighash, calculate it
    (used by double spend proofs and normal signature calculation)
 */
bool SignatureHashNexa(const CScript &scriptCode,
    uint8_t txVersion,
    uint32_t txLockTime,
    const SigHashType &sigHashType,
    const uint256 &hashPrevouts,
    const uint256 &hashSequence,
    const uint256 &hashInputAmounts,
    const uint256 &hashOutputs,
    uint256 &result,
    size_t *nHashedOut);

uint256 SignatureHashBitcoin(const CScript &scriptCode,
    const SatoshiTransaction &txTo,
    unsigned int nIn,
    const uint8_t sigHashType,
    size_t *nHashedOut = nullptr);

uint256 SignatureHashBitcoinCash(const CScript &scriptCode,
    const SatoshiTransaction &txTo,
    unsigned int nIn,
    const uint8_t sigHashType,
    const CAmount &amount,
    size_t *nHashedOut = nullptr);

/** Extract the sighashtype from a signature */
SigHashType GetSigHashType(const std::vector<unsigned char> &vchSig);
/** remove the sighashtype data from a signature, in-place */
void RemoveSigHashType(std::vector<unsigned char> &vchSig);

extern const SigHashType defaultSigHashType;

#endif // NEXA_SCRIPT_HASH_TYPE_H
