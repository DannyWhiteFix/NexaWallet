#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/scripttemplate.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "test/test_nexa.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <stdint.h>
#include <string>
#include <univalue.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(scripttemplate_tests, BasicTestingSetup)

class QuickAddress
{
public:
    QuickAddress()
    {
        secret.MakeNewKey(true);
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(addr);
    }
    QuickAddress(const CKey &k)
    {
        secret = k;
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(addr);
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
        addr = pubkey.GetID();
        eAddr = pubkey.GetHash();
        grp = CGroupTokenID(addr);
    }

    CKey secret;
    CPubKey pubkey;
    CKeyID addr; // 160 bit normal address
    uint256 eAddr; // 256 bit extended address
    CGroupTokenID grp;
};

class AlwaysGoodSignatureChecker : public BaseSignatureChecker
{
public:
    mutable int numVerifyCalls = 0;
    mutable int numCheckSigCalls = 0;
    mutable std::vector<unsigned char> lastPubKey;
    mutable std::vector<unsigned char> lastSig;
    AlwaysGoodSignatureChecker(unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID) { nFlags = flags; }

    //! Verifies a signature given the pubkey, signature and sighash
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig,
        const CPubKey &vchPubKey,
        const uint256 &sighash) const
    {
        numVerifyCalls++;
        if (vchSig.size() > 0)
            return true;
        return false;
    }

    //! Verifies a signature given the pubkey, signature, script, and transaction (member var)
    virtual bool CheckSig(const std::vector<unsigned char> &scriptSig,
        const std::vector<unsigned char> &vchPubKey,
        const CScript &scriptCode) const
    {
        numCheckSigCalls++;
        lastPubKey = vchPubKey;
        lastSig = scriptSig;
        if (scriptSig.size() > 0)
            return true;
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const { return true; }
    virtual bool CheckSequence(const CScriptNum &nSequence) const { return true; }
    virtual ~AlwaysGoodSignatureChecker() {}
};

static uint256 hash256(const CScript &script) { return Hash(script.begin(), script.end()); }

std::vector<unsigned char> vch(const CScript &script) { return ToByteVector(script); }

BOOST_AUTO_TEST_CASE(verifywellknown)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptError error;
    auto nogroup = OP_0;
    bool ret;

    // Try p2pkt
    {
        AlwaysGoodSignatureChecker ck(flags);
        ScriptImportedState sis(&ck);
        ScriptMachineResourceTracker tracker;

        // we are using AlwaysGoodSignatureChecker so this sig doesnt have to be right, but must pass basic size check
        VchType fakeSig(64);
        defaultSigHashType.appendToSig(fakeSig);
        QuickAddress fakeAddr;
        CScript hashedArgs = CScript() << ToByteVector(fakeAddr.pubkey);
        CScript satisfier = CScript() << fakeSig;

        CScript txin = (CScript() << vch(hashedArgs)) + satisfier;
        CScript txout = (CScript(ScriptType::TEMPLATE) << nogroup << P2PKT_ID << hash256(hashedArgs));
        ret = VerifyScript(txin, txout, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // make sure that the expect script ran by checking the number of sigchecks it should have done,
        // and that the sig and pubkey are correct.
        BOOST_CHECK(ck.numCheckSigCalls == 1);
        BOOST_CHECK(ck.lastSig == fakeSig);
        BOOST_CHECK(ck.lastPubKey == fakeAddr.pubkey);

        // Incorrect txin script (contains preimage, even though well-known)
        // Since the preimage is well-known the param is ignored, throwing off all the params (so vch(p2pkt) will
        // be seen as the hash of the args causing a failure
        CScript txin2 = (CScript() << vch(p2pkt) << vch(hashedArgs)) + satisfier;
        ret = VerifyScript(txin2, txout, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }
}

BOOST_AUTO_TEST_CASE(verifytemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;

    auto nogroup = OP_0;
    bool ret;

    {
        CScript templat = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY;
        CScript templat2 = CScript() << OP_FROMALTSTACK << OP_ADD;
        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        CScript badSatisfier = CScript() << OP_9;
        CScript badConstraint = CScript() << OP_10;

        ret = VerifyTemplate(templat, constraint, satisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
        ret = VerifyTemplate(templat, constraint, badSatisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyTemplate(templat, badConstraint, satisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        // Now wrap these scripts into scriptSig and scriptPubKeys

        // No args commitment
        CScript tmplVisArgs = (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << OP_0) + constraint;
        // Args commitment
        CScript tmplCmtArgs = CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(constraint);

        CScript scriptSigVisArgs = (CScript() << vch(templat)) + satisfier;
        CScript scriptSigCmtArgs = (CScript() << vch(templat) << vch(constraint)) + satisfier;

        CScript badScriptSigTemplate = (CScript() << vch(templat2)) + satisfier;

        CScript badScriptPubKey = (CScript() << hash256(templat)) + badConstraint;
        CScript badScriptSig = (CScript() << vch(templat)) + badSatisfier;

        ret = VerifyScript(scriptSigVisArgs, tmplVisArgs, flags, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
        ret = VerifyScript(scriptSigCmtArgs, tmplCmtArgs, flags, sis, &error, &tracker);
        BOOST_CHECK(ret == true);

        ret = VerifyScript(badScriptSig, tmplVisArgs, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyScript(badScriptSigTemplate, tmplVisArgs, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    {
        // 2 hashed args, 1 public
        // Add 3 numbers from the alt stack (constraint) and compare to the top of the main stack (satisfier)
        CScript templat = CScript() << OP_FROMALTSTACK << OP_FROMALTSTACK << OP_ADD << OP_FROMALTSTACK << OP_ADD
                                    << OP_EQUALVERIFY;
        CScript satisfier = CScript() << OP_10;
        CScript hashedArgs = CScript() << OP_2 << OP_4;
        CScript visArgs = CScript() << OP_4;

        CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + satisfier;
        CScript txout = (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
        ret = VerifyScript(txin, txout, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // random incorrect txin script (doesn't contain the preimages)
        ret = VerifyScript(satisfier, txout, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }
}

BOOST_AUTO_TEST_CASE(largetemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;

    bool ret;

    // This script is bigger than allowed without script templates
    {
        CScript bigT = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY;
        VchType blah(100);
        for (unsigned int i = 0; i < blah.size(); i++)
            blah[i] = i;
        CScript data = CScript() << blah << OP_DROP;
        for (unsigned int i = 0; i < 500; i++)
        {
            bigT += data;
        }

        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        ret = VerifyTemplate(bigT, constraint, satisfier, flags, maxScriptTemplateOps, 0, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
    }

    // Trigger max ops right near the real max
    {
        CScript bigT = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY << OP_1;
        VchType blah(100);
        for (unsigned int i = 0; i < blah.size(); i++)
            blah[i] = i;
        CScript data = CScript() << OP_1 << OP_ADD; // Just keep incrementing
        for (unsigned int i = 0; i < maxScriptTemplateOps - 10; i++)
        {
            bigT += data;
        }

        bigT += CScript() << OP_DROP;
        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        // Got to make it a little smaller to not exceed script size first
        ret = VerifyTemplate(bigT, constraint, satisfier, flags, maxScriptTemplateOps - 400, 0, sis, &error, &tracker);
        BOOST_CHECK(ret != true);
        BOOST_CHECK(error == SCRIPT_ERR_OP_COUNT);

        ret = VerifyTemplate(bigT, constraint, satisfier, flags, maxScriptTemplateOps, 0, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
    }

    // Trigger max size right near the real max
    {
        CScript bigT = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY << OP_1;
        VchType blah(100);
        for (unsigned int i = 0; i < blah.size(); i++)
            blah[i] = i;
        CScript data = CScript() << OP_1 << OP_ADD; // Just keep incrementing

        // This will create a script of the EXACT max size, so will overflow because
        // bigT already has a bit of code in it.
        for (unsigned int i = 0; i < MAX_SCRIPT_TEMPLATE_SIZE / 2; i++)
        {
            bigT += data;
        }

        bigT += CScript() << OP_DROP;
        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        // Got to make it a little smaller to not exceed script size first
        ret = VerifyTemplate(bigT, constraint, satisfier, flags, maxScriptTemplateOps, 0, sis, &error, &tracker);
        BOOST_CHECK(ret != true);
        BOOST_CHECK(error == SCRIPT_ERR_SCRIPT_SIZE);
    }
}


// show how the holder "injects" script constraints into a template via opexec and scripts-as-args
BOOST_AUTO_TEST_CASE(opexectemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    auto nogroup = OP_0;
    bool ret;

    {
        // template compares 2 numbers (from constraint and satisfier) and if equal,
        // execute another rule provided by the constraint, which is that the satisfier pushed 8 on the stack

        CScript templat = CScript() << OP_FROMALTSTACK << OP_EQUALVERIFY << OP_FROMALTSTACK << OP_SWAP << OP_1 << OP_0
                                    << OP_EXEC;
        CScript satisfier = CScript() << OP_8 << OP_2;
        CScript incorrectSatisfier = CScript() << OP_7 << OP_2;
        CScript scriptArg = CScript() << OP_8 << OP_EQUALVERIFY;
        CScript hashedArgs = CScript() << vch(scriptArg) << OP_2;
        CScript visArgs = CScript();

        {
            CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + satisfier;
            CScript txout =
                (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
            ret = VerifyScript(txin, txout, flags, sis, &error, &tracker);
            BOOST_CHECK(ret);
        }

        // Tests that a VERIFY operation inside an op_exec-ed constraint script arg fails the entire script
        {
            CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + incorrectSatisfier;
            CScript txout =
                (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
            ret = VerifyScript(satisfier, txout, flags, sis, &error, &tracker);
            BOOST_CHECK(!ret);
        }
    }
}

BOOST_AUTO_TEST_CASE(opexec)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    bool ret;

    {
        CScript execed = CScript() << OP_ADD;
        CScript scriptSig = CScript() << vch(execed) << OP_4 << OP_6;
        CScript scriptPubKey = CScript() << OP_2 << OP_1 << OP_EXEC << OP_10 << OP_EQUAL;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);

        ret = VerifyScript(CScript() << vch(execed) << OP_5 << OP_6, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << vch(execed) << OP_5, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << vch(execed), scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript(), scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << OP_FALSE << OP_5 << OP_5, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyScript(CScript() << vch(CScript() << OP_CHECKSIGVERIFY) << OP_5 << OP_5, scriptPubKey, flags, sis,
            &error, &tracker);
        BOOST_CHECK(!ret);
    }

    // Verify op_exec.md:T.o2 (empty script is valid)
    {
        CScript execed = CScript();
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKey = CScript() << OP_0 << OP_0 << OP_EXEC << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);
    }

    // Verify op_exec.md:T.L4
    {
        // This script simply pushes the parameters needed for the next op_exec so that the constraint script
        // can be 20 OP_EXEC in a row.
        CScript execed = CScript() << OP_DUP << OP_1 << OP_4;
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKeyOk = CScript() << OP_DUP << OP_1 << OP_4 << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        CScript scriptPubKeyNok = CScript()
                                  << OP_DUP << OP_1 << OP_4 << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKeyOk, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);

        ret = VerifyScript(scriptSig, scriptPubKeyNok, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_COUNT_EXCEEDED);
    }


    {
        CScript execed = CScript() << OP_1;
        CScript execedFalse = CScript() << OP_0;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC;
        CScript scriptPubKeyF = CScript() << vch(execedFalse) << OP_0 << OP_1 << OP_EXEC;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // execed script returns OP_O so script should fail because that false is left on the stack
        ret = VerifyScript(scriptSig, scriptPubKeyF, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    {
        CScript execed = CScript();
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_0 << OP_EXEC << OP_TRUE;
        CScript scriptPubKeyRet1 = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC << OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);

        // Expecting more returned data than the subscript provides
        ret = VerifyScript(scriptSig, scriptPubKeyRet1, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    {
        CScript execed = CScript() << OP_DUP << OP_0 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_0 << OP_0 << OP_EXEC;

        // script was expecting 1 param
        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    {
        CScript execed = CScript() << OP_DUP << OP_1 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_1 << OP_0 << OP_EXEC;

        // test that a recursive script fails
        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);
    }

    {
        // This script recursively calls itself the number of times passed as a parameter, and ends by pushing true to
        // the stack.
        CScript execed = CScript() << OP_DUP << OP_IF << OP_1 << OP_SUB << OP_SWAP << OP_TUCK << OP_2 << OP_1 << OP_EXEC
                                   << OP_ELSE << OP_1 << OP_ENDIF;
        CScript scriptSig = CScript();
        CScript scriptPubKey2 = CScript() << vch(execed) << OP_DUP << OP_2 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;
        CScript scriptPubKey3 = CScript() << vch(execed) << OP_DUP << OP_3 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;

        // test that the max recursion depth succeeds
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // test that 1+max recursion depth fails
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey3, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);

        // test that max operations can be exceeded
        uint64_t tmp = maxSatoScriptOps;
        maxSatoScriptOps = 25;
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_OP_COUNT);
        maxSatoScriptOps = tmp;
    }
}

BOOST_AUTO_TEST_SUITE_END()
