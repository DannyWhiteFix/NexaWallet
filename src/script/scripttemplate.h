// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCRIPT_TEMPLATE_H
#define SCRIPT_TEMPLATE_H

#include "consensus/grouptokens.h"
#include <vector>

/** Get the script's template hash if this script is a template.  If the template hash is a "well-known" number, it is
    returned as that number (not converted to a hash, but the number in vector form).  Use
    ConvertWellKnownTemplateHash() to convert well-known templates value to a hash, and get the actual script it refers
    to.  Pass nullptr for any output parameters that you are not interested in.
    @param[in] script The "script" (the output of a transaction) containing all the info.
    @param[out] groupInfo Group token information
    @param[out] templateHash Hash of the script template
    @param[out] argsHash Hash of the template arguments
    @param[out] pcout  Iterator pointing to the next unused bytes in the script (these are unblinded arguments).

    @return error Whether the script is a template, is not a template, or is an invalid template.
 */
ScriptTemplateError GetScriptTemplate(const CScript &script,
    CGroupTokenInfo *groupInfo,
    std::vector<unsigned char> *templateHash,
    std::vector<unsigned char> *argsHash = nullptr,
    CScript::const_iterator *pcout = nullptr);

/** Convert well-known templates value to a hash, and get the actual script it refers to.
    The templateHash argument MUST be within the correct size range for well-known templates (1 or 2 bytes), unless
    ignored due to an numeric opcode.
    @param[in/out] templateHash  Pass in the well-known ID, get the actual hash out.
    @param[in/out] templateScript The actual script

    @return error SCRIPT_ERR_OK if this is a valid well-known template, otherwise SCRIPT_ERR_TEMPLATE.
 */
ScriptError ConvertWellKnownTemplateHash(VchType &templateHash, CScript &templateScript);

/** Parse the template hash arg into the actual script it refers to.
    This function checks input validity and then calls ConvertWellKnownTemplateHash for well known templates
    @param[in/out] templateHash  Pass in the well-known ID, get the actual hash out.
    @param[in/out] templateScript The actual script

    @return error SCRIPT_ERR_OK if this is a valid well-known template, providing the template in templateScript,
                  or SCRIPT_ERR_OK if this is an unknown hash (and templateScript will be empty).
 */
ScriptTemplateError ParseWellKnownTemplateHashArg(VchType &templateHash, CScript &templateScript);

/** This function looks at the input script and templateHash, extracts the template script, and verifies that the
   template hash is a proper size and that the template script is the proper preimage for the hash.

   @param[in] satisfier  The satisfier script (used to extract the template script, if needed)
   @param[in/out] satisfierIter  Grab the scriptTemplate (if needed) from here.  Since scriptTemplates are the first
       item in satisfier script, this MUST be satisfier.begin().  If this function is successful, the satisfierIter
       will be moved past the script template hash (if it exists).
   @param[in/out] templateHash The templateHash is updated to an actual hash if it encodes a well-known shorthand.
   @param[in/out] templateScript The script, either extracted from the satisfier or copied from the list of well-known
       scripts.
*/
ScriptError LoadCheckTemplateHash(const CScript &satisfier,
    CScript::const_iterator &satisfierIter,
    VchType &templateHash,
    CScript &templateScript);

void NumericOpcodeToVector(opcodetype opcode, VchType &templateHash);

/** Create a "locking" CScript suitable for placement in a CTxOut that spends to a script template with args
    and group.  Its called locking because it contains all the data that locks a UTXO from being spent.
    @param[in] scriptHash  Hash160 or Hash256 of the script template
    @param[in] argsHash  Hash160 or Hash256 of the template's arguments in CScript format.
    @param[in] visibleArgs  Arguments (in CScript format) that you want to be visible in the output.
    @param[in] group  Group Identifier (if output should be grouped, otherwise use NoGroup)
    @param[in] grpQuantity  Quantity of tokens (if any).  If -1 is passed, the resulting CScript will place OP_0
    where the group quantity should be, provided that a group is specified. This is an illegal value so the script
    will not validate.  This is used to pass information around (as addresses), without needing to specify a token
    quantity.
*/
CScript ScriptTemplateLock(const VchType &scriptHash,
    const VchType &argsHash = VchType(),
    const VchType &visibleArgs = VchType(),
    const CGroupTokenID &group = NoGroup,
    CAmount grpQuantity = -1);

inline CScript ScriptTemplateOutput(const VchType &scriptHash,
    const VchType &argsHash = VchType(),
    const VchType &visibleArgs = VchType(),
    const CGroupTokenID &group = NoGroup,
    CAmount grpQuantity = -1)
{
    return ScriptTemplateLock(scriptHash, argsHash, visibleArgs, group, grpQuantity);
}


/** Create a "locking" CScript suitable for placement in a CTxOut that spends to a script template with args
    and group.  Its called locking because it contains all the data that locks a UTXO from being spent.
    @param[in] constraintScript  constraint script
    @param[in] argsScript  push script of args
    @param[in] visibleArgsScript  Arguments (in CScript format) that you want to be visible in the output.
    @param[in] group  Group Identifier (if output should be grouped, otherwise use NoGroup)
    @param[in] grpQuantity  Quantity of tokens (if any).  If -1 is passed, the resulting CScript will place OP_0
    where the group quantity should be, provided that a group is specified. This is an illegal value so the script
    will not validate.  This is used to pass information around (as addresses), without needing to specify a token
    quantity.
    @param[in] usehash256 Set LSB (bit 0) to 1 if you want the constraint script to be Hash256.  Set bit 1 to 1 for
               argsScript otherwise Hash160 (default is both Hash160)
*/
CScript ScriptTemplateLock(const CScript &constraintScript,
    const CScript &argsScript = CScript(),
    const CScript &visibleArgsScript = CScript(),
    const CGroupTokenID &group = NoGroup,
    CAmount grpQuantity = -1,
    uint8_t usehash256Bitmap = 0);

inline CScript ScriptTemplateOutput(const CScript &constraintScript,
    const CScript &argsScript = CScript(),
    const CScript &visibleArgsScript = CScript(),
    const CGroupTokenID &group = NoGroup,
    CAmount grpQuantity = -1,
    uint8_t usehash256Bitmap = 0)
{
    return ScriptTemplateLock(constraintScript, argsScript, visibleArgsScript, group, grpQuantity, usehash256Bitmap);
}

/**
    The same as ScriptTemplateLock above but pass in an existing script as the first arg rather than
    in parts (scriptHash, argsHash, and visibleArgs). The existing script template will be deconstructed
    into those parts internally before replacing the group and amount in the returned script
 */
CScript ScriptTemplateLock(const CScript &templateIn, const CGroupTokenID &group, CAmount grpQuantity = -1);

inline CScript ScriptTemplateOutput(const CScript &templateIn, const CGroupTokenID &group, CAmount grpQuantity = -1)
{
    return ScriptTemplateLock(templateIn, group, grpQuantity);
}

/**  Create an "unlocking" CScript, to be placed in the CTxIn.  Its called "unlocking" because it contains the
     data (and scripts) required to prove that you can spend (or "unlock") the UTXO.
 */
CScript ScriptTemplateUnlock(const CScript &constraintScript,
    const CScript &satisfierScript,
    const CScript &argsScript = CScript());

CScript UngroupedScriptTemplate(const CScript &templateIn);

/** Create a "locking" CScript, to be placed in a CTxOut, that uses a well known template. */
CScript ScriptWellKnownTemplateLock(const uint64_t wellKnownId,
    const VchType &argsHash,
    const VchType &visibleArgs,
    const CGroupTokenID &group,
    CAmount grpQuantity);

/** Create an "unlocking" CScript, to be placed in a CTxIn, based on a well known template. */
CScript ScriptWellKnownTemplateUnlock(uint64_t wellKnownId, const CScript &satisfierScript, const CScript &argsScript);

/** Well-known script templates */

/** p2pkt - pay-to-public key template script */
extern const CScript p2pkt;
/** p2pkt well known identifier: just a 1 byte vector containing "1" */
extern const std::vector<unsigned char> P2PKT_ID; // Push will convert this vector to OP_1

/** Create a CScript suitable for placement in a CTxOut that spends into a P2PKT */
CScript P2pktOutput(const VchType &argsHash, const CGroupTokenID &group = NoGroup, CAmount grpQuantity = 0);
/** Create a CScript suitable for placement in a CTxOut that spends into a P2PKT */
CScript P2pktOutput(const CPubKey &pubkey, const CGroupTokenID &group = NoGroup, CAmount grpQuantity = 0);
#endif
