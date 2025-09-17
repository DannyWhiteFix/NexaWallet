// Copyright (c) 2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_COPYRIGHT_H
#define NEXA_COPYRIGHT_H

#include "utilstrencodings.h"
#include "utiltranslate.h"

std::string LicenseInfo()
{
    return FormatParagraph(strprintf(_("Copyright (C) 2015-%i The Bitcoin Unlimited Developers"), COPYRIGHT_YEAR)) +
           "\n\n" +
           FormatParagraph(strprintf(_("Portions Copyright (C) 2009-%i The Bitcoin Core Developers"), COPYRIGHT_YEAR)) +
           "\n\n" +
           FormatParagraph(strprintf(_("Portions Copyright (C) 2014-%i The Bitcoin XT Developers"), COPYRIGHT_YEAR)) +
           "\n\n" + "\n" + FormatParagraph(_("This is experimental software.")) + "\n" + "\n" +
           FormatParagraph(_("Distributed under the MIT software license, see the accompanying file COPYING or "
                             "<http://www.opensource.org/licenses/mit-license.php>.")) +
           "\n";
}

#endif
