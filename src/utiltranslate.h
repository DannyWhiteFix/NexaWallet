// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_UTILTRANSLATE_H
#define NEXA_UTILTRANSLATE_H

#include <string>

#ifndef LIGHT
#include <boost/signals2/signal.hpp>

/** Signals for translation. */
class CTranslationInterface
{
public:
    /** Translate a message to the native language of the user. */
    boost::signals2::signal<std::string(const char *psz)> Translate;
};
extern CTranslationInterface translationInterface;

/**
 * Translation function: Call Translate signal on UI interface, which returns a boost::optional result.
 * If no translation slot is registered, nothing is returned, and simply return the input.
 */
inline std::string _(const char *psz)
{
    boost::optional<std::string> rv = translationInterface.Translate(psz);
    return rv ? (*rv) : psz;
}

#else // ifdef LIGHT

class CTranslationInterface
{
public:
    std::string Translate(const char *psz);
};
extern CTranslationInterface translationInterface;

inline std::string _(const char *psz)
{
    std::string rv = translationInterface.Translate(psz);
    if (rv.empty())
    {
        return std::string(psz);
    }
    return rv;
}
#endif

#endif // NEXA_UTILTRANSLATE_H
