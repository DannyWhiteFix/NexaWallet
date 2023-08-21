// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_DATASTREAM_H
#define NEXA_DATASTREAM_H

#include "serialize.h"
#include "support/allocators/zeroafterfree.h"

#include <string>
#include <vector>

/**
 * Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */
class CDataStream
{
protected:
    typedef CSerializeData vector_type;
    vector_type vch;
    unsigned int nReadPos;

    int nType;
    int nVersion;

public:
    typedef vector_type::allocator_type allocator_type;
    typedef vector_type::size_type size_type;
    typedef vector_type::difference_type difference_type;
    typedef vector_type::reference reference;
    typedef vector_type::const_reference const_reference;
    typedef vector_type::value_type value_type;
    typedef vector_type::iterator iterator;
    typedef vector_type::const_iterator const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit CDataStream(int nTypeIn, int nVersionIn) { Init(nTypeIn, nVersionIn); }
    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn, int nVersionIn) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const char *pbegin, const char *pend, int nTypeIn, int nVersionIn) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const vector_type &vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<char> &vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<unsigned char> &vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args &&...args)
    {
        Init(nTypeIn, nVersionIn);
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void Init(int nTypeIn, int nVersionIn)
    {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;
    }

    CDataStream &operator+=(const CDataStream &b)
    {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CDataStream operator+(const CDataStream &a, const CDataStream &b)
    {
        CDataStream ret = a;
        ret += b;
        return (ret);
    }

    std::string str() const { return (std::string(begin(), end())); }
    //
    // Vector subset
    //
    const_iterator begin() const { return vch.begin() + nReadPos; }
    iterator begin() { return vch.begin() + nReadPos; }
    const_iterator end() const { return vch.end(); }
    iterator end() { return vch.end(); }
    size_type size() const { return vch.size() - nReadPos; }
    bool empty() const { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c = 0) { vch.resize(n + nReadPos, c); }
    void reserve(size_type n) { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const { return vch[pos + nReadPos]; }
    reference operator[](size_type pos) { return vch[pos + nReadPos]; }
    void clear()
    {
        vch.clear();
        nReadPos = 0;
    }
    iterator insert(iterator it, const char &x = char()) { return vch.insert(it, x); }
    void insert(iterator it, size_type n, const char &x) { vch.insert(it, n, x); }
    value_type *data() { return vch.data() + nReadPos; }
    const value_type *data() const { return vch.data() + nReadPos; }
    void insert(iterator it, std::vector<char>::const_iterator first, std::vector<char>::const_iterator last)
    {
        if (last == first)
            return;
        assert(last - first > 0);
        if (it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos)
        {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        }
        else
            vch.insert(it, first, last);
    }

    // Append data from one datastream to this one.
    void append(CDataStream &ss, const unsigned int nChars) { vch.insert(vch.end(), ss.begin(), ss.begin() + nChars); }
    void insert(iterator it, std::string::iterator first, std::string::iterator last)
    {
        if (last == first)
            return;
        assert(last - first > 0);
        if (it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos)
        {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        }
        else
            vch.insert(it, first, last);
    }

    iterator erase(iterator it)
    {
        if (it == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (++nReadPos >= vch.size())
            {
                // whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        }
        else
            return vch.erase(it);
    }

    iterator erase(iterator first, iterator last)
    {
        if (first == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (last == vch.end())
            {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            else
            {
                nReadPos = (last - vch.begin());
                return last;
            }
        }
        else
            return vch.erase(first, last);
    }

    inline void Compact()
    {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    /** Return the current read offset from the beginning of the message
        This helps provide information to the Rewind() function.  Otherwise the caller must
        count bytes read which can be very hard when things like compact ints are being read.
     */
    size_type ReadPos() { return nReadPos; }
    /** Rewind by n characters, returns false if n is > the maximum rewindable amount */
    bool Rewind(size_type n)
    {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos)
            return false;
        nReadPos -= n;
        return true;
    }


    //
    // Stream subset
    //
    bool eof() const { return size() == 0; }
    CDataStream *rdbuf() { return this; }
    int in_avail() { return size(); }
    void SetType(int n) { nType = n; }
    int GetType() const { return nType; }
    void SetVersion(int n) { nVersion = n; }
    int GetVersion() const { return nVersion; }
    void read(char *pch, size_t nSize)
    {
        if (nSize == 0)
            return;

        // Read from the beginning of the buffer
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
            {
                throw std::ios_base::failure("CDataStream::read(): end of data");
            }
            memcpy(pch, &vch[nReadPos], nSize);
            nReadPos = 0;
            vch.clear();
            return;
        }
        memcpy(pch, &vch[nReadPos], nSize);
        nReadPos = nReadPosNext;
    }

    void ignore(int nSize)
    {
        // Ignore from the beginning of the buffer
        if (nSize < 0)
        {
            throw std::ios_base::failure("CDataStream::ignore(): nSize negative");
        }
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
                throw std::ios_base::failure("CDataStream::ignore(): end of data");
            nReadPos = 0;
            vch.clear();
            return;
        }
        nReadPos = nReadPosNext;
    }

    void write(const char *pch, size_t nSize)
    {
        // Write to the end of the buffer
        vch.insert(vch.end(), pch, pch + nSize);
    }

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        // Special case: stream << stream concatenates like stream += stream
        if (!vch.empty())
            s.write((char *)&vch[0], vch.size() * sizeof(vch[0]));
    }

    template <typename T>
    CDataStream &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    CDataStream &operator>>(T &obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    void GetAndClear(CSerializeData &data)
    {
        data.insert(data.end(), begin(), end());
        clear();
    }

    /**
     * XOR the contents of this stream with a certain key.
     *
     * @param[in] key    The key used to XOR the data in this stream.
     */
    void Xor(const std::vector<unsigned char> &key)
    {
        if (key.size() == 0)
        {
            return;
        }

        for (size_type i = 0, j = 0; i != size(); i++)
        {
            vch[i] ^= key[j++];

            // This potentially acts on very many bytes of data, so it's
            // important that we calculate `j`, i.e. the `key` index in this
            // way instead of doing a %, which would effectively be a division
            // for each byte Xor'd -- much slower than need be.
            if (j == key.size())
                j = 0;
        }
    }
};

#endif // NEXA_DATASTREAM_H
