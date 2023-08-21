// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_STREAMS_H
#define NEXA_STREAMS_H

#include "datastream.h"
#include "util.h"

#include <algorithm>
#include <assert.h>
#include <ios>
#include <limits>
#include <map>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

template <typename Stream>
class OverrideStream
{
    Stream *stream;

    const int nType;
    const int nVersion;

public:
    OverrideStream(Stream *stream_, int nType_, int nVersion_) : stream(stream_), nType(nType_), nVersion(nVersion_) {}

    template <typename T>
    OverrideStream<Stream> &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    OverrideStream<Stream> &operator>>(T &&obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    void write(const char *pch, size_t nSize) { stream->write(pch, nSize); }

    void read(char *pch, size_t nSize) { stream->read(pch, nSize); }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    void ignore(size_t size) { return stream->ignore(size); }
};

template <typename S>
OverrideStream<S> WithOrVersion(S *s, int nVersionFlag)
{
    return OverrideStream<S>(s, s->GetType(), s->GetVersion() | nVersionFlag);
}

/**
 * Minimal stream for overwriting and/or appending to an existing byte vector.
 *
 * The referenced vector will grow as necessary.
 */
class CVectorWriter
{
public:
    /**
     * @param[in]  nTypeIn Serialization Type
     * @param[in]  nVersionIn Serialization Version (including any flags)
     * @param[in]  vchDataIn  Referenced byte vector to overwrite/append
     * @param[in]  nPosIn Starting position. Vector index where writes should
     * start. The vector will initially grow as necessary to  max(nPosIn,
     * vec.size()). So to append, use vec.size().
     */
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<uint8_t> &vchDataIn, size_t nPosIn)
        : nType(nTypeIn), nVersion(nVersionIn), vchData(vchDataIn), nPos(nPosIn)
    {
        if (nPos > vchData.size())
        {
            vchData.resize(nPos);
        }
    }
    /**
     * (other params same as above)
     * @param[in]  args  A list of items to serialize starting at nPosIn.
     */
    template <typename... Args>
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<uint8_t> &vchDataIn, size_t nPosIn, Args &&...args)
        : CVectorWriter(nTypeIn, nVersionIn, vchDataIn, nPosIn)
    {
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }
    void write(const char *pch, size_t nSize)
    {
        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(nSize, vchData.size() - nPos);
        if (nOverwrite)
        {
            memcpy(vchData.data() + nPos, reinterpret_cast<const uint8_t *>(pch), nOverwrite);
        }
        if (nOverwrite < nSize)
        {
            vchData.insert(vchData.end(), reinterpret_cast<const uint8_t *>(pch) + nOverwrite,
                reinterpret_cast<const uint8_t *>(pch) + nSize);
        }
        nPos += nSize;
    }
    template <typename T>
    CVectorWriter &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    size_t size() const { return vchData.size(); }
    void seek(size_t nSize)
    {
        nPos += nSize;
        if (nPos > vchData.size())
        {
            vchData.resize(nPos);
        }
    }

private:
    const int nType;
    const int nVersion;
    std::vector<uint8_t> &vchData;
    size_t nPos;
};

/**
 * Minimal stream for reading from an existing vector by reference
 */
class VectorReader
{
private:
    const int m_type;
    const int m_version;
    const std::vector<uint8_t> &m_data;
    size_t m_pos = 0;

public:
    /**
     * @param[in]  type Serialization Type
     * @param[in]  version Serialization Version (including any flags)
     * @param[in]  data Referenced byte vector to overwrite/append
     * @param[in]  pos Starting position. Vector index where reads should start.
     */
    VectorReader(int type, int version, const std::vector<uint8_t> &data, size_t pos)
        : m_type(type), m_version(version), m_data(data), m_pos(pos)
    {
        if (m_pos > m_data.size())
        {
            throw std::ios_base::failure("VectorReader(...): end of data (m_pos > m_data.size())");
        }
    }

    /**
     * (other params same as above)
     * @param[in]  args  A list of items to deserialize starting at pos.
     */
    template <typename... Args>
    VectorReader(int type, int version, const std::vector<uint8_t> &data, size_t pos, Args &&...args)
        : VectorReader(type, version, data, pos)
    {
        ::UnserializeMany(*this, std::forward<Args>(args)...);
    }

    template <typename T>
    VectorReader &operator>>(T &obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    int GetVersion() const { return m_version; }
    int GetType() const { return m_type; }

    size_t size() const { return m_data.size() - m_pos; }
    bool empty() const { return m_data.size() == m_pos; }

    void read(char *dst, size_t n)
    {
        if (n == 0)
        {
            return;
        }

        // Read from the beginning of the buffer
        size_t pos_next = m_pos + n;
        if (pos_next > m_data.size())
        {
            throw std::ios_base::failure("VectorReader::read(): end of data");
        }
        memcpy(dst, m_data.data() + m_pos, n);
        m_pos = pos_next;
    }
};

/** Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null.
 * If you're returning the file pointer, return file.release().
 * If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CAutoFile
{
private:
    // Disallow copies
    CAutoFile(const CAutoFile &);
    CAutoFile &operator=(const CAutoFile &);

    const int nType;
    const int nVersion;

    FILE *file;

public:
    CAutoFile(FILE *filenew, int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) { file = filenew; }
    ~CAutoFile() { fclose(); }
    void fclose()
    {
        if (file)
        {
            ::fclose(file);
            file = nullptr;
        }
    }

    /** Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the CAutoFile object, and makes it the responsibility of the caller
     * of this function to clean up the returned FILE*.
     */
    FILE *release()
    {
        FILE *ret = file;
        file = nullptr;
        return ret;
    }

    /** Get wrapped FILE* without transfer of ownership.
     * @note Ownership of the FILE* will remain with this class. Use this only if the scope of the
     * CAutoFile outlives use of the passed pointer.
     */
    FILE *Get() const { return file; }
    /** Return true if the wrapped FILE* is nullptr, false otherwise.
     */
    bool IsNull() const { return (file == nullptr); }
    //
    // Stream subset
    //
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }
    void read(char *pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::read: file handle is nullptr");
        if (fread(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure(feof(file) ? "CAutoFile::read: end of file" : "CAutoFile::read: fread failed");
    }

    void ignore(size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::ignore: file handle is nullptr");
        unsigned char data[4096];
        while (nSize > 0)
        {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (fread(data, 1, nNow, file) != nNow)
                throw std::ios_base::failure(
                    feof(file) ? "CAutoFile::ignore: end of file" : "CAutoFile::read: fread failed");
            nSize -= nNow;
        }
    }

    void write(const char *pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::write: file handle is nullptr");
        if (fwrite(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure("CAutoFile::write: write failed");
    }

    template <typename T>
    CAutoFile &operator<<(const T &obj)
    {
        // Serialize to this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator<<: file handle is nullptr");
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    CAutoFile &operator>>(T &obj)
    {
        // Unserialize from this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator>>: file handle is nullptr");
        ::Unserialize(*this, obj);
        return (*this);
    }
};


/** Non-refcounted RAII wrapper around a FILE* that implements a ring buffer to
 *  deserialize from. It guarantees the ability to rewind a given number of bytes.
 *
 *  Will automatically close the file when it goes out of scope if not null.
 *  If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CBufferedFile
{
private:
    // Disallow copies
    CBufferedFile(const CBufferedFile &);
    CBufferedFile &operator=(const CBufferedFile &);

    const int nType;
    const int nVersion;

    FILE *src; // source file
    uint64_t nSrcPos; // how many bytes have been read from source
    uint64_t nReadPos; // how many bytes caller has read from this
    uint64_t nReadLimit; // up to which position we're allowed to read
    uint64_t nRewind; // how many bytes we guarantee to rewind
    std::vector<char> vchBuf; // the buffer
    enum
    {
        RESIZE_EXTRA = 200000
    }; // BU how much additional to allocate if forced to resize
protected:
    // read data from the source to fill the buffer
    bool Fill()
    {
        unsigned int pos = nSrcPos % vchBuf.size();
        unsigned int readNow = vchBuf.size() - pos; // how much to go until the end
        unsigned int nAvail = vchBuf.size() - (nSrcPos - nReadPos) - nRewind; // how much do we need to preserve
        if (nAvail < readNow)
            readNow = nAvail;
        if (readNow == 0)
            return false;
        size_t read = fread((void *)&vchBuf[pos], 1, readNow, src);
        if (read == 0)
        {
            throw std::ios_base::failure(
                feof(src) ? "CBufferedFile::Fill: end of file" : "CBufferedFile::Fill: fread failed");
        }
        else
        {
            nSrcPos += read;
            return true;
        }
    }

public:
    CBufferedFile(FILE *fileIn, uint64_t nBufSize, uint64_t nRewindIn, int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn), nSrcPos(0), nReadPos(0), nReadLimit((uint64_t)(-1)), nRewind(nRewindIn),
          vchBuf(nBufSize, 0)
    {
        src = fileIn;
    }

    ~CBufferedFile() { fclose(); }
    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    void fclose()
    {
        if (src)
        {
            ::fclose(src);
            src = nullptr;
        }
    }

    // check whether we're at the end of the source file
    bool eof() const { return nReadPos == nSrcPos && feof(src); }
    // read a number of bytes
    void read(char *pch, size_t nSize)
    {
        if (nSize + nReadPos > nReadLimit)
            throw std::ios_base::failure("Read attempted past buffer limit");
        if (nSize + nRewind > vchBuf.size()) // What's already read + what I want to read + how far I want to rewind
        {
            LOG(REINDEX, "Large read, growing buffer (size: %lld)\n", nSize);
            GrowTo(nSize + nRewind + RESIZE_EXTRA);
            if (nSize + nRewind > vchBuf.size()) // make sure it worked
                throw std::ios_base::failure("Read larger than buffer size");
        }
        while (nSize > 0)
        {
            if (nReadPos == nSrcPos)
                Fill();
            unsigned int pos = nReadPos % vchBuf.size();
            size_t nNow = nSize;
            if (nNow + pos > vchBuf.size())
                nNow = vchBuf.size() - pos;
            if (nNow + nReadPos > nSrcPos)
                nNow = nSrcPos - nReadPos;
            memcpy(pch, &vchBuf[pos], nNow);
            nReadPos += nNow;
            pch += nNow;
            nSize -= nNow;
        }
    }

    // return the current reading position
    uint64_t GetPos() { return nReadPos; }
    // rewind to a given reading position
    bool SetPos(uint64_t nPos)
    {
        nReadPos = nPos;
        if (nReadPos + nRewind < nSrcPos)
        {
            LOG(REINDEX, "Short SetPos: desired %lld actual %lld srcpos %lld buffer size %lld, rewind %lld\n", nPos,
                nReadPos, nSrcPos, vchBuf.size(), nRewind);
            nReadPos = nSrcPos - nRewind;
            return false;
        }
        else if (nReadPos > nSrcPos)
        {
            LOG(REINDEX, "Long SetPos: desired %lld actual %lld srcpos %lld buffer size %lld, rewind %lld\n", nPos,
                nReadPos, nSrcPos, vchBuf.size(), nRewind);
            nReadPos = nSrcPos;
            return false;
        }
        else
        {
            return true;
        }
    }

// BU: commented because this function is unused, and not correct -- after seeking, you can't SetPos and therefore
// correctly rewind...
#if 0
    bool Seek(uint64_t nPos) {
        long nLongPos = nPos;
        if (nPos != (uint64_t)nLongPos)
            return false;
        if (fseek(src, nLongPos, SEEK_SET))
            return false;
        nLongPos = ftell(src);
        nSrcPos = nLongPos;
        nReadPos = nLongPos;
        return true;
    }
#endif

    // prevent reading beyond a certain position
    // no argument removes the limit
    bool SetLimit(uint64_t nPos = (uint64_t)(-1))
    {
        if (nPos < nReadPos)
            return false;
        nReadLimit = nPos;
        return true;
    }

    template <typename T>
    CBufferedFile &operator>>(T &obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    // search for a given byte in the stream, and remain positioned on it
    void FindByte(char ch)
    {
        while (true)
        {
            if (nReadPos == nSrcPos)
                Fill();
            if (vchBuf[nReadPos % vchBuf.size()] == ch)
                break;
            nReadPos++;
        }
    }

    // if the current buffer doesn't have amt more data, then extend it by that much
    void GrowTo(uint64_t amt)
    {
        if (vchBuf.size() < amt) // We want as much data as we are currently saving, plus the new data
        {
            // Resize is inefficient, so at a minimum double the buffer to make # resizes log(n)
            amt = std::max(amt, ((uint64_t)vchBuf.size()) * 2);
            vchBuf.resize(amt, 0);
            LOG(REINDEX, "File buffer resize to %s\n", vchBuf.size());

            // Now at this new buffer size the boundaries will be different so I have to reload the rewinded data
            // Position the data to be read at the start of the old maximum rewind (or the file beginning)
            uint64_t readPos = 0;
            if (nRewind < nReadPos)
                readPos = nReadPos - nRewind;

            // Now expand the rewind
            nRewind = amt / 2;

            if (fseek(src, readPos, SEEK_SET))
            {
                throw std::ios_base::failure("CBufferedFile::GrowTo: fseek error");
            }
            unsigned int pos = readPos % vchBuf.size();
            // the amount to read is the minimum of what's left over or the max we can read
            unsigned int readNow = std::min((uint64_t)(vchBuf.size() - pos), nRewind);
            size_t read = fread((void *)&vchBuf[pos], 1, readNow, src);
            // We MUST be able to read something because we rewound by nRewind so we've already read this once.
            assert(read != 0);
            nSrcPos = readPos + read;
            if ((nReadPos > nSrcPos) && (read == readNow)) // I filled to the buffer end, but that wasn't enough
            {
                // The limit of this read is the prior start position in the buffer, or the maximum ahead the read is
                // allowed to get
                readNow = std::min(pos, (unsigned int)(nRewind - read));
                read = fread((void *)&vchBuf[0], 1, readNow, src);
                if (read == 0)
                {
                    throw std::ios_base::failure(
                        feof(src) ? "CBufferedFile::GrowTo: end of file" : "CBufferedFile::GrowTo: fread failed");
                }
                nSrcPos += read;
            }
            // By the end of the above logic, we must have filled the buffer up to the current read position.
            assert(nReadPos <= nSrcPos);
        }
    }
};

#endif // NEXA_STREAMS_H
