// Copyright (c) 2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_LOCKSWAP_H
#define NEXA_LOCKSWAP_H

#include <queue>

/** A queue class that reduces lock contention.  This is primarily to be used
 *  for the send and receive queues.
 *
 *  The atomic counters which indicate the size and byte sizes in the queues are not necessarily
 *  exact at any moment in time but are used in a general way to know whether the queues have grown
 *  too large when determining whether to send or receive data from the network.
 */
template <class T>
class CLockSwapQ
{
private:
    // Lock order is cs_read then cs_write
    CCriticalSection cs_read;
    CCriticalSection cs_write;
    std::queue<T> vReadQ;
    std::queue<T> vWriteQ;

    std::atomic<int64_t> nReadSize{0};
    std::atomic<int64_t> nWriteSize{0};
    std::atomic<int64_t> nTotalBytes{0};

public:
    CLockSwapQ() {}

    bool pop_front(T &msg)
    {
        if (nWriteSize > 0 && !nReadSize)
        {
            TRY_LOCK(cs_read, lock_read);
            if (!lock_read)
                return false;

            // Another thread could have had an item already added the queue before we grabbed the lock so
            // check that it really is empty.  This way we don't end up swapping a non-empty readQ back
            // into the writeQ and thereby distrupting message ordering.
            if (vReadQ.empty())
            {
                TRY_LOCK(cs_write, lock_write);
                if (!lock_write)
                    return false;

                // Another thread may already have swapped or emptied the queue
                if (vWriteQ.empty())
                    return false;

                // If only one in queue then get it. No need to swap.
                if (vWriteQ.size() == 1)
                {
                    nWriteSize--;
                    msg = std::move(vWriteQ.front());
                    vWriteQ.pop();
                    nTotalBytes -= msg.size();
                    return true;
                }
                else
                {
                    // Swap queues
                    std::swap(vReadQ, vWriteQ);
                    nReadSize = vReadQ.size();
                    nWriteSize = vWriteQ.size();
                }
            }

            // We assume the readQ has at least one item otherwise
            // we would have already returned in the section above.
            nReadSize--;
            msg = std::move(vReadQ.front());
            vReadQ.pop();
            nTotalBytes -= msg.size();
            return true;
        }

        if (nReadSize > 0)
        {
            TRY_LOCK(cs_read, lock);
            if (!lock)
                return false;

            // Some other thread may have already emptied it.
            if (vReadQ.empty())
                return false;

            nReadSize--;
            msg = std::move(vReadQ.front());
            vReadQ.pop();
            nTotalBytes -= msg.size();
            return true;
        }
        return false;
    }

    void push_back(T msg)
    {
        LOCK(cs_write);
        nTotalBytes += msg.size();
        nWriteSize++;

        vWriteQ.emplace(std::move(msg));
        return;
    }

    bool empty() { return (nReadSize + nWriteSize) == 0; }

    size_t size() { return nReadSize + nWriteSize; }

    size_t totalbytes() { return nTotalBytes; }

    void clear()
    {
        LOCK2(cs_read, cs_write);
        while (!vReadQ.empty())
            vReadQ.pop();
        while (!vWriteQ.empty())
            vWriteQ.pop();
        nReadSize = 0;
        nWriteSize = 0;
        nTotalBytes = 0;
    }
};

#endif // NEXA_LOCKSWAP_H
