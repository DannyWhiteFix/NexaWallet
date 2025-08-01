// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2017-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"

#include "consensus/params.h"

// bip135 begin fill out entire table
struct ForkDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {/*.name =*/(char *)"", // unallocated bit 0
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 1
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 2
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 3
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 4
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 5
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 6
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 7
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 8
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 9
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 10
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 11
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 12
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 13
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 14
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 15
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 16
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 17
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 18
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 19
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 20
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 21
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 22
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 23
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 24
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 25
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 26
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 27
        /*.gbt_force =*/true,
        /*myVote = */ false},
    {/*.name =*/(char *)"", // unallocated bit 28
        /*.gbt_force =*/true,
        /*myVote = */ false}};
// bip135 end


// bip135 begin

// bip135 begin
/**
 * Return true if a deployment is considered to be configured for the network.
 * Deployments with a zero-length name, or a windowsize or threshold equal to
 * zero are not considered to be configured, and will be reported as 'unknown'
 * if signals are detected for them.
 * Unconfigured deployments can be ignored to save processing time, e.g.
 * in ComputeBlockVersion() when computing the default block version to emit.
 */
bool IsConfiguredDeployment(const Consensus::Params &consensusParams, const int bit)
{
    DbgAssert(bit >= 0 && bit <= (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS, return false);

    const Consensus::ForkDeployment *vdeployments = consensusParams.vDeployments;
    const struct ForkDeploymentInfo &vbinfo = VersionBitsDeploymentInfo[bit];

    if (strlen(vbinfo.name) == 0)
        return false;

    return (vdeployments[bit].windowsize != 0 && vdeployments[bit].threshold != 0);
}

/**
 * Return a string representing CSV-formatted deployments for the network.
 * Only configured deployments satisfying IsConfiguredDeployment() are included.
 */
const std::string NetworkDeploymentInfoCSV(const std::string &network)
{
    const Consensus::Params &consensusParams = Params(network).GetConsensus();
    const Consensus::ForkDeployment *vdeployments = consensusParams.vDeployments;

    std::string networkInfoStr;
    networkInfoStr = "# deployment info for network '" + network + "':\n";

    for (int bit = 0; bit < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; bit++)
    {
        const struct ForkDeploymentInfo &vbinfo = VersionBitsDeploymentInfo[bit];
        if (IsConfiguredDeployment(consensusParams, bit))
        {
            networkInfoStr += network + ",";
            networkInfoStr += std::to_string(bit) + ",";
            networkInfoStr += std::string(vbinfo.name) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].nStartTime) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].nTimeout) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].windowsize) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].threshold) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].minlockedblocks) + ",";
            networkInfoStr += std::to_string(vdeployments[bit].minlockedtime) + ",";
            networkInfoStr += (vbinfo.gbt_force ? "true" : "false");
            networkInfoStr += "\n";
        }
    }
    return networkInfoStr;
}

bool AbstractThresholdConditionChecker::backAtDefined(ThresholdConditionCache &cache, const CBlockIndex *pindex) const
{
    return (cache.count(pindex) && cache[pindex] == THRESHOLD_DEFINED);
}

bool AssignBip135Vote(const std::string &feature, int vote)
{
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++)
    {
        if (feature == VersionBitsDeploymentInfo[i].name)
        {
            // -1 means check existence but don't set
            if (vote != -1)
                VersionBitsDeploymentInfo[i].myVote = vote;
            return true;
        }
    }
    return false;
}

void ClearBip135Votes()
{
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++)
    {
        VersionBitsDeploymentInfo[i].myVote = false;
    }
}

bool AssignBip135Votes(const std::string &features, int vote)
{
    bool ret = true;
    std::string::size_type start = 0;
    std::string::size_type pos = 0;

    do
    {
        pos = features.find(',', start);
        std::string feature = features.substr(start, pos - start);
        // trim spaces from front and back
        auto spacePos = feature.find_first_not_of(" ");
        if (spacePos != 0 && spacePos != std::string::npos)
            feature.erase(0, spacePos);
        spacePos = feature.find_last_not_of(" ");
        if (spacePos != std::string::npos)
            feature.erase(spacePos + 1);

        ret &= AssignBip135Vote(feature, vote);
        start = pos + 1; // skip the comma
    } while (pos != std::string::npos);
    return ret;
}

// major adaptations to generalize and support new grace period parameters
ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex *pindexPrev,
    const Consensus::Params &params,
    ThresholdConditionCache &cache) const
{
    int nPeriod = Period(params);
    int nThreshold = Threshold(params);
    int64_t nTimeStart = BeginTime(params);
    int64_t nTimeTimeout = EndTime(params);
    int nMinLockedBlocks = MinLockedBlocks(params);
    int64_t nMinLockedTime = MinLockedTime(params);
    int64_t nActualLockinTime = 0;
    int nActualLockinBlock = 0;

    if (nPeriod == 0)
    {
        // we cannot do anything further -this deployment is not really defined.
        return THRESHOLD_DEFINED;
    }

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev
    // whose height equals a multiple of nPeriod - 1.
    if (pindexPrev != nullptr)
    {
        assert(nPeriod);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->height() - ((pindexPrev->height() + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev which was DEFINED
    std::vector<const CBlockIndex *> vToCompute;

    while (!backAtDefined(cache, (const CBlockIndex *)pindexPrev))
    {
        if (pindexPrev == nullptr)
        {
            // The genesis block is by definition defined.
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart)
        {
            // Optimizaton: don't recompute down further, as we know every
            // earlier block will be before the start time
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }

        // push the pindex for later forward walking
        vToCompute.push_back(pindexPrev);
        // go back one more period
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->height() - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    assert(cache.count(pindexPrev));

    // initialize starting state for forward walk
    ThresholdState state = cache[pindexPrev];
    assert(state == THRESHOLD_DEFINED);
    // Now walk forward and compute the state of descendants of pindexPrev
    while (!vToCompute.empty())
    {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        switch (state)
        {
        case THRESHOLD_DEFINED:
        {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout)
            {
                stateNext = THRESHOLD_FAILED;
            }
            else if (pindexPrev->GetMedianTimePast() >= nTimeStart)
            {
                stateNext = THRESHOLD_STARTED;
            }
            break;
        }
        case THRESHOLD_STARTED:
        {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout)
            {
                stateNext = THRESHOLD_FAILED;
                break;
            }
            // We need to count
            const CBlockIndex *pindexCount = pindexPrev;
            int count = 0;
            for (int i = 0; i < nPeriod; i++)
            {
                if (Condition(pindexCount, params))
                {
                    count++;
                }
                pindexCount = pindexCount->pprev;
            }
            if (count >= nThreshold)
            {
                stateNext = THRESHOLD_LOCKED_IN;
                // bip135: make a note of lock-in time & height
                // this will be used for assessing grace period conditions.
                nActualLockinBlock = pindexPrev->height();
                nActualLockinTime = pindexPrev->GetMedianTimePast();
            }
            break;
        }
        case THRESHOLD_LOCKED_IN:
        {
            // bip135: Progress to ACTIVE only once all grace conditions are met.
            if (pindexPrev->GetMedianTimePast() >= nActualLockinTime + nMinLockedTime &&
                pindexPrev->height() >= nActualLockinBlock + nMinLockedBlocks)
            {
                stateNext = THRESHOLD_ACTIVE;
            }
            else
            {
                // bip135: if grace not yet met, remain in LOCKED_IN
                stateNext = THRESHOLD_LOCKED_IN;
            }
            break;
        }
        case THRESHOLD_FAILED:
        case THRESHOLD_ACTIVE:
        {
            // Nothing happens, these are terminal states.
            break;
        }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}
// bip135 end


namespace
{
/**
 * Class to implement versionbits logic.
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    const Consensus::DeploymentPos id;

protected:
    int64_t BeginTime(const Consensus::Params &params) const { return params.vDeployments[id].nStartTime; }
    int64_t EndTime(const Consensus::Params &params) const { return params.vDeployments[id].nTimeout; }
    int Period(const Consensus::Params &params) const { return params.vDeployments[id].windowsize; }
    int Threshold(const Consensus::Params &params) const { return params.vDeployments[id].threshold; }
    int MinLockedBlocks(const Consensus::Params &params) const { return params.vDeployments[id].minlockedblocks; }
    int64_t MinLockedTime(const Consensus::Params &params) const { return params.vDeployments[id].minlockedtime; }
    bool Condition(const CBlockIndex *pindex, const Consensus::Params &params) const
    {
        return false;
        /* TODO version bits feature selector will need to be moved if used */
    }

public:
    VersionBitsConditionChecker(Consensus::DeploymentPos id_) : id(id_) {}
    uint32_t Mask(const Consensus::Params &params) const { return ((uint32_t)1) << params.vDeployments[id].bit; }
};
} // namespace

ThresholdState VersionBitsState(const CBlockIndex *pindexPrev,
    const Consensus::Params &params,
    Consensus::DeploymentPos pos,
    VersionBitsCache &cache)
{
    return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, cache.caches[pos]);
}

uint32_t VersionBitsMask(const Consensus::Params &params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).Mask(params);
}


void VersionBitsCache::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++)
    {
        caches[d].clear();
    }
}
