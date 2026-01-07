// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation/dag.h"

#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(tailstorm_dag_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(coinbase_rewards)
{
    // set up a set of nodes and put them in a dag. The nodes must have
    // a correct set of ancestors so we can calculate scores. 
    //
    // The following dags are show in verticle going from top to bottom
    // Each dag show the summary block "block" at each end.  The score
    // for each subblock is show as a number in the center of the subblock
    //
    // The final block is itself a subblock so that's why, in the first example,
    // the score is 2, when you only see on subblock. But it's actually one
    // subblock "plus" the summary blocks' subbock which makes 2.


    /*
    Dag (k=2) with 1 subblock and the summary's subblock

    =======
    block 1
    =======
       |
     -----
     | 1 |
     -----
       |
    =======
    block 2
      (1)
    =======

    */

    std::set<CTreeNodeRef> setBestDag;
    std::map<uint256, uint32_t> mapExpectedScores;

    CTreeNode node;
    node.hash = InsecureRand256();
    node.dagHeight = 1;
    CTreeNodeRef noderef = MakeTreeNodeRef(node);

    setBestDag.insert(noderef);
    mapExpectedScores.emplace(node.hash, 1);

    auto mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }


    /*
    Dag (k=3) with 2 subblock and the summary's subblock

    =======
    block 1
    =======
       |
     -----
     | 2 |
     -----
       |
     -----
     | 2 |
     -----
       |
    =======
    block 2
      (2)
    =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    CTreeNodeRef noderef1 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.insert(noderef1);
    CTreeNodeRef noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 2 |
    -----  -----
       \   /
        | |
       -----
       | 3 |
       -----
         |
      =======
      block 2
        (3)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    CTreeNodeRef noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    CTreeNodeRef noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    node.setAncestors.insert(noderef1b);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 3);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);
    noderef1b->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

       =======
       block 1
       =======
       /     \
    -----    -----
    | 2 |    | 1 | * low score from a skipped dagheight link.
    -----    -----
      |        /
      |       /
    -----    /
    | 2 |   /
    -----  /
       \  /
      =======
      block 2
        (3)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=8) with 3 subblocks and the summary's subblock

       =======
       block 1
       =======
       /     \
    -----    -----
    | 6 |    | 1 | * low score from a skipped dagheight link.
    -----    -----
      |        /
      |       /
    -----    /
    | 6 |   /
    -----  /
      |   /
    -----  
    | 7 |   
    -----    
      |   \
      |    \
      |     \
    -----    -----
    | 6 |    | 5 | * low score from a skipped dagheight link.
    -----    -----
      |        /
      |       /
    -----    /
    | 6 |   /
    -----  /
       \  /
      =======
      block 2
        (7)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 6);


    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2);
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);


    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 5;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef4);
    CTreeNodeRef noderef5 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef5);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);
    noderef1b->setDescendants.insert(noderef3);
    noderef2->setDescendants.insert(noderef3);
    noderef3->setDescendants.insert(noderef4);
    noderef3->setDescendants.insert(noderef4b);
    noderef4->setDescendants.insert(noderef5);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=5) with 4 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 2 |
    -----  -----
      |      |
      |      |
    -----  -----
    | 2 |  | 2 |
    -----  -----
       \   /
      =======
      block 2
        (4)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    CTreeNodeRef noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=6) with 5 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 3 |
    -----  -----
      |      |  \
      |      |   \
    -----  -----  -----
    | 2 |  | 2 |  | 2 |
    -----  -----  -----
      \    |     /
        =======
        block 2
          (5)
        =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=7) with 6 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 3 |  | 4 |
    -----  -----
      |      |  \
      |      |   \
    -----  -----  -----
    | 3 |  | 3 |  | 3 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
           -----
           | 6 |
           -----
             |
          =======
          block 2
            (6)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    CTreeNodeRef noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=6) with 5 subblocks and the summary's subblock

          =======
          block 1
          =======
             |
           -----
           | 5 |
           -----
          /  |  \
         /   |   \
    -----  -----  -----
    | 3 |  | 3 |  | 3 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
           -----
           | 5 |
           -----
             |
          =======
          block 2
            (5)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 5);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1a->setDescendants.insert(noderef2b);
    noderef1a->setDescendants.insert(noderef2c);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

          =======
          block 1
          =======
          /  |  \
         /   |   \
    -----  -----  -----
    | 1 |  | 1 |  | 1 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
          =======
          block 2
            (3)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();


    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 1);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=5) with 4 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 3 |  | 1 | * low score skipped dagheight link
    -----  -----
      |      |
      |      |
    -----    |
    | 3 |    |
    -----    |
      |      |
      |      |
      |      |
    -----    |
    | 3 |    |
    -----    |
        \    |
        =======
        block 2
          (4)
        =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 3);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef2a->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }


    /*
    Wider dag (k=9) with 8 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 6 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 2 | *a possible selfish miner with a skipped dagheight link gets a low score
    -----  -----  -----  -----
        \    |    /     /
         \   |   /     /
          \  |  /     /
           -----     /
           | 7 |    /
           -----   /
             |    /
             |   /
           ----- 
           | 8 |
           -----
             |
          =======
          block 2
            (8)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    // Special case in that we need to add the children so we can
    // properly caclulate scores for the skipped level
    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3a);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);
    noderef2d->setDescendants.insert(noderef4);
    noderef3a->setDescendants.insert(noderef4);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=11) with 10 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 8 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 4 | * has both skipped and non skipped dagheight links.
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /   -----
           | 7 |    /    | 4 |
           -----   /     -----
             |    /        |
             |   /         |
           -----         -----
           | 8 |         | 4 |
           -----         -----
             |             |
          =======          |
          block 2  ________|
            (10)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3a);
    CTreeNodeRef noderef4a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef3a);
    noderef3->setDescendants.insert(noderef4);
    noderef3a->setDescendants.insert(noderef4a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=10) with 9 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 5 |  | 7 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 5 |  | 5 |  | 5 |  | 2 | * has 2 skipped dagheight links and a low score as a result
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /     |
           | 8 |\   /      |
           ----- \ /       |
             |    /        |
             |   / \       |
           -----    \    -----
           | 8 |     \__ | 8 |
           -----         -----
             |             |
          =======          |
          block 2  ________|
            (9)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4a);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef4a);
    noderef3->setDescendants.insert(noderef4);
    noderef3->setDescendants.insert(noderef4a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=10) with 9 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 7 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 3 | * has both skipped and non skipped dagheight links.
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /   -----
           | 7 |    /    | 3 | * has a skipped dagheight link 
           -----   /     -----
             |    /      /
             |   /      /
           -----       / 
           | 8 |      /  
           -----     /    
             |      /
          =======  /
          block 2  
            (9)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef3a);
    noderef3->setDescendants.insert(noderef4);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*  Prove that adding exta an unnecessary links to past blocks does not effect the score
    Wider dag (k=7) with 6 subblocks and the summary's subblock

           =======
           block 1
           =======
            /   \
         -----  -----
    ____ | 3 |  | 4 |_________
   |     -----  -----         |
   |       |      |  \        |
   |       |      |   \       |
   |     -----  -----  -----  |
   |     | 3 |  | 3 |  | 3 |  |
   |     -----  -----  -----  |
   |         \    |    /      |
   |          \   |   /       |
   |           \  |  /        |
   |            -----         |
   |___________ | 6 |_________|
                -----
                  |
               =======
               block 2
                 (6)
              =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    node.setAncestors.insert(noderef1b);
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1a->setDescendants.insert(noderef3a);
    noderef1b->setDescendants.insert(noderef3a);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

}

BOOST_AUTO_TEST_SUITE_END()
