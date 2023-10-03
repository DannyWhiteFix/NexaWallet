#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import test_framework.loginit
import pdb
from test_framework.util import *
from test_framework.test_framework import BitcoinTestFramework
import hashlib
import logging
import pprint
import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
logging.basicConfig(format='%(asctime)s.%(levelname)s: %(message)s', level=logging.DEBUG, stream=sys.stdout)


class GroupTokensTest (BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        self.verbose = False
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir)

        # Now interconnect the nodes
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        self.is_network_split = False
        self.sync_blocks()

    def checkGroupNew(self, txjson, ticker=None, name = None, url = None, sha = None):
        hasGroupOutput = 0
        groupFlags = 0
        for t in txjson["vout"]:
            asm = t["scriptPubKey"]["asm"].split()
            assert(len(asm) > 0)  # output script must be something
            if "group" in t["scriptPubKey"]:
                hasGroupOutput += 1
                groupFlags = int(asm[1], 10)
        assert(hasGroupOutput == 1)
        assert(groupFlags < 0)  # verify group bit set (highest bit set causes bitcoind asm script decoder to output a negative number)
        if ticker:
            for t in txjson["vout"]:
                if t["value"] == Decimal("0"): # Found the op return
                    asm = t["scriptPubKey"]["asm"].split()
                    tmp = hex(int(asm[2]))
                    assert bytes.fromhex(tmp[2:])[::-1].decode() == ticker
                    assert bytes.fromhex(asm[3]).decode() == name
                    assert bytes.fromhex(asm[4]).decode() == url
                    assert bytes.fromhex(asm[5])[::-1] == bytes.fromhex(sha)

    def checkTokenInfo(self, node, grpId, ticker="", name="", url="", url_hash="", balance="0"):
        info = node.token("info")
        if (grpId not in info):
            raise Exception("Group Id not found")

        assert_equal(info[grpId]['ticker'], ticker)
        assert_equal(info[grpId]['name'], name)
        assert_equal(info[grpId]['url'], url)
        assert_equal(info[grpId]['hash'], url_hash)
        assert_equal(info[grpId]['balance'], balance)

        info = node.token("info", grpId)
        if (len(info) != 1):
            raise Exception("Incorrect number of elements returned")
        if (grpId not in info):
            raise Exception("Group Id not found")

        assert_equal(info[grpId]['ticker'], ticker)
        assert_equal(info[grpId]['name'], name)
        assert_equal(info[grpId]['url'], url)
        assert_equal(info[grpId]['hash'], url_hash)
        assert_equal(info[grpId]['balance'], balance)


    def examineTx(self, tx, node):
        txjson = node.decoderawtransaction(node.gettransaction(tx)["hex"])
        i = 0
        for txi in txjson["vin"]:
            if self.verbose:
              print("input %d:\n" % i)
              pprint.pprint(txi, indent=2, width=200)
            i += 1
        if self.verbose:
          print("\n")
          pprint.pprint(txjson, indent=2, width=200)
          print("\n")

    def subgroupTest(self):
        logging.info("subgroup test")
        self.nodes[0].generate(1)
        grp1 = self.nodes[0].token("new")["groupIdentifier"]

        sg1a = self.nodes[0].token("subgroup", grp1, 1)
        tmp  = self.nodes[0].token("subgroup", grp1, "1")
        assert_equal(sg1a, tmp)  # This equality is a feature of this wallet, not subgroups in general
        sg1b = self.nodes[0].token("subgroup", grp1, 2)
        assert(sg1a != sg1b)
        logging.info("Made groups and subgroups")
        addr2 = self.nodes[2].getnewaddress()

        # mint 100 tokens for node 2
        tx = self.nodes[0].token("mint",sg1a, addr2, 100)
        waitFor(30, lambda: tx in self.nodes[2].getrawtxpool())  # If this fails, remember that there's a very rare chance that a tx won't propagate due to an inv bloom filter collision.
        assert_equal(self.nodes[2].token("balance", sg1a), 100)
        assert_equal(self.nodes[2].token("balance", grp1), 0)

        try: # node 2 doesn't have melt auth on the group or subgroup
            tx = self.nodes[2].token("melt",sg1a, 50)
            assert(0)
        except JSONRPCException as e:
            pass

        tx = self.nodes[0].token("authority","create", sg1a, addr2, "MELT", "NOCHILD")
        waitFor(30, lambda: tx in self.nodes[2].getrawtxpool())  # If this fails, remember that there's a very rare chance that a tx won't propagate due to an inv bloom filter collision.
        tx = self.nodes[2].token("melt",sg1a, 50)

        try: # gave a nonrenewable authority
            tx = self.nodes[2].token("melt",sg1a, 50)
            assert(0)
        except JSONRPCException as e:
            pass

        return True

    def decimalDescTest(self):
        anyhash = "9241565005f6647e8a521801e72c6d66b6cf01ff85df89e238f24b02878d3b40"
        n = self.nodes[0]
        addr = n.getnewaddress()
        n.generate(5) # clear out anything and get coins

        g0 = n.token("new", "tkr", "name","http://nothing.com/", anyhash, 4)
        tx0 = waitFor(60, lambda: n.getrawtransaction(g0["transaction"], True))
        assert(tx0['vout'][0]['scriptPubKey']['asm'].split()[-1] == '4')
        ti = n.token("info", g0["groupIdentifier"])
        assert(ti[g0["groupIdentifier"]]["decimals"] == "4")

        try:
            g0 = n.token("new", "tkr", "name","http://nothing.com/", anyhash, 19)
            assert(0) # too many decimals
        except JSONRPCException as e:
            pass  # worked

        try:
            g0 = n.token("new", "tkr", "name","http://nothing.com/", anyhash, -1)
            assert(0) # negative doesn't work
        except JSONRPCException as e:
            pass  # worked

        n.generate(1)
        # no arg means 0 decimals
        g0 = n.token("new", "tkr", "name","http://nothing.com/", anyhash)
        tx0 = waitFor(60, lambda: n.getrawtransaction(g0["transaction"], True))
        assert(tx0['vout'][0]['scriptPubKey']['asm'].split()[-1] == '0')
        ti = n.token("info", g0["groupIdentifier"])
        assert(ti[g0["groupIdentifier"]]["decimals"] == "0")

        n.generate(1)
        # try max decimals and string
        g0 = n.token("new", "tkr", "name","http://nothing.com/", anyhash, "18")
        tx0 = waitFor(60, lambda: n.getrawtransaction(g0["transaction"], True))
        assert(tx0['vout'][0]['scriptPubKey']['asm'].split()[-1] == '18')
        ti = n.token("info", g0["groupIdentifier"])
        assert(ti[g0["groupIdentifier"]]["decimals"] == "18")

        # done


    def descDocTest(self):
        logging.info("description doc test")
        self.nodes[2].generate(10)

        # These restrictions are implemented in this wallet and follow the spec, but are NOT consensus.
        try:
            ret = self.nodes[2].token("new", "tkr")
            assert(0) # need token name
        except JSONRPCException as e:
            assert("token name" in e.error["message"])
        try:
            ret = self.nodes[2].token("new", "012345678", "name")
            assert(0) # need token name
        except JSONRPCException as e:
            assert("too many characters" in e.error["message"])

        ret = self.nodes[2].token("new", "tkr", "name")
        ret = self.nodes[2].token("new", "", "")  # provide empty ticker and name

        try:
            ret = self.nodes[2].token("new", "tkr", "name", "foo")
        except JSONRPCException as e:
            assert("missing colon" in e.error["message"])
        try:
            ret = self.nodes[2].token("new", "tkr", "name", "foo:bar")
        except JSONRPCException as e:
            assert("token description document hash" in e.error["message"])

        tddId = hashlib.sha256(b"tdd here").hexdigest()
        ret = self.nodes[2].token("new", "tkr", "name", "foo:bar", tddId )

    def run_test(self):
        logging.info("starting grouptokens test")


        # instant transactions should be on so that balances are fully
        # available when transactions show up in the mempool.  Later
        # in the testing we can turn off to test whether
        # instant transactions can be turned off for tokens.
        self.nodes[0].set("wallet.instant=true");
        self.nodes[0].set("wallet.instantDelay=0");
        self.nodes[1].set("wallet.instant=true");
        self.nodes[1].set("wallet.instantDelay=0");
        self.nodes[2].set("wallet.instant=true");
        self.nodes[2].set("wallet.instantDelay=0");

        # generate enough blocks so that nodes[0] has a balance
        self.nodes[2].generate(2)
        self.sync_blocks()
        self.nodes[0].generate(101)
        self.sync_blocks()

        assert_equal(self.nodes[0].getbalance(), COINBASE_REWARD)

        try:
            ret = self.nodes[1].token("new")
            assert(0)  # should have raised exception
        except JSONRPCException as e:
            assert("No coins available" in e.error["message"])

        auth2Addr = self.nodes[2].getnewaddress()
        auth1Addr = self.nodes[1].getnewaddress()
        auth0Addr = self.nodes[0].getnewaddress()

        try:
            ret = self.nodes[1].token("new", auth1Addr)
            assert(0)  # should have raised exception
        except JSONRPCException as e:
            assert("No coins available" in e.error["message"])

        # Create a group, allow wallet to pick an authority address
        t = self.nodes[0].token("new")
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grpId = t["groupIdentifier"]
        self.checkTokenInfo(self.nodes[0], grpId)

        # Create a group to a specific authority address
        t = self.nodes[0].token("new", auth0Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp0Id = t["groupIdentifier"]
        self.checkTokenInfo(self.nodes[0], grp0Id)

        t = self.nodes[0].token("new", auth0Addr, "TICK", "NameGoesHere", "https://www.nexa.org", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")
        raw = self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"])
        self.checkGroupNew(raw,"TICK", "NameGoesHere", "https://www.nexa.org", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")
        self.checkTokenInfo(self.nodes[0], t["groupIdentifier"], "TICK", "NameGoesHere", "https://www.nexa.org", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")

        t = self.nodes[0].token("new", "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]),
        "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")
        self.checkTokenInfo(self.nodes[0], t["groupIdentifier"], "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a63")

        try:
            t = self.nodes[0].token("new", "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing")
            assert False  # bad param combination (missing - each param is optional in the spec but in the RPC if you give a url to a desc doc you need to provide the dsha256 hash of that doc)
        except JSONRPCException as e:
            pass
        try:
            t = self.nodes[0].token("new", "TICK2", "AnotherNameGoesHere")
        except JSONRPCException as e:
            assert False  # this param combination should work
        try:
            t = self.nodes[0].token("new", "TICK2")
            assert False  # bad param combination (missing)
        except JSONRPCException as e:
            pass

        try:
            t = self.nodes[0].token("new", auth1Addr, "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing")
            assert False
        except JSONRPCException as e:
            pass
        try:
            t = self.nodes[0].token("new", auth1Addr, "TICK2", "AnotherNameGoesHere")
        except JSONRPCException as e:
            assert False
        try:
            t = self.nodes[0].token("new", auth1Addr, "TICK2")
            assert False  # bad param combination (missing)
        except JSONRPCException as e:
            pass

        # In this python test we periodically consolidate all txns in the main wallet which should have
        # no effect on any tokens in the wallet
        logging.info("Consolidating " + str(len(self.nodes[0].listunspent(0))))
        self.nodes[0].consolidate(5000, 1)

        # Create a group on behalf of a different node (with an authority address I don't control)
        t = self.nodes[0].token("new", auth1Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp1Id = t["groupIdentifier"]
        self.nodes[0].generate(1)
        self.sync_blocks()
        self.checkTokenInfo(self.nodes[1], grp1Id)
        try:
            self.checkTokenInfo(self.nodes[0], grp1Id)
            assert False
        except:
            pass

        t = self.nodes[0].token("new", auth2Addr)
        self.checkGroupNew(self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(t["transaction"])["hex"]))
        grp2Id = t["groupIdentifier"]
        self.nodes[0].generate(1)
        self.sync_blocks()
        self.checkTokenInfo(self.nodes[2], grp2Id)
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id)
            assert False
        except:
            pass

        mint0_0 = self.nodes[0].getnewaddress()
        mint0_1 = self.nodes[0].getnewaddress()
        mint1_0 = self.nodes[1].getnewaddress()
        mint2_0 = self.nodes[2].getnewaddress()
        # mint to a local address
        self.nodes[0].token("mint", grpId, mint0_0, 1000)
        self.checkTokenInfo(self.nodes[0], grpId, "", "", "", "", 1000)

        # mint to a local address
        self.nodes[0].token("mint", grpId, mint0_0, 1000)
        assert(self.nodes[0].token("balance", grpId) == 2000)
        self.checkTokenInfo(self.nodes[0], grpId, "", "", "", "", 2000)
        # mint to a foreign address
        self.nodes[0].token("mint", grpId, mint1_0, 1000)
        assert(self.nodes[0].token("balance", grpId) == 2000)
        self.checkTokenInfo(self.nodes[0], grpId,"","","","", 2000)

        # TODO: what happens here to foreign address minting? 
        # print("node 1 balance " + str( self.nodes[1].token("balance", grpId)))
          # add more tests for foreign address?

        # mint but node does not have authority
        try:
            self.nodes[0].token("mint", grp2Id, mint0_0, 1000)
        except JSONRPCException as e:
            assert("To mint coins, an authority output with mint capability is needed." in e.error["message"])

        # mint but node does not have anything to spend
        try:
            self.nodes[1].token("mint", grp1Id, mint0_0, 1000)
        except JSONRPCException as e:
            assert("Not enough funds for fee" in e.error["message"])

        # In this python test we periodically consolidate all txns in the main wallet which should have
        # no effect on any tokens in the wallet
        logging.info("Consolidating " + str(len(self.nodes[0].listunspent(0))))
        self.nodes[0].consolidate(5000, 1)

        # mint from node 2 of group created by node 0 on behalf of node 2
        self.sync_all()  # node 2 has to be able to see the group new tx that node 0 made
        assert(self.nodes[2].token("balance", grp2Id) == 0)
        tx = self.nodes[2].token("mint", grp2Id, mint2_0, 1000)
        txjson = self.nodes[2].decoderawtransaction(self.nodes[2].getrawtransaction(tx))

        tx = self.nodes[2].token("mint", grp2Id, mint0_0, 100)
        waitFor(30, lambda: self.nodes[2].token("balance", grp2Id) == 1000) # check proper token balance
        self.checkTokenInfo(self.nodes[2], grp2Id, "","","","", 1000)
        self.sync_all()  # node 0 has to be able to see the mint tx that node 2 made
        assert(self.nodes[0].token("balance", grp2Id) == 100)   # on both nodes
        # This should fail because the grp2Id was created for an address on node[2]
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id, "","","","", 100)
            assert False
        except:
            pass
        tx = self.nodes[2].token("mint", grp2Id, mint0_0, 100)
        self.sync_all()  # node 0 has to be able to see the mint tx that node 2 made
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 200)
        # This should fail because the grp2Id was created for an address on node[2]
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id, "","","","", 200)
            assert False
        except:
            pass
        # check that a different token group doesn't count toward balance
        tx = self.nodes[0].token("mint", grpId, mint0_0, 1000)
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 200)
        # This should fail because the grp2Id was created for an address on node[2]
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id, "","","","", 200)
            assert False
        except:
            pass

        try:  # melt without authority
            self.nodes[0].token("melt", grp2Id, 200)  # I should not be able to melt without authority
            assert(0)
        except JSONRPCException as e:
            assert("To melt coins, an authority output with melt capability is needed." in e.error["message"])
            pass

        try:  # melt too much
            self.nodes[2].token("melt", grp2Id, 2000)
            assert(0)
        except JSONRPCException as e:
            assert("Not enough tokens in the wallet." in e.error["message"])

        try:  # melt too little
            self.nodes[2].token("melt", grp2Id, 0)
            assert(0)
        except JSONRPCException as e:
            print(str(e.error["message"]))
            assert("Token melt amount must be greater than zero" in e.error["message"])

        try:  # melt too little
            self.nodes[2].token("melt", grp2Id, -1)
            assert(0)
        except JSONRPCException as e:
            assert("Token melt amount must be greater than zero" in e.error["message"])

        try:  # melt too little
            self.nodes[2].token("melt", grp2Id, "A")
            assert(0)
        except JSONRPCException as e:
            assert("Token melt amount must be greater than zero" in e.error["message"])

        try:  # melt too many params
            self.nodes[2].token("melt", grp2Id, 1, 2)
            assert(0)
        except JSONRPCException as e:
            assert("Invalid number of arguments for token melt" in e.error["message"])

        try:  # melt with invalid group id
            self.nodes[2].token("melt", "invalidgroupid", 1)
            assert(0)
        except JSONRPCException as e:
            assert("Invalid parameter: No group specified" in e.error["message"])

        self.nodes[2].token("melt", grp2Id, 100)
        waitFor(30, lambda: self.nodes[2].token("balance", grp2Id) == 900)

        try:  # send too much
            self.nodes[2].token("send", grp2Id, mint0_0, 1000)
            assert(0)
        except JSONRPCException as e:
            assert("Not enough tokens in the wallet." in e.error["message"])

        waitFor(30, lambda: self.nodes[2].token("balance", grp2Id) == 900)
        tx = self.nodes[2].token("send", grp2Id, mint0_0, 100)
        self.examineTx(tx, self.nodes[2])
        self.sync_all()
        waitFor(30, lambda: self.nodes[0].token("balance", grp2Id, mint0_0) == 300)
        waitFor(30, lambda: self.nodes[2].token("balance", grp2Id) == 800)
        # This should fail because the grp2Id was created for an address on node[2]
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id, "","","","", 300)
            assert False
        except:
            pass
        self.checkTokenInfo(self.nodes[2], grp2Id, "","","","", 800)

        # In this python test we periodically consolidate all txns in the main wallet which should have
        # no effect on any tokens in the wallet
        logging.info("Consolidating " + str(len(self.nodes[0].listunspent(0))))
        self.nodes[0].consolidate(5000, 1)

        self.nodes[0].generate(1)
        self.sync_blocks()
        # no balances should change after generating a block
        assert(self.nodes[0].token("balance", grp2Id, mint0_0) == 300)
        assert(self.nodes[2].token("balance", grp2Id) == 800)
        assert(self.nodes[0].token("balance", grpId) == 3000)
        assert(self.nodes[1].token("balance", grpId) == 1000)
        # This should fail because the grp2Id was created for an address on node[2]
        try:
            self.checkTokenInfo(self.nodes[0], grp2Id, "","","","", 300)
            assert False
        except:
            pass
        self.checkTokenInfo(self.nodes[2], grp2Id, "","","","", 800)
        self.checkTokenInfo(self.nodes[0], grpId, "","","","", 3000)
        # This should fail because the grp2Id was created for an address on node[0]
        try:
            self.checkTokenInfo(self.nodes[1], grpId, "","","","", 1000)
            assert False
        except:
            pass

        try: # not going to work because this wallet has 0 native crypto
            self.nodes[1].token("send", grpId, mint2_0, 10)
        except JSONRPCException as e:
            # print(e.error["message"])
            assert("Not enough funds for fee" in e.error["message"])

        # test multiple destinations
        self.nodes[0].token("mint", grp0Id, mint0_0, 310, mint1_0, 20, mint2_0, 30)
        self.nodes[0].token("send", grp0Id, mint1_0, 100, mint2_0, 200)
        self.sync_all()
        assert(self.nodes[0].token("balance", grp0Id) == 10)
        assert(self.nodes[1].token("balance", grp0Id) == 120)
        assert(self.nodes[2].token("balance", grp0Id) == 230)
        self.checkTokenInfo(self.nodes[0], grp0Id, "","","","", 10)
        # This should fail because the grp2Id was created for an address on node[0]
        try:
            self.checkTokenInfo(self.nodes[1], grp0Id, "","","","", 120)
            assert False
        except:
            pass
        # This should fail because the grp2Id was created for an address on node[0]
        try:
            self.checkTokenInfo(self.nodes[2], grp0Id, "","","","", 230)
            assert False
        except:
            pass

        n2addr = self.nodes[2].getnewaddress()
        logging.info("melt authority")
        # create melt authority and pass it to node 1
        self.nodes[0].token("authority", "create", grp0Id, n2addr, "MELT", "NOCHILD")
        self.sync_all()
        try:
            # I gave melt, not mint
            self.nodes[2].token("mint", grp0Id, n2addr, 1000)
        except JSONRPCException as e:
            assert("To mint coins, an authority output with mint capability is needed." in e.error["message"])

        # In this python test we periodically consolidate all txns in the main wallet which should have
        # no effect on any tokens in the wallet
        logging.info("Consolidating " + str(len(self.nodes[0].listunspent(0))))
        self.nodes[0].consolidate(5000, 1)

        # melt some of my tokens
        logging.info("melt")
        self.nodes[2].token("melt", grp0Id, 100)
        waitFor(30, lambda: self.nodes[2].token("balance", grp0Id) == 130)
        try:  # test that the NOCHILD authority worked -- I should only have the opportunity to melt once
            self.nodes[2].token("melt", grp0Id, 10)
        except JSONRPCException as e:
            assert("To melt coins")

        self.subgroupTest()
        self.descDocTest()
        self.decimalDescTest()


        ### Test that the instant transaction delay works for tokens
        # 1) Send a token from node2 to a new address on node2.  Even with
        #    and instantdelay setting the balance should update immmediately because
        #    the sourc of the tokens is ourselves and is trusted.
        # 2) Send a token from one node to another. The instant delay should be in effect.
        logging.info("testing instant transactions")
        instantDelay = 3
        self.nodes[0].set("wallet.instantDelay=3");
        self.nodes[1].set("wallet.instantDelay=3");
        self.nodes[2].set("wallet.instantDelay=3");

        # Send to our own node - there should be no instant delay
        addr1 = self.nodes[2].getnewaddress()
        self.nodes[2].token("send", grp2Id, addr1, 100)
        assert(self.nodes[2].token("balance", grp2Id, addr1) == 100)

        # Send to another node - the instant delay should be visible
        addr2 = self.nodes[2].getnewaddress()
        self.nodes[0].token("send", grp0Id, addr2, 10)
        time.sleep(instantDelay - 1) # wait until just before the delay expires
        assert(self.nodes[2].token("balance", grp0Id, addr2) == 0)
        time.sleep(1) # wait the last second and the balance should update
        assert(self.nodes[2].token("balance", grp0Id, addr2) == 10)


        ### Test instant transactions for tokens can be turned off.
        #   1) send tokens back to node0 and observer that the balance does not
        #      update after the instantDelay has expired
        self.nodes[0].set("wallet.instant=false");
        self.nodes[1].set("wallet.instant=false");
        self.nodes[2].set("wallet.instant=false");

        addr3 = self.nodes[0].getnewaddress()
        self.nodes[2].token("send", grp0Id, addr3, 25)
        time.sleep(instantDelay + 1) # wait one second extra to be sure
        assert(self.nodes[0].token("balance", grp0Id, addr3) == 0)
        
        # generate a block and the balance should now update
        self.nodes[0].generate(1)
        assert(self.nodes[0].token("balance", grp0Id, addr3) == 25)


        logging.info("test complete")


if __name__ == '__main__':
    GroupTokensTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = GroupTokensTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    # you may want these additional flags:
    # "--srcdir=<out-of-source-build-dir>/debug/src"
    # "--tmpdir=/ramdisk/test"
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
