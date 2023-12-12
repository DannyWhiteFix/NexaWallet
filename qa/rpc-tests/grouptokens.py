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
        #self.nodes = start_nodes(3, self.options.tmpdir)

        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=mempool"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=mempool"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug=mempool"]))

        # Now interconnect the nodes
        #connect_nodes_bi(self.nodes, 0, 1)
        #connect_nodes_bi(self.nodes, 0, 2)
        #connect_nodes_bi(self.nodes, 1, 2)
        interconnect_nodes(self.nodes)
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

    def checkTokenInfo(self, node, grpId, ticker="", name="", url="", url_hash="", balance="0", mintage=0):
        info = node.token("info")
        if (grpId not in info):
            raise Exception("Group Id not found")

        assert_equal(info[grpId]['ticker'], ticker)
        assert_equal(info[grpId]['name'], name)
        assert_equal(info[grpId]['url'], url)
        assert_equal(info[grpId]['hash'], url_hash)
        assert_equal(info[grpId]['balance'], balance)
        assert_equal(info[grpId]['mintage'], mintage)

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
        assert_equal(info[grpId]['mintage'], mintage)


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
        waitFor(30, lambda: self.nodes[0].token("mintage", sg1a), 0);
        tx = self.nodes[0].token("mint",sg1a, addr2, 100)
        waitFor(30, lambda: tx in self.nodes[2].getrawtxpool())  # If this fails, remember that there's a very rare chance that a tx won't propagate due to an inv bloom filter collision.
        assert_equal(self.nodes[2].token("balance", sg1a), 100)
        assert_equal(self.nodes[2].token("balance", grp1), 0)

        # check mintages are correct
        waitFor(30, lambda: self.nodes[0].token("mintage", sg1a), 100);
        waitFor(30, lambda: self.nodes[2].token("mintage", sg1a), 100);

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
            t = self.nodes[0].token("new", "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a6") # missing one character to the uint256 hash
            assert False  # should be an invalid uint256 message
        except JSONRPCException as e:
            assert("is not a uint256" in e.error['message'])
        try:
            t = self.nodes[0].token("new", "TICK2", "AnotherNameGoesHere", "https://www.nexa.org/smthing", "1296fdd732e34fa750256095bb68dcd78091c49ab9382a35dce89ea15e055a6aa") # one character too many for the uint256 hash
            assert False  # should be an invalid uint256 message
        except JSONRPCException as e:
            assert("is not a uint256" in e.error['message'])
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
            assert("Insufficient funds for this token." in e.error["message"])

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
        self.checkTokenInfo(self.nodes[2], grp2Id, "","","","", 800, 1100)
        self.checkTokenInfo(self.nodes[0], grpId, "","","","", 3000, 4000)
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
        self.nodes[0].generate(1)
        self.sync_blocks()
        self.nodes[2].generate(1)
        self.sync_blocks()

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
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()
        self.nodes[0].generate(2)
        self.sync_blocks()

        instantDelay = 3
        self.nodes[0].set("wallet.instantDelay=3");
        self.nodes[1].set("wallet.instantDelay=3");
        self.nodes[2].set("wallet.instantDelay=3");

        # Send to our own node - there should be no instant delay
        addr1 = self.nodes[2].getnewaddress()
        self.nodes[2].token("send", grp2Id, addr1, 100)
        startTime = time.time()
        endTime = startTime
        totalTimeAllowed = startTime + instantDelay
        while ((self.nodes[2].token("balance", grp2Id, addr1) != 100) and (endTime < totalTimeAllowed)):
            time.sleep(0.1)
            endTime = time.time()
        assert(endTime <= totalTimeAllowed)
        self.sync_all()

        # Send to another node - the instant delay should be visible
        addr2 = self.nodes[2].getnewaddress()
        self.nodes[0].generate(1)
        self.sync_blocks()
        self.nodes[0].token("send", grp0Id, addr2, 10)
        while (self.nodes[2].gettxpoolinfo()['size'] == 0):
            time.sleep(.1)
        time.sleep(instantDelay - 1.5) # wait until just before the delay expires
        assert_equal(self.nodes[2].token("balance", grp0Id, addr2), 0)
        time.sleep(1.5) # wait the last second and the balance should update (wait just a little longer for the tx to get into the txpool)
        assert_equal(self.nodes[2].token("balance", grp0Id, addr2), 10)


        ### Test instant transactions for tokens can be turned off.
        #   1) send tokens back to node0 and observer that the balance does not
        #      update after the instantDelay has expired
        self.nodes[0].set("wallet.instant=false");
        self.nodes[1].set("wallet.instant=false");
        self.nodes[2].set("wallet.instant=false");

        addr3 = self.nodes[0].getnewaddress()
        self.nodes[2].token("send", grp0Id, addr3, 25)
        self.sync_all()
        time.sleep(instantDelay + 1) # wait one second extra to be sure
        assert(self.nodes[0].token("balance", grp0Id, addr3) == 0)

        # generate a block and the balance should now update
        self.nodes[0].generate(1)
        assert(self.nodes[0].token("balance", grp0Id, addr3) == 25)


        # Check mint/melt is updated correctly
        #
        # When minting or melting the "mintage" value should not update until a block is mined.
        # Also need to check that rolling back blocks updates the "mintage" correctly
        logging.info("testing mintage tracking")

        # create 2 new groups to use
        t = self.nodes[0].token("new")
        grp_node0 = t["groupIdentifier"]
        t = self.nodes[2].token("new")
        grp_node2 = t["groupIdentifier"]
 

        # check mintages are correct for single mint
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        self.nodes[0].token("mint", grp_node0, mint0_0, 100)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 0)
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        self.nodes[0].generate(1);
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 100)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 100)

        # check mintages are correct for single melt
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        self.nodes[0].token("melt", grp_node0, 10)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 0)
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        self.nodes[0].generate(1);
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 - 10)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 - 10)


        # check mintages are correct for multiple mints
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        mintage2 = self.nodes[2].token("mintage", grp_node2)
        self.nodes[0].token("mint", grp_node0, mint0_0, 100)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1)
        self.nodes[0].token("mint", grp_node0, mint0_0, 1)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 2)
        self.nodes[2].token("mint", grp_node2, mint2_0, 1400)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 3)
        self.nodes[2].token("mint", grp_node2, mint2_0, 100)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 4)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == mintage2 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == mintage2 + 0)
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        mintage2 = self.nodes[2].token("mintage", grp_node2)

        self.sync_all()
        self.nodes[0].generate(1);
        self.sync_blocks()
        self.nodes[2].generate(1);
        self.sync_blocks()

        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 101)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 101)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == mintage2 + 1500)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == mintage2 + 1500)

        # check mintages are correct for multiple mints/melts
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        mintage2 = self.nodes[2].token("mintage", grp_node2)
        # Need to add small waits or checks to the mempool because after mint/melt we need the
        # authority to be in the txpool so we can create the next mint or melt.
        self.nodes[0].token("mint", grp_node0, mint0_0, 100)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1)
        self.nodes[0].token("melt", grp_node0, 99)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 2)
        self.nodes[0].token("mint", grp_node0, mint0_0, 10)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 3)
        self.nodes[0].token("melt", grp_node0, 2)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 4)
        self.nodes[2].token("melt", grp_node2, 10)
        waitFor(30, lambda: self.nodes[0].gettxpoolinfo()['size'] == 5)
        self.nodes[2].token("mint", grp_node2, mint2_0, 1400)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 6)
        self.nodes[2].token("melt", grp_node2, 10)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 7)
        self.nodes[2].token("melt", grp_node2, 10)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 8)
        self.nodes[2].token("melt", grp_node2, 13)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 9)
        self.nodes[2].token("mint", grp_node2, mint2_0, 100)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 10)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 0)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == mintage2 + 0)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == mintage2 + 0)
        mintage0 = self.nodes[0].token("mintage", grp_node0)
        mintage2 = self.nodes[2].token("mintage", grp_node2)

        self.sync_all()
        self.nodes[0].generate(1);
        self.sync_blocks()
        self.nodes[2].generate(1);
        self.sync_blocks()

        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 9)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 9)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == mintage2 + 1457)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == mintage2 + 1457)

        # stop and start nodes and make sure mintages are still available
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(3, self.options.tmpdir)
        interconnect_nodes(self.nodes)
        self.sync_blocks()
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == mintage0 + 9)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node0) == mintage0 + 9)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == mintage2 + 1457)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == mintage2 + 1457)


        # Melt all tokens
        balance0 = self.nodes[0].token("balance", grp_node0)
        mintage0 = self.nodes[0].token("mintage", grp_node0)

        balance2 = self.nodes[2].token("balance", grp_node2)
        mintage2 = self.nodes[2].token("mintage", grp_node2)
        assert_equal(balance0, mintage0);
        assert_equal(balance2, mintage2);

        self.nodes[0].token("melt", grp_node0, balance0)
        self.nodes[2].token("melt", grp_node2, balance2)
        self.sync_all()
        self.nodes[0].generate(1);
        self.sync_blocks()
        self.nodes[2].generate(1);
        self.sync_blocks()
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node0) == 0)
        waitFor(30, lambda: self.nodes[0].token("mintage", grp_node2) == 0)

        logging.info("testing mintage tracking with rollback and reorg")

        self.nodes[2].token("mint", grp_node2, mint2_0, 1500)
        self.nodes[2].generate(1);
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == 1500)
        self.nodes[2].token("mint", grp_node2, mint2_0, 100)
        self.nodes[2].generate(1);
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == 1600)
        self.nodes[2].token("melt", grp_node2, 5)
        self.nodes[2].generate(1);
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == 1595)
        self.nodes[2].token("melt", grp_node2, 10)
        self.nodes[2].generate(1);
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == 1585)

        # undo the last melts of coins on node2
        mintage = self.nodes[2].token("mintage", grp_node2)
        self.nodes[2].invalidateblock(self.nodes[2].getbestblockhash())
        mintageafter = self.nodes[2].token("mintage", grp_node2)
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == mintage + 10)

        mintage = self.nodes[2].token("mintage", grp_node2)
        self.nodes[2].invalidateblock(self.nodes[2].getbestblockhash())
        mintageafter = self.nodes[2].token("mintage", grp_node2)
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == mintage + 5)

        # undo the last mints of coins on node2
        mintage = self.nodes[2].token("mintage", grp_node2)
        self.nodes[2].invalidateblock(self.nodes[2].getbestblockhash())
        mintageafter = self.nodes[2].token("mintage", grp_node2)
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == mintage - 100)

        mintage = self.nodes[2].token("mintage", grp_node2)
        self.nodes[2].invalidateblock(self.nodes[2].getbestblockhash())
        mintageafter = self.nodes[2].token("mintage", grp_node2)
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == mintage - 1500)
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == 0)

        # create a new chain by mining a block.  The 4 mint/melt transactions will be
        # in the txpool and when mined will return the mintage for this token to its value
        # before we started invalidating blocks.
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'] == 4)
        self.nodes[2].generate(1);
        mintageafter = self.nodes[2].token("mintage", grp_node2)
        waitFor(30, lambda: self.nodes[2].token("mintage", grp_node2) == 1585)

        # Now finally invalidate this last block which has all 4 mint/melt txns
        # Result:  we should be back to a mintage of zero!
        self.nodes[2].invalidateblock(self.nodes[2].getbestblockhash())
        waitFor(10, lambda: self.nodes[2].token("mintage", grp_node2) == 0)

        ### Check authority tracking is updated correctly

        # Check new creation authority shows up
        logging.info("testing authority tracking")
        self.nodes[2].reconsidermostworkchain()
        self.sync_blocks()

        # Create basic token and check that the authority is tracked
        authGrpId1 = self.nodes[2].token("new", "NEXA", "NEXA.org" "" "" "2")["groupIdentifier"]  
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        try:
            self.nodes[2].token("authority", "count", authGrpId1)["mint"]
            assert(0)  # should have raised exception
        except JSONRPCException as e:
            assert("Could not find authority information for the token id given" in e.error["message"])
        self.nodes[2].generate(1) # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["subgroup"], "1")

        addr2 = self.nodes[2].getnewaddress()
        self.nodes[2].token("mint", authGrpId1, addr2, 1000)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].token("mint", authGrpId1, addr2, 1200)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 2)
        self.nodes[2].token("mint", authGrpId1, addr2, 100)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 3)
        self.nodes[2].token("melt", authGrpId1, 150)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 4)
        self.nodes[2].generate(1) # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["subgroup"], "1")

        # The new token creation transaction is in the same block as the first mint
        authGrpId2 = self.nodes[2].token("new")["groupIdentifier"]  
        authGrpId3 = self.nodes[2].token("new")["groupIdentifier"]  
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 2)

        addr2 = self.nodes[2].getnewaddress()
        self.nodes[2].token("mint", authGrpId2, addr2, 100)
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].generate(1); # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["subgroup"], "1")

        # Create other authorities and check the counts
        addr2 = self.nodes[2].getnewaddress()
        self.nodes[2].token("authority", "create", authGrpId2, addr2, "mint", "nochild", "rescript")
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].generate(1); # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        addr2 = self.nodes[2].getnewaddress()
        self.nodes[2].token("authority", "create", authGrpId2, addr2, "melt", "rescript")
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].generate(1) # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        # create authority with same receiving address
        self.nodes[2].token("authority", "create", authGrpId2, addr2, "mint", "melt")
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].generate(1) # must mine a block for tracking to update
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        # Check the other group id and its authorities are unaffected by the changes above
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["subgroup"], "1")

        # create a token authority to an address on another peer
        addr0 = self.nodes[0].getnewaddress()
        self.nodes[2].token("authority", "create", authGrpId2, addr0, "mint", "melt", "nochild")
        waitFor(30, lambda: self.nodes[2].gettxpoolinfo()['size'], 1)
        self.nodes[2].generate(1) # must mine a block for tracking to update
        self.sync_blocks()
        assert_equal(self.nodes[0].token("authority", "count", authGrpId1)["mint"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId1)["melt"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId1)["renew"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId1)["rescript"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId1)["subgroup"], "1")

        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId1)["subgroup"], "1")

        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "4")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "4")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        assert_equal(self.nodes[0].token("authority", "count", authGrpId2)["mint"], "4")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId2)["melt"], "4")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId2)["renew"], "3")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId2)["subgroup"], "1")

        assert_equal(self.nodes[0].token("authority", "count", authGrpId3)["mint"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId3)["melt"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId3)["renew"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId3)["rescript"], "1")
        assert_equal(self.nodes[0].token("authority", "count", authGrpId3)["subgroup"], "1")

        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["mint"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["rescript"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId3)["subgroup"], "1")

        logging.info("testing authority tracking with rollback and reorg")
        self.nodes[2].rollbackchain(self.nodes[2].getblockcount() - 1)
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        self.nodes[2].rollbackchain(self.nodes[2].getblockcount() - 1)
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "3")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")

        self.nodes[2].rollbackchain(self.nodes[2].getblockcount() - 1)
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["mint"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["melt"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["renew"], "1")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["rescript"], "2")
        assert_equal(self.nodes[2].token("authority", "count", authGrpId2)["subgroup"], "1")


        logging.info("testing authority tracking after destroying an authority")



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
