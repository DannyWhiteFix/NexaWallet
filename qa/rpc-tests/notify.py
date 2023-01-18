#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test -alertnotify -walletnotify and -blocknotify
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class NotifyTest(BitcoinTestFramework):

    alert_filename = None  # Set by setup_network

    def setup_network(self):
        self.nodes = []
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        logging.info("Alert file is: " + self.alert_filename)
        with open(self.alert_filename, 'w') as f:
            pass  # Just open then close to create zero-length file
        self.nodes.append(start_node(0, self.options.tmpdir,
                            ["-alertnotify=echo %s >> \"" + self.alert_filename + "\""]))
        # Node1 mines block.version=211 blocks
        self.nodes.append(start_node(1, self.options.tmpdir,
                                []))
        connect_nodes(self.nodes[1], 0)

        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        ########################################
        # Run blocknotify and alertnotify tests.
        ########################################

        self.nodes[0].issuealert("this is an alert")
        time.sleep(1)
        with open(self.alert_filename, 'r') as f:
            alert_text = f.read()

        if len(alert_text) == 0:
            raise AssertionError("-alertnotify did not work")

        stop_nodes(self.nodes)
        wait_bitcoinds()

        ####################################################################
        # Run blocknotify and walletnotify tests.
        # Create new files when a block is received or wallet event happens.
        ####################################################################
        logging.info("touch check 1")
        self.touch_filename1 = os.path.join(self.options.tmpdir, "newfile1")
        self.touch_filename2 = os.path.join(self.options.tmpdir, "newfile2")
        self.touch_filename3 = os.path.join(self.options.tmpdir, "newfile3")
        self.touch_filename4 = os.path.join(self.options.tmpdir, "newfile4")
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-blocknotify=touch " + self.touch_filename1, "-walletnotify=touch " + self.touch_filename2]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-blocknotify=touch " + self.touch_filename3, "-walletnotify=touch " + self.touch_filename4]))
        connect_nodes(self.nodes[1], 0)
        self.is_network_split = False

        # check files not created after startup
        logging.info("touch check 2")
        waitFor(10, lambda: os.path.isfile(self.touch_filename1) == False)
        waitFor(10, lambda: os.path.isfile(self.touch_filename2) == False)
        waitFor(10, lambda: os.path.isfile(self.touch_filename3) == False)
        waitFor(10, lambda: os.path.isfile(self.touch_filename4) == False)

        # mine a block. Both nodes should have created a file: newfile1 and newfile3.
        logging.info("generate")
        self.nodes[1].generate(1)
        logging.info("sync")
        self.sync_all()
        logging.info("sleep")
        time.sleep(1)
        
        logging.info("touch check 3")
        
        # check blocknotify - both nodes should have run the blocknotify command.
        waitFor(10, lambda: os.path.isfile(self.touch_filename1) == True)
        waitFor(10, lambda: os.path.isfile(self.touch_filename3) == True)
        os.remove(self.touch_filename1)
        os.remove(self.touch_filename3)

        # walletnotify will have been run on node1 because we just mined a block there and so
        # have coins in the wallet that were just added.
        waitFor(10, lambda: os.path.isfile(self.touch_filename4) == True)
        os.remove(self.touch_filename4)

        # check walletnotify - send a transaction from node1 to itself. Only node1 should have run
        # the walletnotify command.
        logging.info("generate 100")
        self.nodes[1].generate(100)
        logging.info("sync")
        self.sync_all()
        logging.info("sync done")
        address = self.nodes[1].getnewaddress("test1")
        logging.info("getnewaddress done")
        txid = self.nodes[1].sendtoaddress(address, 100, "", "", True)
        sync_mempools(self.nodes)
        logging.info("sync_mempools done")
        waitFor(10, lambda: os.path.isfile(self.touch_filename2) == False)
        waitFor(10, lambda: os.path.isfile(self.touch_filename4) == True)
        os.remove(self.touch_filename4)

        # check walletnotify - send a transaction from node1 to node0. Both nodes should have run
        # the walletnotify command.
        address2 = self.nodes[0].getnewaddress("test2")
        txid = self.nodes[1].sendtoaddress(address2, 100, "", "", True)
        sync_mempools(self.nodes)
        waitFor(10, lambda: os.path.isfile(self.touch_filename2) == True)
        waitFor(10, lambda: os.path.isfile(self.touch_filename4) == True)
        os.remove(self.touch_filename2)
        os.remove(self.touch_filename4)


if __name__ == '__main__':
    NotifyTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = NotifyTest()
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
