[Website](https://www.nexa.org)  | [Download](https://gitlab.com/nexa/nexa/-/releases) | [Setup](../README.md)   |   [Miner](miner.md)  |  [Electrum](electrum-integration.md)  |  [UnconfirmedChains](unconfirmedTxChainLimits.md)

# Electrum Server

## Overview

Nexa includes support for electrum server (Linux x64 only).

The server is maintained as a [separate piece of software](https://gitlab.com/BitcoinUnlimited/Rostrum), but is integrated with the node software. Its process has the same lifetime as the nexad process, uses the same log files and adds functionality to the same RPC interface.  Detailed documentation exists [here](https://gitlab.com/BitcoinUnlimited/Rostrum/blob/master/doc/usage.md).

Running a private electrum server gives you an extended API interface, for example allowing you to lookup transaction history and balances of any address on the blockchain. Having a private electrum server also allows you to use wallet software such as Electron Cash, without compromising your privacy.

By [enabling SSL support](https://gitlab.com/BitcoinUnlimited/Rostrum/blob/master/doc/usage.md) and making the server public, you're able to support the network light client infrastructure, which is run on volunteer basis (you may want to [add it to the server list](https://github.com/Electron-Cash/Electron-Cash/blob/master/lib/servers.json) in that case).  You can make your server public without enabling SSL support, but some light wallet insist on a SSL connection.

## Starting the server

Add `electrum=1` to your nexa.conf file, or pass `-electrum=1` argument to nexad when from command line. You may want to also add `debug=electrum` to enable useful logging.
To allow incoming connections from any wallet, use `electrum.host=0.0.0.0`.  `electrum.port=1234` will change the listening port.  The default port is 20001.  Don't forget to configure your firewall to pass this port though (similar to what you did for nexa port 7227), if you have a firewall/NAT.


The RPC call `getelectruminfo` gives you runtime details, such as indexing status of the server. More detailed metrics are available via Prometheus, see monitoring section of the [usage document](https://gitlab.com/BitcoinUnlimited/Rostrum/blob/master/doc/usage.md).

## Compiling from source

First install dependencies (rust version has to be 1.64+ for the latest stable rostrum version, i.e. 9.0.0):

```sh
sudo apt install python3-git cargo clang
```

If your Linux distro does not provide a recent enough version of rust, just visit https://rustup.rs/ to get the detailed instruction to install it.

The latest stable release used by the node software can be compiled from the Nexa source tree by running

```sh
make rostrum
```

For more recent development versions, see the [usage document](https://gitlab.com/BitcoinUnlimited/Rostrum/blob/master/doc/usage.md).

## Known issues

If you use RPC username/password rather than the default "RPC cookie", the credentials will be logged to `debug.log` by the Rostrum server.

Any public service can suffer from DOS attacks if "the public" chooses to make many or difficult requests into the service.  Ultimately the only "solution" is mitigation since the *purpose* of this service is to offload CPU and storage tasks from light clients.  Although we are working on better efficiency and DOS mitigation, this software should be run separately from other mission-critical software.
