# Installing Nexa

This document describes how to install and configure Nexa.

# Downloading Nexa

If you just want to run the Nexa software go to the
[Download](https://gitlab.com/nexa/nexa/-/releases/) page and get the relevant
files for your system.

If you are moving from another Nexa compatible implementation, make sure to follow this plan before moving:

- backup your wallet (if any)
- make a backup of the `~/.nexa` dir
- if you have installed nexa via apt using the ppa nexa repo:
   - `sudo apt-get remove nexa*`
   - `sudo rm /etc/apt/sources.list.d/nexa-*.*`
- if you have compile Nexa from source:
   - `cd /path/where/the/code/is/stored`
   - `sudo make uninstall`


## Windows

You can choose

- Download the setup file (exe), and run the setup program, or
- download the (zip) file, unpack the files into a directory, and then run nexa-qt.exe.


## Linux / Unix

Unpack the files into a directory and run:

- `bin/nexa-qt` (GUI) or
- `bin/nexad` (headless)

## macOS

Drag Nexa to your applications folder, and then run Nexa.

[comment]: # (# Installing Ubuntu binaries from Bitcoin Unlimited Official BU repositories)
[comment]: # ()
[comment]: # (If you're running an Ubuntu system you can install Bitcoin Unlimited from the official BU repository.)
[comment]: # (The repository will provide binaries and debug symbols for 4 different architectures: i386, amd64, armhf and arm64. From a terminal do)
[comment]: # ()
[comment]: # ()
[comment]: # (```sh)
[comment]: # (sudo apt-get install software-properties-common)
[comment]: # (sudo add-apt-repository ppa:bitcoin-unlimited/bu-ppa)
[comment]: # (sudo apt-get update)
[comment]: # (sudo apt-get install nexad nexa-qt (# on headlesse server just install nexad))
[comment]: # (```)
[comment]: # ()
[comment]: # (Once installed you can run `nexad` or `nexa-qt`)


# Building Nexa from source

See doc/build-*.md for detailed instructions on building the Nexa software for your specific architecture. Includes both info on building 
- `nexad`, the intended-for-services, no-graphical-interface, implementation of Nexa and 
- `nexa-qt`, the GUI.

Once you have finished the process you can find the relevant binary files (`nexad`, `nexa-qt` and `nexa-cli`) in `/src/`.


## Dependencies

Make sure you have installed the [Dependencies](doc/Dependencies.md).

If you're compiling from source on a Ubuntu like system, you can get all the required dependencies with the commands below

```sh
sudo apt-get install git build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev

## optional: only needed if you want nexa-qt
sudo apt-get install qttools5-dev-tools qttools5-dev libprotobuf-dev protobuf-compiler libqrencode-dev

## Fetching the code and compile it

```sh
git clone https://gitlab.com/nexa/nexa.git nexa
cd nexa
git checkout release 	# or git checkout origin/dev
./autogen.sh

# if you want a plain nexad binary without GUI and without wallet support, use this configure line:
./configure --disable-wallet --without-gui

# otherwise if you need nexa-qt just issue
./configure

export NUMCPUS=`grep -c '^processor' /proc/cpuinfo`
make -j$NUMCPUS
sudo make install #(will place them in /usr/local/bin, this step is to be considered optional.)
```

## Miscellaneous


- `strip(1)` your binaries, nexad will get a lot smaller, from 73MB to 4.3MB)
- execute `nexad` using the `-daemon` option, bash will fork nexa process without cluttering the stdout



# Quick Startup and Initial Node operation

## QT or the command line:

There are two modes of operation, one uses the QT UI and the other runs as a daemon from the command line.  The QT version is nexa-qt or nexa-qt.exe, the command line version is nexad or nexad.exe. No matter which version you run, when you launch for the first time you will have to complete the intial blockchain sync.

## Initial Sync of the blockchain:

When you first run the node it must first sync the current blockchain.  All block headers are first retrieved and then each block is downloaded, checked and the UTXO finally updated.  This process can take from hours to *weeks* depending on the node configuration, and therefore, node configuration is crucial.

The most important configuration which impacts the speed of the initial sync is the `cache.dbcache` setting.  The larger the dbcache the faster the initial sync will be, therefore, it is vital to make this setting as high as possible.  If you are running on a Windows machine there is an automatically adjusting dbcache setting built in; it will size the dbcache in such a way as to leave only 10% of the physical memory free for other uses.  On Linux and other OS's the sizing is such that one half the physical RAM will be used as dbcache. While these settings, particularly on non Windows setups, are not ideal they will help to improve the initial sync dramatically.

However, even with the automatic configuration of the `cache.dbcache` setting it is recommended to set one manually if you haven't already done so (see the section below on Startup Configuration). This gives the node operator more control over memory use and in particular for non Windows setups, can further improve the performance of the initial sync.

## Startup configuration:

There are dozens of configuration and node policy options available but the two most important for the initial blockchain sync are as follows.

### dbcache:

As stated above, this setting is crucial to a fast initial sync. If you don't configure any value then the system
will automatically adjust this size for you, more or less. On windows the auto adjustment works very well and will rise and fall with your nodes needs, however, on linux/maxOS the adjustments are not as granular and so if your a power user
you will likely want to manually configure your dbcache settings.

You can set this value manually from the command line (or adding it to your nexa.conf) by running
```
nexad -cache.dbcache=<your size in MB>
```
For example, a 1GB dbcache would be 
```
nexad -cache.dbcache=1000
```
Similarly you can also add the setting to the nexa.conf file located in your installation folder. In the config file a simlilar entry would be

 > `cache.dbcache=1000`

When entering the size
try to give it the maximum that your system can afford while still leaving enough memory for other processes.

### Getting enough network connections:

It is generally fine to leave the default inbound/outbound connection settings for doing a sync, however, at times some users have reported issues with not being able to find any useful connections. This is often a problem because too many nodes are looking for outbound connections but node operators have forgotten to configure for allowing inbound connections (if nobody allows inbound connections then there would be no network connectivity for anyone).

Note that you must have connections to the network in order to send or receive coins from you wallet!

#### Port forwarding:

To get inbound connections for Nexa require that port 7228 be port forwarded

#### UPnP:

Port forrwarding is considered the better option, but if you don't want to setup port fowarding then you need to configure your router with UPnP turned on and then also turn on UPnP on nexad (-upnp=1), however, UPnP can be a security risk and so it is usually turned off by default on your router.

### Wallet Options

#### Paying a higher fee

Generally you don't need to make any changes to the default wallet configuration but when blocks become full for long periods of time, such as when exchanges consolidate dust, it can take a while to get your transactions to confirm. But by sending your transactions with a little higher fee than the minimum you can generally get confirmed in the next block.  The minimum fee is currently set at 1000 sat/byte however you can raise that fee by using the `wallet.payTxFee=<fee per Kb>` argument in your nexa.conf, or from the command line, and set it to something higher than 1000. By doing this your transactions will be mined before any lower fee transactions and so get confirmed quickly.

#### Using automatic fee estimation

If you don't want to set a fee you can use the fee estimator which will automatically try to figure out what the best fee would be to get a quick confirmation. To use this feature you can set `wallet.feeEstimation=1` in your nexa.conf or `-wallet.feeEstimation=1` from the command line.

#### Setting maximum fees

The Nexa wallet will limit your maximum fee you can add by default 10000 sat/byte, but if you prefer to set the value much lower you can with the `wallet.maxTxFee=<your max fee>` setting. Using this can protect you from accidentally sending very large fees, particularly if you are generating your own raw transactions.


# Getting help

 - [Issue Tracker](https://gitlab.com/nexa/nexa/issues)
 - [Reddit /r/nexa](https://www.reddit.com/r/nexa)


