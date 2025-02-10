[Website](https://www.nexa.org) | [Download](https://gitlab.com/nexa/nexa/-/releases) | [Setup](README.md) | [Miner](doc/miner.md) | [ElectronCash](doc/bu-electrum-integration.md)

[![Build Status](https://gitlab.com/nexa/nexa/badges/dev/pipeline.svg?key_text=Build%20Status%20%28dev%29&key_width=110)](https://gitlab.com/nexa/nexa/-/pipelines)

<a href="https://www.producthunt.com/posts/nexa-full-node-coins-tokens-and-nfts?utm_source=badge-featured&utm_medium=badge&utm_souce=badge-nexa&#0045;full&#0045;node&#0045;coins&#0045;tokens&#0045;and&#0045;nfts" target="_blank"><img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=452361&theme=light" alt="Nexa&#0032;Full&#0032;Node&#0044;&#0032;coins&#0044;&#0032;tokens&#0032;and&#0032;NFTs - A&#0032;digital&#0032;economy&#0032;with&#0032;capacity&#0032;for&#0032;all&#0046;&#0032;Smart&#0032;contracts | Product Hunt" style="width: 250px; height: 54px;" width="250" height="54" /></a>

# What is Nexa?

Nexa is an experimental financial blockchain and digital currency.  It updates the Bitcoin codebase to enable more transactions per block, advanced scripting, and miner validated (native) fungible and non-fungible tokens.

Bitcoin can be considered digital gold, while Ethereum is a massively redundant computer that primarily implements financial contracts.  

Nexa positions itself differently -- like Bitcoin, it has a sound money coin distribution, but it supports use as a currency via its massive layer one scalability via dynamic block sizes, double-spend notifications, deep unconfirmed transaction chains, and 2 minute average block discovery times.  

It has smart contracting features like Ethereum, but is not a full turing-complete language.  This and its Bitcoin-like UTXO model allows for massive parallelization of transaction processing.  Financial and cryptographic functions (namely tokens, "fenced" nexa, and large integers) are implemented as fundamental blockchain primitives, allowing for very size and time efficient implementations of financial operations.

Nexa's primary goal is to be a financial blockchain -- to allow diverse financial instruments to be created, owned, tracked, and to interact on a peer-to-peer, permissionless, trust-free, pseudo-anonymous, and decentralized ledger.

For more general information see [www.nexa.org](https://www.nexa.org).  For protocol specifications see [spec.nexa.org](https://spec.nexa.org).

# Installing

For info on installing Nexa see [INSTALL.md](INSTALL.md)

# Building

For info on building Bitcoin Unlimited from sources, see
- [Dependencies](doc/dependencies.md)
- [Unix Build Notes](doc/build-unix.md)
- [Unix Build Notes (RPM)](doc/build-unix-rpm.md)
- [Windows Build Notes](doc/build-windows.md)
- [OpenBSD Build Notes](doc/build-openbsd.md)
- [macOS Build Notes](doc/build-macos.md)
- [Alpine Build Notes](doc/build-alpine.md)
- [Deterministic macOS DMG Notes](doc/README_macos.md)
- [Gitian Building Guide](doc/gitian-building.md)

They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

# Running / setup

- [Running an electron cash protocol server](doc/bu-electrum-integration.md)
- [Tor Support](doc/tor.md)
- [Init Scripts (systemd/upstart/openrc)](doc/init.md)
- [Using Nexa for mining](doc/miner.md)

# Development

- [Developer Notes](doc/developer-notes.md)
- [Contributing](CONTRIBUTING.md)
- [Multiwallet Qt Development](doc/multiwallet-qt.md)
- [Release Notes](doc/release-notes.md)
- [Release Process](doc/release-process.md)
- [Translation Process](doc/translation_process.md)
- [Translation Strings Policy](doc/translation_strings_policy.md)
- [Unit Tests](doc/unit-tests.md)
- [Unauthenticated REST Interface](doc/REST-interface.md)
- [Shared Libraries](doc/shared-libraries.md)
- [Assets Attribution](contrib/debian/copyright)
- [Files](doc/files.md)
- [Fuzz-testing](doc/fuzzing.md)


# Online resources

 - [Issue Tracker](https://gitlab.com/BitcoinUnlimited/BitcoinUnlimited/issues)
 - [The Nexa Forum](https://forum.bitcoinunlimited.info/forum)

# Nexa Specification

The comprehensive specification of the Nexa protocol could be found at either of the following:
- [Specification Gitlab](https://gitlab.com/nexa/specfication)
- [Specification Website](https://spec.nexa.org)

# License

Nexa is released under the terms of the [MIT software license](http://www.opensource.org/licenses/mit-license.php). See [COPYING](COPYING) for more
information.

This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
