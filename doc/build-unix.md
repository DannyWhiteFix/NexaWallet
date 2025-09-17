# UNIX BUILD NOTES

Some notes on how to build Nexa in Unix. Mostly with at Ubuntu / Debian focus.

For RPM based distros, see [build-unix-rpm.md](build-unix-rpm.md).
For OpenBSD specific instructions, see [build-openbsd.md](build-openbsd.md).
For FreeBSD specific instructions, see [build-freebsd.md](build-freebsd.md).


# Installing dependencies

Run the following to install the base dependencies for building:


```bash
sudo apt-get install build-essential libtool autotools-dev autoconf automake pkg-config libevent-dev libgmp-dev bsdmainutils git
```

On at least Ubuntu 14.04+ and Debian 7+ there are generic names for the
individual boost development packages, so the following can be used to only
install necessary parts of boost:

```bash
sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
```

If that doesn't work, you can install all boost development packages with:

```bash
sudo apt-get install libboost-all-dev
```

## Optional

### miniupnpc

[miniupnpc](http://miniupnp.free.fr/) may be used for UPnP port mapping.  It can be downloaded from [here](
http://miniupnp.tuxfamily.org/files/).  UPnP support is compiled in and
turned off by default.
To install the dependencies
```bash
sudo apt-get install libminiupnpc-dev
```

See the configure options for upnp behavior desired:
```bash
--without-miniupnpc      #No UPnP support miniupnp not required
--disable-upnp-default   #(the default) UPnP support turned off by default at runtime
--enable-upnp-default    #UPnP support turned on by default at runtime
```

### ZMQ

```bash
sudo apt-get install libzmq3-dev # provides ZMQ API 4.x
```


## Installing dependencies for wallet support


BerkeleyDB is required for the wallet. If you don't need wallet support, but just want a node, you don't need this.

Ubuntu and Debian have their own libdb-dev and libdb++-dev packages, these will install
BerkeleyDB 5.3 or later.

See the section "Disable-wallet mode" to build Nexa without wallet.

## Installing dependencies for the GUI

If you want to build Nexa-Qt, make sure that the required packages for Qt development
are installed. Qt 5.3 or higher is necessary to build the GUI.
To build without GUI pass `--without-gui`.

To build with Qt 5.3 or higher you need the following:

```bash
sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools
```

libqrencode (optional) can be installed with:

```bash
sudo apt-get install libqrencode-dev
```

Once these are installed, they will be found by configure and a nexa-qt executable will be
built by default.

## Dependencies

These dependencies are required:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 libboost    | Utility          | Library for threading, data structures, etc
 libevent    | Networking       | OS independent asynchronous networking
 libgmp      | Math             | Arbitrary precision arithmetic

Optional dependencies:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 miniupnpc   | UPnP Support     | Firewall-jumping support
 libdb5.3    | Berkeley DB      | Wallet storage (only needed when wallet enabled)
 qt          | GUI              | GUI toolkit (only needed when GUI enabled)
 libqrencode | QR codes in GUI  | Optional for generating QR codes (only needed when GUI enabled)
 libzmq3     | ZMQ notification | Optional, allows generating ZMQ notifications (requires ZMQ version >= 4.x)

For the versions used, see [dependencies.md](dependencies.md)

# Building Nexa

Start out by fetching the code

```bash
git clone https://gitlab.com/nexa/nexa.git nexa
cd nexa/
```
## To build without wallet

If you only need to run a node, and have no need for a wallet or GUI you can build the binaries with:

In this case there is no dependency on Berkeley DB 5.3 or Qt5.

Mining is also possible in disable-wallet mode, but only using the `getblocktemplate` RPC
call not `getwork`.



```bash
./autogen.sh
./configure --disable-wallet --with-gui=no
make
make install # optional
```

You will find the `nexad` binary in the `src/` folder.

## To build with wallet


It is recommended to use Berkeley DB 5.3.

If you install the package from the BU Launchpad ppa, as descibed [above](#installing-dependencies-for-wallet-support) you can build with


```bash
./autogen.sh
./configure
make
make install # optional
```

You will find the `nexad` binary in the `src/` folder. This will build `nexa-qt` as well (in `src/qt`), if the dependencies are met.


# Notes

## Additional Configure Flags

A list of additional configure flags can be displayed with:

```bash
./configure --help
```

## Absolute path

Always use absolute paths to configure and compile nexa and the dependencies,
for example, when specifying the path of the dependency:

```bash
../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
```

Here BDB_PREFIX must absolute path - it is defined using $(pwd) which ensures
the usage of the absolute path.

## System requirements

C++ compilers are memory-hungry. It is recommended to have at least 1 GB of
memory available when compiling Nexa. With 512MB of memory or less
compilation will take much longer due to swap thrashing.

## Strip debug symbols

The release is built with GCC and then `strip nexad` to strip the debug
symbols, which reduces the executable size by about 90%.



## Security

To help make your Nexa installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, binaries are hardened by default.
This can be disabled with:

Hardening Flags:

```bash
./configure --enable-hardening
./configure --disable-hardening
```


Hardening enables the following features:

* Position Independent Executable
    Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. Attackers who can cause execution of code at an arbitrary memory
    location are thwarted if they don't know where anything useful is located.
    The stack and heap are randomly located by default but this allows the code section to be
    randomly located as well.

    On an AMD64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To test that you have built PIE executable, install `scanelf`, part of `pax-utils`, and use:

```bash
scanelf -e ./nexad
```

    The output should contain:

     TYPE
    ET_DYN

* Non-executable Stack
    If the stack is executable then trivial stack based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, nexa should be built with a non-executable stack
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    `scanelf -e ./nexad`

    the output should contain:
	STK/REL/PTL
	RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.


## Produce Static Binaries

If you want to build statically linked binaries so that you could compile in one machine
and deploy in same parch/platform boxes without the need of installing all the dependencies
just follow these steps. You will need to install `curl` and `bison` via apt. The former is
needed to fetch the source code of all the depends packages, the latter is needed to build
the Qt library from source.

```bash
git clone https://gitlab.com/nexa/nexa.git nexa
cd nexa/depends
make HOST=x86_64-pc-linux-gnu NO_QT=1 -j4
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu --without-gui --disable-shared
make -j4
```

in the above commands we are statically compiling headless 64 bit Linux binaries. If you want to compile
32 bit binaries just use `i686-pc-linux-gnu` rather than `x86_64-pc-linux-gnu`

## ARM Cross-compilation

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

Make sure you install the build requirements mentioned above.
Then, install the toolchain and curl:

```bash
sudo apt-get install g++-arm-linux-gnueabihf curl
```

To build executables for ARM:

```bash
cd depends
make HOST=arm-linux-gnueabihf NO_QT=1
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/arm-linux-gnueabihf --enable-glibc-back-compat --enable-reduce-exports LDFLAGS=-static-libstdc++
make
```


For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.
