# ALPINE BUILD NOTES

This guide describes how to build nexad and command-line utilities on Alpine Linux.

We will not cover building the GUI since Alpine Linux mostly used for docker environment.

# Installing dependencies

Run the following to install the base dependencies for building:

```sh
apk add curl git build-base libtool autoconf automake pkgconf openssl-dev libevent-dev gmp-dev util-linux boost-dev
```

## Optional

### miniupnpc

[miniupnpc](http://miniupnp.free.fr/) may be used for UPnP port mapping.  It can be downloaded from [here](http://miniupnp.tuxfamily.org/files/).
UPnP support is compiled in and turned off by default.

To install the dependencies
```sh
apk add miniupnpc-dev
```

See the configure options for upnp behavior desired:
```sh
--without-miniupnpc      #No UPnP support miniupnp not required
--disable-upnp-default   #(the default) UPnP support turned off by default at runtime
--enable-upnp-default    #UPnP support turned on by default at runtime
```

### ZMQ (Optional)

```sh
apk add zeromq-dev # provides ZMQ API 4.x
```


## Installing dependencies for wallet support

BerkeleyDB is required for the wallet. If you don't need wallet support, but just want a node, you don't need this.

To install install BerkeleyDB 5.3 or later:

```sh
apk add db-dev
```

See the section "Disable-wallet mode" to build Nexa without wallet.


# Building Nexa

Start out by fetching the code

```sh
git clone https://gitlab.com/nexa/nexa.git
cd nexa/
```

## To build without wallet

If you only need to run a node, and have no need for a wallet you can build the binaries with:

```sh
./autogen.sh
./configure --disable-wallet --without-gui
make -j`nproc`
make install # optional
```
You will find the `nexad` binary in the `src/` folder.

In this case there is no dependency on Berkeley DB 5.3.

Mining is also possible in disable-wallet mode, but only using the `getblocktemplate` RPC call, not `getwork`.


## To build with wallet

It is recommended to use Berkeley DB 5.3.

```sh
./autogen.sh
./configure --without-gui
make -j`nproc`
make install # optional
```
You will find the `nexad` binary in the `src/` folder..


# Notes

## Additional Configure Flags

A list of additional configure flags can be displayed with:

```sh
./configure --help
```

## System requirements

C++ compilers are memory-hungry. It is recommended to have at least 1 GB of
memory available when compiling Nexa. With 512MB of memory or less
compilation will take much longer due to swap thrashing.

## Strip debug symbols

The release is built with GCC and then `strip nexad` to strip the debug
symbols, which reduces the executable size by about 90%.

## Produce Static Binaries

If you want to build statically linked binaries so that you could compile in one machine
and deploy in same parch/platform boxes without the need of installing all the dependencies
just follow these steps. You will need to install `curl` and `bison` via apk. The former is
needed to fetch the source code of all the depends packages, the latter is needed to build
the Qt library from source.

```sh
git clone https://gitlab.com/nexa/nexa.git
cd nexa/depends
make HOST=x86_64-linux-musl NO_QT=1 NO_RUST=1 -j`nproc`
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-linux-musl --without-gui --disable-wallet --disable-shared --enable-reduce-exports --disable-bench --disable-gui-tests --disable-tests LDFLAGS="-static-libstdc++ -static-libgcc"
make -j`nproc`
strip src/nexad
```

in the above commands we are statically compiling headless 64 bit Linux binaries. If you want to compile
32 bit binaries just use `i686-linux-musl` rather than `x86_64-linux-musl`

For ARM on Alpine, you might use: `aarch64-linux-musl` (for 64-bit ARM) or `arm-linux-musleabihf` (for 32-bit ARM).

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.
