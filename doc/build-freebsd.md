# OpenBSD build guide
(updated for FreeBSD 12.1)

This guide describes how to build nexad and command-line utilities on FreeBSD.

We will not cover building the GUI.

**Important**: use `gmake`, not `make`. The non-GNU `make` will exit with a horrible error.

## Preparation

Run the following as root to install the base dependencies for building:

```bash
pkg install autoconf automake gmake git libevent libtool boost-libs pkgconf openssl python
```

See [dependencies.md](dependencies.md) for a complete overview.

If you need to use rostrum it's necessary to enable
[procfs](https://man.freebsd.org/cgi/man.cgi?query=procfs) in FreeBSD so it can
find the binary. It isn't on by default but it's available.
Just put in `/etc/fstab`:

```
proc	       /proc   procfs  rw 0 0
```

## Building Nexa

As your normal (non root) user, go through the steps below

### Fetch the code

```bash
git clone https://gitlab.com/nexa/nexa.git Nexa
cd Nexa/
```

### Preparation

```bash
export MAKE=gmake
```

Now you need to choose to build without or with wallet functionality. If you just require a running node, you generally don't need wallet functionality

### To build without wallet

While in the `nexa` directory

```bash
./autogen.sh
./configure --disable-wallet --with-gui=no
gmake # You may get an error with one of the tests.
```

You will find the `nexad` binary in the `src/` folder.


### To build with wallet

To stay backwards compatible with old walletfiles we specifically need BerkeleyDB 5.3.
You cannot use the BerkeleyDB library from ports.


#### Building BerkeleyDB

BerkeleyDB is only necessary for the wallet functionality. To skip this, pass `--disable-wallet` to `./configure`. See above.

To build Berkeley DB 5.3:

```bash
# Pick some path to install BDB to, here we create a directory within the nexa directory
BDB_PREFIX=$(pwd)/db4
mkdir -p $BDB_PREFIX

# Fetch the source and verify that it is not tampered with
curl 'https://download.oracle.com/berkeley-db/db-5.3.28.NC.tar.gz' -o db-5.3.28.NC.tar.gz
echo '76a25560d9e52a198d37a31440fd07632b5f1f8f9f2b6d5438f4bc3e7c9013ef'  db-5.3.28.NC.tar.gz' | shasum -c
# MUST output: db-5.3.28.NC.tar.gz: OK
tar -xzf db-5.3.28.NC.tar.gz

# Fetch, verify that it is not tampered with and apply clang related patch
cd db-5.3.28.NC/
curl 'https://gist.githubusercontent.com/LnL7/5153b251fd525fe15de69b67e63a6075/raw/7778e9364679093a32dec2908656738e16b6bdcb/clang.patch' -o clang.patch
echo '7a9a47b03fd5fb93a16ef42235fa9512db9b0829cfc3bdf90edd3ec1f44d637c  clang.patch' | shasum -c
# MUST output: clang.patch: OK
patch -p2 < clang.patch

# Build the library and install to specified prefix
cd build_unix/
./../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
gmake install
cd ../..
```

You should now have the required files in `db4/lib/` and `db4/include/`.

### To build with wallet

Make sure `BDB_PREFIX` is set to the appropriate path from building BDB. See above.

While in the `nexa` directory.

```bash
./autogen.sh
./configure LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/" --with-gui=no
gmake
```

