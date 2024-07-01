# Fuzz-testing Nexa

A special test harness `test_nexa_fuzzy` is provided to provide an easy
entry point for fuzzers and the like. In this document we'll describe how to
use it with AFL.

Compared to Bitcoin Core, this test harness has been updated to both
remove some redundant code as well as to provide entry points for fuzzing
single data structures.

## Building AFL

It is recommended to always install the latest version of AFLplusplus from https://github.com/AFLplusplus.

See https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md for installation details.
Summary:
```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 14 and install the distro default if that fails
sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

For fast fuzzing (see below), the `afl-clang-fast` and
`afl-clang-fast++` AFL drivers should be build and used.

## Instrumentation

Before building Nexa with AFL, ensure that it can be built normally (see doc/build-unix.md).

To build Nexa using AFL instrumentation (this assumes that the
`AFLPATH` was set as above):
```
./autogen.sh
mkdir afl
cd afl
../configure --disable-shared --enable-tests CC=`which afl-clang-fast` CXX=`which afl-clang-fast++`
export AFL_HARDEN=1
cd src/
make -j12 V=1 test/test_nexa_fuzzy
```

The fuzzer is _a lot_ faster now when run in LLVM persistent mode. To enable LLVM persistent mode, `test_nexa_fuzzy` has to be built with
clang/clang++. But if you MUST use g++ you can still do it by setting CC and CXX appropriately:
```
./configure [--disable-ccache] --disable-shared --enable-tests CC=${AFLPATH}/afl-gcc CXX=${AFLPATH}/afl-g++
```

Note that fuzzing in fast mode (llvm_mode) might introduce some
inaccuracies that might lead the fuzzer astray. For details on this,
consult the documentation of AFL. It is expected however (and some
simple experiments show so as well), that AFL still is a lot quicker
to discover input structure this way.


## Preparing fuzzing

AFL needs an input directory with examples, and an output directory where it
will place examples that it found. These can be anywhere in the file system,
we'll define environment variables to make it easy to reference them.

```
mkdir inputs
AFLIN=$PWD/inputs
mkdir outputs
AFLOUT=$PWD/outputs
```

For the old fuzzing code that fuzzes everything at once, example inputs might still
be available from:

- https://download.visucore.com/bitcoin/bitcoin_fuzzy_in.tar.xz
- http://strateman.ninja/fuzzing.tar.xz

Extract these (or other starting inputs) into the `inputs` directory before starting fuzzing.

## Fuzzing

To start the actual fuzzing and to fuzz all fuzz cases at once:
```
$AFLPATH/afl-fuzz -i ${AFLIN} -o ${AFLOUT} -m 200 -- test/test_nexa_fuzzy
```

And to fuzz using just a single fuzzing entrypoint, specify a
corresponding command line argument to test_nexa_fuzzy on what to
fuzz. A list of all possible arguments can be printed like this:

```
test/test_nexa_fuzzy list_tests
```

So, for example, to fuzz the CBlock de-/serialization, you can use this:
```
$AFLPATH/afl-fuzz -i ${AFLIN} -o ${AFLOUT} -m 200 -- test/test_nexa_fuzzy cblock_deser
```
You may have to change a few kernel parameters to test optimally -
`afl-fuzz` will print an error and suggestion if so.

The memory limit of 200MB above (`-m 200`) might be generous. If you
suspect that code might have some memory leaks and you want to test
for that specifically, try lowering the limit until about just before
fuzzing breaks every time.  Further information can be found in the
AFL documentation.

*Important note*: Fuzzing does *not* work by simply calling
`test_nexa_fuzzy`. This will just call the instrumented program and
it will (pretty much) behave like it would have been compiled without
fuzzer options. It can, however, be used this way to retest test cases
from the fuzzer.

## Parallel fuzzing

AFL is single threaded and you are expected to launch multiple instances to do parallel fuzzing.  The following "konsole" example command and tabs file starts up 24 verifyscript fuzzers.  Note that one fuzzer is marked with the flag -M and the rest -S.

It is expected that your current directory is nexa/<build dir>/src/test, and you have created a "scriptFuzzInputs" directory with input patterns (begin with src/test/fuzzvectors/verifyscript*.bin) and an empty output directory named "sfo".
Expected to be launched from the nexa/<build dir>/src/test directory:

Create a file named "afltabs":
```
title: %n;; profile: big;; command: /usr/bin/top
title: r0;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -M r0 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r1;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r1 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r2;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r2 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r3;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r3 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r4;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r4 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r5;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r5 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r6;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r6 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r7;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r7 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r8;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r8 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r9;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r9 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r10;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r10 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r11;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r11 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r12;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r12 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r13;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r13 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r14;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r14 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r15;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r15 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r16;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r16 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r17;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r17 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r18;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r18 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r19;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r19 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r20;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r20 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r21;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r21 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r22;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r22 -m 100 -- ./test_nexa_fuzzy verifyscript
title: r23;; profile: big;; command: /usr/local/bin/afl-fuzz -t 4000 -i ./scriptFuzzInputs -o sfo -S r23 -m 100 -- ./test_nexa_fuzzy verifyscript
```

```
konsole --hold --tabs-from-file afltabs
```


## Extending

The code has been updated to be more easily extensible. In test_nexa_fuzzy.cpp, 
simply derive a class from `FuzzTest` or, alternatively, `FuzzTestNet` (in case you want
to read from a network-like CDataStream). Override the `run()` method and either use
the `buffer` object or the `ds` object to retrieve the data for your test.

