#!/bin/bash

BUILD_AARCH64=1
BUILD_ARMV7A=1
BUILD_I686=1
BUILD_X86_64=1
BUILD_RISCV64=1

NDK_VERSION=27.2.12479018

# check for -h or --help in the args
for var in "$@"
do
    if [ "$var" = "-h" ] || [ "$var" = "--help" ]; then
        echo "This script will build the dependencies to build libnexa for mobile architectures and build them."
        exit 0
    fi
done

export AR=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
export RANLIB=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib

# clean up possible directories from a previous build, could probably use make clean
cd depends
rm -rf aarch64-linux-android
rm -rf armv7a-linux-androideabi
rm -rf i686-linux-android
rm -rf x86_64-linux-android
rm -rf riscv64-linux-android
if [ -d "built" ]; then
    cd built
    rm -rf aarch64-linux-android
    rm -rf armv7a-linux-androideabi
    rm -rf i686-linux-android
    rm -rf x86_64-linux-android
    rm -rf riscv64-linux-android
    cd .. # out of built into depends folder
fi
if [ -d "work" ]; then
cd work
    if [ -d "build" ]; then
        cd build
        rm -rf aarch64-linux-android
        rm -rf armv7a-linux-androideabi
        rm -rf i686-linux-android
        rm -rf x86_64-linux-android
        rm -rf riscv64-linux-android
        cd .. # out of build into work folder
    fi
    if [ -d "staging" ]; then
        cd staging
        rm -rf aarch64-linux-android
        rm -rf armv7a-linux-androideabi
        rm -rf i686-linux-android
        rm -rf x86_64-linux-android
        rm -rf riscv64-linux-android
        cd .. # out of staging into work folder
    fi
    cd .. # out of work folder into depends folder
fi
cd .. # out of depends folder into root dir
# end clean up


if [ $BUILD_AARCH64 -eq 1 ]; then
    rm -rf android-build-aarch64-linux-android
    # build aarch64
    cd depends
    # set the compiler stuff, this is the default location on ubuntu 24
    export CC=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
    export CXX=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang++
    make HOST=aarch64-linux-android NO_QT=1 NO_WALLET=1 NO_RUST=1 ONLY_LIBNEXA=1
    cd ..
    ./autogen.sh
    echo "~~~~~~~~Building libnexa for android aarch64~~~~~~~"
    mkdir android-build-aarch64-linux-android
    cd android-build-aarch64-linux-android
    ../configure --prefix=$PWD/../depends/aarch64-linux-android --enable-only-libnexa --host=aarch64-linux-android
    make -j`nproc`
    cd ..
    echo "~~~~~~~~~~~~~~~~~~done~~~~~~~~~~~~~~~~~~~~~"
fi

if [ $BUILD_ARMV7A -eq 1 ]; then
    rm -rf android-build-armv7a-linux-androideabi
    # build armv7a
    cd depends
    # set the compiler stuff, this is the default location on ubuntu 24
    export CC=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi35-clang
    export CXX=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi35-clang++
    make HOST=armv7a-linux-androideabi NO_QT=1 NO_WALLET=1 NO_RUST=1 ONLY_LIBNEXA=1
    cd ..
    ./autogen.sh
    echo "~~~~~~~~Building libnexa for android armv7a~~~~~~~"
    mkdir android-build-armv7a-linux-androideabi
    cd android-build-armv7a-linux-androideabi
    ../configure --prefix=$PWD/../depends/armv7a-linux-androideabi --enable-only-libnexa --host=armv7a-linux-androideabi
    make -j`nproc`
    cd ..
    echo "~~~~~~~~~~~~~~~~~~done~~~~~~~~~~~~~~~~~~~~~"
fi


if [ $BUILD_I686 -eq 1 ]; then
    rm -rf android-build-i686-linux-android
    # build i686-linux-android
    cd depends
    # set the compiler stuff, this is the default location on ubuntu 24
    export CC=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android35-clang
    export CXX=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android35-clang++
    make HOST=i686-linux-android NO_QT=1 NO_WALLET=1 NO_RUST=1 ONLY_LIBNEXA=1
    cd ..
    ./autogen.sh
    echo "~~~~~~~~Building libnexa for android i686~~~~~~~"
    mkdir android-build-i686-linux-android
    cd android-build-i686-linux-android
    # need to disable USE_ASM because of missing CUPID
    # error in i686 build
    # ../../src/crypto/sha256.cpp:489:5: error: use of undeclared identifier 'GetCPUID'
    #  489 |     GetCPUID(1, 0, eax, ebx, ecx, edx);
    ../configure --prefix=$PWD/../depends/i686-linux-android --enable-only-libnexa --host=i686-linux-android
    make -j`nproc`
    cd ..
    echo "~~~~~~~~~~~~~~~~~~done~~~~~~~~~~~~~~~~~~~~~"
fi


if [ $BUILD_X86_64 -eq 1 ]; then
    rm -rf android-build-x86_64-linux-android
    # build x86_64-linux-android
    cd depends
    # set the compiler stuff, this is the default location on ubuntu 24
    export CC=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang
    export CXX=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang++
    make HOST=x86_64-linux-android NO_QT=1 NO_WALLET=1 NO_RUST=1 ONLY_LIBNEXA=1
    cd ..
    ./autogen.sh
    echo "~~~~~~~~Building libnexa for android x86_64~~~~~~~"
    mkdir android-build-x86_64-linux-android
    cd android-build-x86_64-linux-android
    ../configure --prefix=$PWD/../depends/x86_64-linux-android --enable-only-libnexa --host=x86_64-linux-android
    make -j`nproc`
    cd ..
    echo "~~~~~~~~~~~~~~~~~~done~~~~~~~~~~~~~~~~~~~~~"
fi


if [ $BUILD_RISCV64 -eq 1 ]; then
    rm -rf android-build-riscv64-linux-android
    # build riscv64-linux-android
    cd depends
    # set the compiler stuff, this is the default location on ubuntu 24
    export CC=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/riscv64-linux-android35-clang
    export CXX=/usr/lib/android-sdk/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/riscv64-linux-android35-clang++
    make HOST=riscv64-linux-android NO_QT=1 NO_WALLET=1 NO_RUST=1 ONLY_LIBNEXA=1
    cd ..
    ./autogen.sh
    echo "~~~~~~~~Building libnexa for android riscv64~~~~~~~"
    mkdir android-build-riscv64-linux-android
    cd android-build-riscv64-linux-android
    ../configure --prefix=$PWD/../depends/riscv64-linux-android --enable-only-libnexa --host=riscv64-linux-android --enable-reduce-exports LDFLAGS=-static-libstdc++
    make -j`nproc`
    cd ..
    echo "~~~~~~~~~~~~~~~~~~done~~~~~~~~~~~~~~~~~~~~~"
fi

exit 0
