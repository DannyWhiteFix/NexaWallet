OSX_MIN_VERSION=11.0
OSX_SDK_VERSION=11.3
OSX_SDK=$(SDK_PATH)/MacOSX$(OSX_SDK_VERSION).sdk
LD64_VERSION=609
darwin_CC=clang -target $(host) -mmacosx-version-min=$(OSX_MIN_VERSION) -isysroot $(OSX_SDK) -mlinker-version=$(LD64_VERSION) -B$(build_prefix)/bin
darwin_CXX=clang++ -target $(host) -mmacosx-version-min=$(OSX_MIN_VERSION) -isysroot $(OSX_SDK) -stdlib=libc++ -mlinker-version=$(LD64_VERSION) -B$(build_prefix)/bin -nostdinc++ -isystem $(OSX_SDK)/usr/include/c++/v1

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_native_toolchain=native_cctools
