FROM ubuntu:20.04

RUN apt-get -y update
RUN apt-get install -y --no-install-recommends --no-upgrade -qq software-properties-common
RUN add-apt-repository -y universe

# Make sure UTF-8 isn't borked
RUN apt-get -y --no-install-recommends --no-upgrade -qq install locales
RUN export LANG=en_US.UTF-8
RUN export LANGUAGE=en_US:en
RUN export LC_ALL=en_US.UTF-8
RUN echo "en_US UTF-8" > /etc/locale.gen
# Add de_DE.UTF-8 for specific JSON number formatting unit tests
RUN echo "de_DE.UTF-8 UTF-8" >> /etc/locale.gen
# Generate all locales

RUN locale-gen

# Build requirements
RUN apt-get -y --no-install-recommends --no-upgrade -qq install g++-multilib automake autotools-dev bsdmainutils build-essential ca-certificates ccache clang curl
RUN apt-get -y --no-install-recommends --no-upgrade -qq install git libboost-all-dev
RUN apt-get -y --no-install-recommends --no-upgrade -qq install libdb5.3-dev libdb5.3++-dev libedit2 libevent-dev libminiupnpc-dev libprotobuf-dev libqrencode-dev libssl-dev
RUN apt-get -y --no-install-recommends --no-upgrade -qq install libtool libzmq3-dev pkg-config protobuf-compiler python3 python3-zmq qttools5-dev qttools5-dev-tools bison

# Add clang-format 12
# even thou Ubuntu 20/04 comes with clang-format-12, the actual version is 12.0.0
# whereas the one served via llvm repo is 12.0.1. Unfortunately these 2 versions
# do no produce the same exact formatting in some special case and since we have used
# 12.0.1 for quite a while it's better for us to stick with it
RUN apt-get install -y wget gpg-agent
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x ./llvm.sh
RUN ./llvm.sh 12 all
RUN apt-get install clang-format-12 clang-12

# set clang-12 as the default compiler for C/C++
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100 --slave /usr/bin/clang++ clang++ /usr/bin/clang++-12

#Add GNU mp bignum library
RUN apt-get install -y libgmp-dev

# Support windows build
RUN apt-get -y --no-install-recommends --no-upgrade -qq install python3 nsis g++-mingw-w64-x86-64 wine64 wine-binfmt curl automake autoconf libtool pkg-config
RUN update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
RUN update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix

# Support ARM build
RUN apt-get -y --no-install-recommends --no-upgrade -qq install autoconf automake curl g++-arm-linux-gnueabihf gcc-arm-linux-gnueabihf gperf pkg-config

# Support AArch64 build
RUN apt-get -y --no-install-recommends --no-upgrade -qq install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu qemu-user-static

# Support OSX build
RUN apt-get -y --no-install-recommends --no-upgrade -qq install  cmake imagemagick python3-git libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python-dev python3-setuptools-git python3-setuptools libtinfo5

# Add tools to debug failing QA tests
RUN apt-get -y --no-install-recommends --no-upgrade -qq install python3-pip gdb python3-dev python-is-python3
RUN pip3 install wheel
RUN pip3 install psutil

# Clean up cache
RUN apt-get clean
