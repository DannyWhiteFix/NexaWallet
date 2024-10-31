### Usage

To build dependencies for the current arch+OS:

    make

To build for another arch/OS:

    make HOST=host-platform-triplet

For example:

    make HOST=x86_64-w64-mingw32

A prefix will be generated that's suitable for plugging into Bitcoin's
configure. In the above example, a dir named x86_64-w64-mingw32 will be
created. To use it for Bitcoin:

    ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32

Common `host-platform-triplets` for cross compilation are:

- `i686-pc-linux-gnu` for Linux 32 bit (glibc)
- `x86_64-pc-linux-gnu` for x86 Linux (glibc)
- `i686-linux-musl` for Linux 32 bit (musl)
- `x86_64-linux-musl` for x86 Linux (musl)
- `riscv32-linux-gnu` for Linux RISC-V 32 bit
- `riscv64-linux-gnu` for Linux RISC-V 64 bit
- `i686-w64-mingw32` for Win32
- `x86_64-w64-mingw32` for Win64
- `x86_64-apple-darwin` for MacOSX (Intel)
- `arm64-apple-darwin` for MacOSX (ARM)
- `arm-linux-gnueabihf` for Linux ARM 32 bit (glibc)
- `aarch64-linux-gnu` for Linux ARM 64 bit (glibc)
- `arm-linux-musleabihf` for Linux ARM 32 bit (musl)
- `aarch64-linux-musl` for Linux ARM 64 bit (musl)

No other options are needed, the paths are automatically configured.

Install the required dependencies: Ubuntu & Debian
--------------------------------------------------

For macOS cross compilation:

    sudo apt-get install curl librsvg2-bin libtiff-tools bsdmainutils cmake imagemagick libcap-dev libz-dev libbz2-dev python-setuptools

Note: You must obtain the macOS SDK before proceeding with a cross-compile.
Under the depends directory, create a subdirectory named `SDKs`.
Then, place the extracted SDK under this new directory.
You can find macOS SDKs here: https://github.com/joseluisq/macosx-sdks or you can create an Apple developer account and download it from Apple website. If you chose the latter way you need to extract the SDK your self from the archive provided by Apple.

For Win32/Win64 cross compilation:

- see [build-windows.md](../doc/build-windows.md#cross-compilation-for-ubuntu-and-windows-subsystem-for-linux)

For linux (including i386, ARM) cross compilation:

    sudo apt-get install curl linux-libc-dev:i386 g++-aarch64-linux-gnu g++-aarch64-linux-gnu gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu g++-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf g++-multilib gcc-multilib binutils-gold bsdmainutils


For linux RISC-V 64-bit cross compilation (there are no packages for 32-bit):

    sudo apt-get install curl g++-riscv64-linux-gnu binutils-riscv64-linux-gnu

If you want to build a risc-v 32bits set of binaries you need to build a risc-v 32bits tool chain first, eg by following the instructions you can find here https://github.com/yuzibo/riscv32/wiki

Dependency Options:
The following can be set when running make: make FOO=bar

    SOURCES_PATH: downloaded sources will be placed here
    BASE_CACHE: built packages will be placed here
    SDK_PATH: Path where sdk's can be found (used by OSX)
    FALLBACK_DOWNLOAD_PATH: If a source file can't be fetched, try here before giving up
    NO_QT: Don't download/build/cache qt and its dependencies
    NO_WALLET: Don't download/build/cache libs needed to enable the wallet
    NO_UPNP: Don't download/build/cache packages needed for enabling upnp
    NO_RUST: Don't download/build/cache rust
    DEBUG: disable some optimizations and enable more runtime checking
    JOBS: Number of jobs to use for each package build

If some packages are not built, for example `make NO_WALLET=1`, the appropriate
options will be passed to bitcoin's configure. In this case, `--disable-wallet`.

Additional targets:

    download: run 'make download' to fetch all sources without building them
    download-osx: run 'make download-osx' to fetch all sources needed for osx builds
    download-win: run 'make download-win' to fetch all sources needed for win builds
    download-linux: run 'make download-linux' to fetch all sources needed for linux builds

### Other documentation

- [description.md](description.md): General description of the depends system
- [packages.md](packages.md): Steps for adding packages

