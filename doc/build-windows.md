# WINDOWS BUILD NOTES

Below are some notes on how to build Nexa for Windows.

Most developers use cross-compilation from Ubuntu to build executables for Windows. This is also used to build the release binaries.

While there are potentially a number of ways to build on Windows, using the Windows Subsystem For Linux is the most straight forward.  If you are building with an alternative method, please contribute the instructions here for others who are running versions of Windows that are not compatible with the Windows Subsystem for Linux.

A second alternative way of building on Windows using msys / mingw-w64 is documented in 'build-windows-mingw.md'.

## Compiling with Windows Subsystem For Linux

With Windows 10, Microsoft has released a new feature named the [Windows Subsystem for Linux](https://msdn.microsoft.com/commandline/wsl/about).  This feature allows you to run a bash shell directly on Windows in an Ubuntu-based environment.  Within this environment you can cross compile for Windows without the need for a separate Linux VM or server.

This feature is not supported in versions of Windows prior to Windows 10 or on
Windows Server SKUs. In addition, it is available [only for 64-bit versions of
Windows](https://msdn.microsoft.com/en-us/commandline/wsl/install_guide).

To get the bash shell, you must first activate the feature in Windows.

1. Turn on Developer Mode
  * Open Settings -> Update and Security -> For developers
  * Select the Developer Mode radio button
  * Restart if necessary
2. Enable the Windows Subsystem for Linux feature
  * From Start, search for "Turn Windows features on or off" (type 'turn')
  * Select Windows Subsystem for Linux (beta)
  * Click OK
  * Restart if necessary
3. Complete Installation
  * Open a cmd prompt and type "bash"
  * Accept the license
  * Create a new UNIX user account (this is a separate account from your Windows account)

After the bash shell is active, you can follow the instructions below, starting
with the "Cross-compilation" section. Compiling the 64-bit version is
recommended but it is possible to compile the 32-bit version.

## Cross-compilation

These steps can be performed on, for example, an Ubuntu VM. The depends system will also work on other Linux distributions, however the commands for installing the toolchain will be different.

First, install the general dependencies:

```bash
sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl
```

A host toolchain (`build-essential`) is necessary because some dependency
packages need to build host utilities that are used in the build process.

See also: [dependencies.md](dependencies.md).

## Building for 64-bit Windows

To build executables for Windows 64-bit, install the following dependencies:

```bash
sudo apt-get install python3 nsis g++-mingw-w64-x86-64 mingw-w64-x86-64-dev wine64 wine-binfmt automake autoconf libtool pkg-config
```

Then you need to confiure the compiler to use the POSIX threading model

```bash
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
```

Then build using:

```bash
cd depends
make HOST=x86_64-w64-mingw32
cd ..
./autogen.sh # not required when building from tarball
mkdir build && cd build
../configure --prefix=$PWD/../depends/x86_64-w64-mingw32/
make -j`nproc`
```

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.

Two caveats:

- the configure step needs to be execute using `--prefix` flag rather than using the `CONFIG_SITE` variable, otherwise  the univalue subsytem will be configured to be compiled for the build system (linux) rather than the  host system (windows)

- if you have installed `libqt5dbus5` package on your linux machine you need to pass `--with-qtdbus=no` to the `configure` script. This is due to the fact that the qt dbus library is searched for also in the system path rather then just in the `depends` folder.

Both the above issues will be fixed in the near feature.

## Installation

After building using the Windows subsystem it can be useful to copy the compiled
executables to a directory on the Windows drive in the same directory structure
as they appear in the release `.zip` archive. This can be done in the following
way. This will install to `c:\workspace\nexa`, for example:

```bash
make install DESTDIR=/mnt/c/workspace/nexa
```
