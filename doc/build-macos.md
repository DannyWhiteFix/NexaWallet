# Mac macOS Build Instructions and Notes
The commands in this guide should be executed in a Terminal application.
The built-in one is located in `/Applications/Utilities/Terminal.app`.

## Preparation
Install the macOS command line tools:

```bash
xcode-select --install
```

When the popup appears, click `Install`.

Then install [Homebrew](http://brew.sh).

## Dependencies

```bash
brew install automake libtool boost miniupnpc pkg-config protobuf qt5 libevent gmp
```

If you plane to run nexa linked to berkeley-db 4.8.3 (ie use `--with-incompatible-bdb`) you
need to execute:

```bash
brew install berkeley-db@4
```

In the default `configure` setting nexa expect for berkeley-db 5.3 to be installed on your system,
hence you need to execute:

```bash
brew install berkeley-db@5
```

in advance.

If you are planning not to use the wallet functionality of nexa (ie `--disable-wallet`) you
don't need to install berkeley db on your system.

One final note, `brew install berkeley-db` without specifying a version (eg `@5`) install
the most recent version which is 18.1.40 at the time of this writing. This version is not
supported and tested so `configure` won't complete and fail.

See [dependencies.md](dependencies.md) for a complete overview.

If you want to build the disk image with `make deploy` (.dmg / optional), you need RSVG

```bash
brew install librsvg
```

NOTE: Must build with QT 5.9 or higher. Building with Qt4 is not supported.

## Build Nexa

1. Clone the Nexa source code and cd into `Nexa`
    ```bash
    git clone https://gitlab.com/nexa/nexa.git Nexa
    cd Nexa/
    ```

2.  Build:

    Configure and build the headless Nexa binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.

    ```bash
    ./autogen.sh
    ./configure
    make
    ```

3.  It is recommended to build and run the unit tests:

    ```bash
    make check
    ```

4.  You can also create a .dmg that contains the .app bundle (optional):

    ```bash
    make deploy
    ```

## Running

Nexa is now available at `./src/nexad`

Before running, it's recommended you create an RPC configuration file.

```bash
echo -e "rpcuser=nexarpc\nrpcpassword=$(xxd -l 16 -p /dev/urandom)" > "/Users/${USER}/Library/Application Support/Nexa/nexa.conf"

chmod 600 "/Users/${USER}/Library/Application Support/Nexa/nexa.conf"
```

The first time you run nexad, it will start downloading the blockchain. This process could take several hours.

You can monitor the download process by looking at the debug.log file:

```bash
tail -f $HOME/Library/Application\ Support/Nexa/debug.log
```

## Other commands:

```bash
./src/nexad -daemon # Starts the Nexa daemon.
./src/nexa-cli --help # Outputs a list of command-line options.
./src/nexa-cli help # Outputs a list of RPC commands when the daemon is running.
```

## Using Qt Creator as IDE

You can use Qt Creator as an IDE, for Nexa development.
Download and install the community edition of [Qt Creator](https://www.qt.io/download/).
Uncheck everything except Qt Creator during the installation process.

1. Make sure you installed everything through Homebrew mentioned above
2. Do a proper `./configure --enable-debug`
3. In Qt Creator do "New Project" -> Import Project -> Import Existing Project
4. Enter "nexa-qt" as project name, enter src/qt as location
5. Leave the file selection as it is
6. Confirm the "summary page"
7. In the "Projects" tab select "Manage Kits..."
8. Select the default "Desktop" kit and select "Clang (x86 64bit in /usr/bin)" as compiler
9. Select LLDB as debugger (you might need to set the path to your installation)
10. Start debugging with Qt Creator

## Notes

* Tested on OS X 10.8 through macOS 10.12 on 64-bit Intel processors only.

* Building with downloaded Qt binaries is not officially supported. See the notes in [#7714](https://github.com/bitcoin/bitcoin/issues/7714)
