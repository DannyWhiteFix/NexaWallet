# Dependencies

These are the dependencies currently used by Bitcoin Unlimited. You can find instructions for installing them in the `build-*.md` file for your platform.

| Dependency | Version used | Minimum required | CVEs | Shared | [Bundled Qt library](https://doc.qt.io/qt-5/configure-options.html) |
| --- | --- | --- | --- | --- | --- |
| Berkeley DB | [5.3.28](http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index.html) | 5.3.x | No |  |  |
| Boost | [1.86.0](http://www.boost.org/users/download/) | [1.68.0](https://gitlab.com/nexa/nexa/-/merge_requests/594) | No |  |  |
| D-Bus | [1.10.18](https://cgit.freedesktop.org/dbus/dbus/tree/NEWS?h=dbus-1.10) |  | No | Yes |  |
| Expat | [2.4.1](https://libexpat.github.io/) |  | No | Yes |  |
| fontconfig | [2.12.1](https://www.freedesktop.org/software/fontconfig/release/) |  | No | Yes |  |
| FreeType | [2.11.0](http://download.savannah.gnu.org/releases/freetype) |  | No |  |  |
| GCC |  | [9.1](https://gcc.gnu.org/) | 9.1 |  |  |
| HarfBuzz-NG |  |  |  |  |  |
| libevent | [2.1.12-stable](https://github.com/libevent/libevent/releases) | 2.0.22 | No |  |  |
| libpng |  |  |  |  | [Yes](https://github.com/bitcoin/bitcoin/blob/master/depends/packages/qt.mk) |
| libgmp | [6.3.0](https://gmplib.org) | 6.2.1 | |  |  |
| MiniUPnPc | [2.0.20180203](http://miniupnp.free.fr/files) |  | No |  |  |
| OpenSSL | [1.1.1m](https://www.openssl.org/source) |  | Yes |  |  |
| PCRE |  |  |  |  | [Yes](https://github.com/bitcoin/bitcoin/blob/master/depends/packages/qt.mk#L76) |
| protobuf | [21.12](https://github.com/google/protobuf/releases) |  | No |  |  |
| Python (tests) |  | [3.6](https://www.python.org/downloads) |  |  |  |
| qrencode | [4.1.1](https://fukuchi.org/works/qrencode) |  | No |  |  |
| Qt | [5.15.5](https://download.qt.io/official_releases/qt/) | [5.9.5](https://github.com/bitcoin/bitcoin/issues/20104) | No |  |  |
| Rust | [1.86.0](https://forge.rust-lang.org/infra/other-installation-methods.html#source-code) | [1.86.0](https://nexa.gitlab.io/rostrum/build/) | | | |
| XCB |  |  |  |  | [Yes](https://github.com/bitcoin/bitcoin/blob/master/depends/packages/qt.mk) (Linux only) |
| xkbcommon |  |  |  |  | [Yes](https://github.com/bitcoin/bitcoin/blob/master/depends/packages/qt.mk) (Linux only) |
| ZeroMQ | [4.3.4](https://github.com/zeromq/libzmq/releases) |  | Yes |  |  |
| zlib | |  |  |  | [Yes](https://github.com/bitcoin/bitcoin/blob/master/depends/packages/qt.mk) |
