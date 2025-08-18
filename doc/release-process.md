Release Process
====================

#### First time / New builders

Check out the source code in the following directory hierarchy.

```bash
cd /path/to/your/toplevel/build
git clone https://gitlab.com/nexa/detached-sigs.git
git clone https://gitlab.com/nexa/gitian-builder.git
git clone https://gitlab.com/nexa/nexa.git
```

#### Bitcoin maintainers/release engineers, update (commit) version in sources

```bash
cd ./nexa
configure.ac
doc/README*
contrib/gitian-descriptors/*.yml
src/clientversion.h (change CLIENT_VERSION_IS_RELEASE to true)

# tag version in git

git tag -s nexa(new version, e.g. 0.8.0)

# write release notes. git shortlog helps a lot, for example:

git shortlog --no-merges nexa(current version, e.g. 1.3.0.3)..nexa(new version, e.g. 1.4.0.0)
cd ..
```

#### Setup and perform Gitian builds

Setup Gitian descriptors:

```bash
cd ./nexa
export VERSION=(new version, e.g. 2.0.0.0)
git fetch
git checkout nexa${VERSION}
cd ..
```

Ensure gitian-builder is up-to-date to take advantage of new caching features:

```bash
 cd ./gitian-builder
git pull
```


#### Fetch and create inputs: (first time, or when dependency versions change)

```
mkdir -p inputs
```

Fetch macOS SDK:

```bash
wget https://www.bitcoinunlimited.info/sdks/MacOSX11.3.sdk.tar.xz
```

#### Optional: Seed the Gitian sources cache and offline git repositories

By default, Gitian will fetch source files as needed. To cache them ahead of time:

```bash
make -C ../bitcoin/depends download SOURCES_PATH=`pwd`/cache/common
```

Only missing files will be fetched, so this is safe to re-run for each build.

NOTE: Offline builds must use the --url flag to ensure Gitian fetches only from local URLs. For example:

```bash
export USE_DOCKER=1
./bin/gbuild --url nexa=/path/to/bitcoin {rest of arguments}
```
The gbuild invocations below <b>DO NOT DO THIS</b> by default.

#### Build and sign Bitcoin for Linux, Windows, and OS X:

```bash
export USE_DOCKER=1
./bin/gbuild --commit nexa=nexa${VERSION} ../nexa/contrib/gitian-descriptors/gitian-linux-x86.yml
mv build/out/nexa-*.tar.gz build/out/src/nexa-*.tar.gz ../

./bin/gbuild --commit nexa=nexa${VERSION} ../nexa/contrib/gitian-descriptors/gitian-linux-arm.yml
mv build/out/nexa-*.tar.gz build/out/src/nexa-*.tar.gz ../

./bin/gbuild --commit nexa=nexa${VERSION} ../nexa/contrib/gitian-descriptors/gitian-win.yml
mv build/out/nexa-*-win-unsigned.tar.gz inputs/nexa-win-unsigned.tar.gz
mv build/out/nexa-*.zip build/out/nexa-*.exe ../

./bin/gbuild --commit nexa=nexa${VERSION} ../nexa/contrib/gitian-descriptors/gitian-macos-arm.yml
mv build/out/nexa-*-macos-arm64-unsigned.tar.gz inputs/nexa-macos-arm64-unsigned.tar.gz
mv build/out/nexa-*-macos-arm64.tar.gz build/out/nexa-*.dmg ../

./bin/gbuild --commit nexa=nexa${VERSION} ../nexa/contrib/gitian-descriptors/gitian-macos-x86.yml
mv build/out/nexa-*-osx-unsigned.tar.gz inputs/nexa-macos-x86-unsigned.tar.gz
mv build/out/nexa-*.tar.gz build/out/nexa-*.dmg ../
```

Build output expected:

1. source tarball (nexa-${VERSION}.tar.gz)
2. linux x86 64-bit dist tarballs (nexa-${VERSION}-linux64.tar.gz)
3. linux arm [32|64]-bit dist tarballs (nexa-${VERSION}-arm[32|64].tar.gz)
4. windows 64-bit unsigned installers and dist zips (nexa-${VERSION}-win64-setup-unsigned.exe, nexa-${VERSION}-win64.zip)
5. MacOS arm64 unsigned installer, dist tarball (nexa-${VERSION}-macos-arm64-unsigned.dmg, nexa-${VERSION}-macos-arm64.tar.gz)
6. MacOS x86 unsigned installer, dist tarball (nexa-${VERSION}-macos-x86-unsigned.dmg, nexa-${VERSION}-macos-x86.tar.gz)

#### Next steps:

##### Codesigner only: Sign the macOS arm64 binary:

- transfer nexa-$VERSION-macos-arm64-unsigned.tar.gz to macOS for signing
- tar xf nexa-$VERSION-macos-arm64-unsigned.tar.gz
- ./detached-sig-create.sh /path/to/certificate.p12
- Enter the keychain password and authorize the signature
- Move signature-macos-arm64.tar.gz to your local clone of nexa/detached-sigs repo

##### Codesigner only: Sign the macOS x86 binary:

- transfer nexa-$VERSION-macos-x86-unsigned.tar.gz to macOS for signing
- tar xf nexa-$VERSION-macos-x86-unsigned.tar.gz
- ./detached-sig-create.sh /path/to/certificate.p12
- Enter the keychain password and authorize the signature
- Move signature-macos-x86_64.tar.gz to your local clone of nexa/detached-sigs repo

##### Codesigner only: Commit your detached signature to the nexa repo

```bash
cd ~/nexa-detached-sigs #(assuming your cloned git repo is here)
#checkout the appropriate branch for this release series
rm -rf *
tar xf signature-macos-arm64.tar.gz
tar xf signature-macos-x86_64.tar.gz
git add -A
git commit -m "point to ${VERSION}"
git tag -s v${VERSION} HEAD
git push the current branch and new tag
```

##### Create the signed macOS binary:

```bash
export USE_DOCKER=1
cd ./gitian-builder

# copy the tar.gz containing the files that will be used to created the dmg files
cp releases/${VERSION}/macos_x86/nexa-${VERSION}-macos-x86-unsigned.tar.gz inputs/
cp releases/${VERSION}/macos_arm/nexa-${VERSION}-macos-arm64-unsigned.tar.gz inputs/

# if present remove or rename folders signx86 and signarm
rm -rf signx86 signarm

# strip the version from the above tar.gz files
mv nexa-${VERSION}-macos-x86-unsigned.tar.gz nexa-macos-x86-unsigned.tar.gz
mv nexa-${VERSION}-macos-arm64-unsigned.tar.gz nexa-macos-arm64-unsigned.tar.gz

# reproducing the singned dmg for macos arm64 (NB adjust the path to gitian descriptor)
./bin/gbuild -i --commit signature=v${VERSION} ../nexa/contrib/gitian-descriptors/gitian-macos-arm-signer.yml

# move the signed dmg to the release folder
mv build/out/nexa-macos-arm64-signed.dmg ../nexa-${VERSION}-macos-arm64.dmg

# reproducing the singned dmg for macos x86_64 (NB adjust the path to gitian descriptor)
./bin/gbuild -i --commit signature=v${VERSION} ../nexa/contrib/gitian-descriptors/gitian-macos-x86-signer.yml

# move the signed dmg to the release folder
mv build/out/nexa-macos-x86-signed.dmg ../nexa-${VERSION}-macos-x86.dmg
cd ..
```

