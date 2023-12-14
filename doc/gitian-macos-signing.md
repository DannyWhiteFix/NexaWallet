Signing macOS
============

This guide describes all the steps needed to sign `.dmg` file that have to be installed
on macOS machine (both x86 and arm archs)


Prerequisites
-------------

You need to get a certificate, see these [documentation](https://developer.apple.com/support/certificates/)
to get more details.

There are different types of certificate, in this document we assume you create the one needed to properly
distribute our software outside of the Apple Apps store.

Once the certificate has been created, downloaded to your osx machine. Then you need to import in
KeyChain Access app (the one you've made the certificate requested on Apple Developer) so that you
can export it into `.p12` format. This is format is the one we are going to use to sign nexa `.dmg` file.

In the process of exporting it using the "Personal Information Exchange" format, you will be asked to
set a passphrase to protect the file itself. In fact that file contains both the public and the private key,
hence the need to protect it to be read from people that are not supposed to have access to it.

So now we have you apple certificate stored in a specific location on your machine.

Signing dmg
------------

Assuming that:

- [signapple](https://github.com/achow101/signapple) is installed in your machine store
- `RELVER` env variable is initialized to the current nexa version
- `ARCH` env variable contains either one of those 2 strings `arm64` or `x86`

Store nexa-$RELVER-macos-$ARCH-unsigned.tar.gz, produced by the gitian building steps, and `detached-sig-create.sh`,
script you could find in `/contrib/macdeploy`, in the same location. To produce the detached signature execute
the following shell commands:

```sh
tar xf nexa-$RELVER-macos-$ARCH-unsigned.tar.gz
./detached-sig-create.sh /path/to/certificate.p12
# enter the pass phrase
```

At the end this archive will be produced `signature-macos-$ARCH.tar.gz`

To verify that the produced signature attach properly you need to place `nexa-$RELVER-macos-$ARCH-unsigned.tar.gz` and
the putput of the previous step `signature-macos-$ARCH.tar.gz` on the same direcotory and do the following:

```sh
tar xf nexa-$RELVER-macos-$ARCH-unsigned.tar.gz
tar xf signature-macos-$ARCH.tar.gz
OSX_VOLNAME="$(cat osx_volname)"
./detached-sig-apply.sh dist/Nexa-Qt.app osx/dist
```

After the last command you should see an output like the following on the terminal:

```
Code signature applied
Code signature is valid
Signed: signed-app
```

The last step would be to check if the actual signed application would run on the intended
macOS/arch combination as expected.

To do that we need to create a `.dmg` file starting from the signed application, hence we
need to execute the following commands

```
xorrisofs -D -l -V "Nexa" -no-pad -r -dir-mode 0755 -o uncompressed.dmg signed-app
./dmg dmg ./uuncompressed.dmg" nexa-$RELVER-macos-$ARCH.dmg¶
```

Mind you the produced `dmg` is not deterministic but you should be able to install it on macOS machine and
successfully run it.

Gitian builder should be using `gitian-osx-arm64-signer.yml` and `gitian-osx-x86-signer.yml` to produce
a deterministic signed `dmg` file.

Now we need to upload the public repo where we store the detached signature, so that other gitian builder could
fetch it and apply it to the unsigned `dmg` file.

A further verification that the installed app is properly signed would be to use `codesign` program on the macOS
machine where you just installed the app and run:

```sh
$> cd /Applications/Nexa-Qt.app/Contents/MacOS
$> codesign -dv -r - ./Nexa-Qt
```

The output would be something along those lines if you have signed your app properly

```
Executable=/Applications/Nexa-Qt.app/Contents/MacOS/Nexa-Qt
Identifier=org.bitcoinunlimited.Nexa-Qt
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=56264 flags=0x0(none) hashes=1751+3 location=embedded
Signature size=9064
Timestamp=11 Dec 2023 at 16:20:52
Info.plist entries=19
TeamIdentifier=8A87667ULD
Sealed Resources version=2 rules=13 files=12
designated => identifier "org.bitcoinunlimited.Nexa-Qt" and anchor apple generic and certificate leaf[subject.OU] = "8A87667ULD"
```

Further Steps
-------------

https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

Basically the dmg signed file need to be uploaded to the apple servers and they will vouch the software
in a way that once installed the usual dialog telling the user that the software has just been downloaded
form internet would not appear

Just signing would not remove that dialog.

misc: modify the gitian descriptor to remove linker added signature to osx binaries
further step: notirize the signed dmg file
