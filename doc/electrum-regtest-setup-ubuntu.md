
# Setting up the Nexa Full Node on Linux for regtest

This tutorial will guide you through the process of setting up the Nexa (Bitcoin-like) full node on a Linux machine. By the end, you'll have a working Electrum node for REGTEST on the NEXA cryptocurrency.

## Prerequisites

- Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-32-generic x86_64) or a similar OS
- Build Nexa: https://gitlab.com/nexa/nexa#building

## Steps

### 1. Clone the Nexa repository

```bash
git clone https://gitlab.com/nexa/nexa
```

### 2. Build out-of-tree

To avoid potential build linker errors, it's recommended to build out-of-tree:

```bash
cd nexa
./autogen.sh
mkdir build
cd build
../configure
make -j`nproc`
```

### 3. Compile the Node

Compile the NEXA node with the following command:

```bash
make rostrum
```

### 4. Set Up the Configuration File for Regtest

Create a configuration file named `nexa.conf` and place it in the `.nexa` directory:

```bash
mkdir ~/.nexareg
nano ~/.nexareg/nexa.conf
```

Paste the following configuration:

```
regtest=1
#testnet=1
#nexa=1
server=1
rpcuser=regtest
rpcpassword=regtest
debug=all, -libevent
txindex=1
mining.unsafeGetBlockTemplate=1
rpcallowip=0.0.0.0/0
net.allowp2pTxVal=1
electrum=1
```

### 5. Start the Node

```bash
cd src
```

Start the Nexa node using the command below:

```bash
./nexad -datadir=/home/<user>/.nexareg
```

Verify the node is running:

```bash
ps -efwww | grep nexad
```

And check its status:

```bash
./nexa-cli -datadir=/home/<user>/.nexareg getinfo
```

And check rostrum status:
```bash
./nexa-cli -datadir=/home/<user>/.nexareg getelectruminfo
```

### 6. Generate Blocks

In regtest mode, you can produce blocks whenever needed. Generate a block:

```bash
./nexa-cli -datadir=/home/<user>/.nexareg generate 1
```

### 7. Logs
```bash
tail -f ~/.nexareg/regtest/debug.log
```

### 8. Write Tests

For testing, you can use the given scripts to handle the mempool:

```kotlin
x = mempool.size
send_transaction()
waitFor(30, { mempool.size == x+1})
```

### Additional Notes

- For code formatting, you can use:

  ```bash
  make check-formatting
  ```

  This will check the format of all files listed in `src/.formatted-files`. If you want to run the linter for just one file:

  ```bash
  contrib/devtools/clang-format.py format-stdout-if-wanted clang-format <file_path>
  ```

- For networking checks, use:

  ```bash
  nc -zv localhost 60401
  lsof -i :60401
  ```

- Remember, local addresses like `192.168.1.XX` are not routable outside their network. Ensure your devices are on the same local network during testing.

Congratulations! You now have a Nexa full node set up and running.
