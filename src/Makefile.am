# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = rsm secp256k1 univalue

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
if ENABLE_GPERF
AM_CXXFLAGS = -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free $(HARDENED_CPPFLAGS)
else
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
endif
if ENABLE_GPERF
AM_CXXFLAGS += -pg
AM_CPPFLAGS += -pg
AM_LDFLAGS  += -pg
endif
if ENABLE_GPROF
AM_CXXFLAGS += -pg
AM_CPPFLAGS += -pg
AM_LDFLAGS  += -pg
endif
if ENABLE_MUTRACE
AM_CXXFLAGS += -O0 -g -rdynamic
AM_CPPFLAGS += -O0 -g -rdynamic
AM_LDFLAGS  += -O0 -g -rdynamic
endif
if ENABLE_JAVACASHLIB
JNI_CXXFLAGS = -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/include -DJAVA
endif

#EXTRA_LIBRARIES = libgmp.a
EXTRA_LIBRARIES =

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
NEXA_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

NEXA_INCLUDES += -I$(srcdir)/secp256k1/include
NEXA_INCLUDES += -I$(srcdir)/univalue/include
NEXA_INCLUDES += -I$(srcdir)/rsm/include

LIBNEXA_SERVER=libnexa_server.a
LIBNEXA_COMMON=libnexa_common.a
LIBNEXA_CLI=libnexa_cli.a
LIBNEXA_UTIL=libnexa_util.a
LIBNEXA_CRYPTO=crypto/libnexa_crypto.a
LIBNEXA_CRYPTO_SSE41=crypto/libnexa_crypto_sse41.a
LIBNEXA_CRYPTO_AVX2=crypto/libnexa_crypto_avx2.a
LIBNEXAQT=qt/libnexaqt.a
LIBRSM=rsm/librsm.la
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBUNIVALUE=univalue/libunivalue.la

if ENABLE_ZMQ
LIBNEXA_ZMQ=libnexa_zmq.a
endif

if BUILD_NEXA_LIBS
LIBBITCOINCASH=libnexa.la
endif

if ENABLE_WALLET
LIBNEXA_WALLET=libnexa_wallet.a
endif

$(LIBRSM): $(wildcard rsm/lib/*) $(wildcard rsm/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBNEXA_CRYPTO) \
  $(LIBNEXA_CRYPTO_SSE41) \
  $(LIBNEXA_CRYPTO_AVX2) \
  $(LIBNEXA_UTIL) \
  $(LIBNEXA_COMMON) \
  $(LIBNEXA_SERVER) \
  $(LIBNEXA_CLI) \
  $(LIBNEXA_WALLET) \
  $(LIBNEXA_ZMQ)

lib_LTLIBRARIES = $(LIBBITCOINCASH)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += nexad
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += nexa-cli nexa-tx nexa-miner
endif

.PHONY: FORCE check-symbols check-security check-formatting
# bitcoin core #
BITCOIN_CORE_H = \
  addrman.h \
  allowed_args.h \
  base58.h \
  bandb.h \
  banentry.h \
  bitmanip.h \
  blockrelay/blockrelay_common.h \
  blockrelay/compactblock.h \
  blockrelay/graphene.h \
  blockrelay/graphene_set.h \
  blockrelay/mempool_sync.h \
  blockrelay/thinblock.h \
  blockstorage/blockleveldb.h \
  blockstorage/blockstorage.h \
  blockstorage/dbabstract.h \
  blockstorage/sequential_files.h \
  blockstorage/blockcache.h \
  bitnodes.h \
  bloom.h \
  capd/capd.h \
  cashaddr.h \
  cashaddrenc.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/cpuid_compat.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  config.h \
  connmgr.h \
  consensus/consensus.h \
  consensus/grouptokens.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  DoubleSpendProof.h \
  DoubleSpendProofStorage.h \
  deadlock-detection/locklocation.h \
  deadlock-detection/lockorder.h \
  deadlock-detection/threaddeadlock.h \
  dosman.h \
  dstencode.h \
  expedited.h \
  electrum/electrumrpcinfo.h \
  electrum/electrumserver.h \
  electrum/rostrum.h \
  extversionmessage.h \
  extversionkeys.h \
  fast-cpp-csv-parser/csv.h \
  fastfilter.h \
  forks_csv.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  iblt.h \
  iblt_params.h \
  index/txindex.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  logging.h \
  main.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  nodestate.h \
  leakybucket.h \
  netaddress.h \
  netbase.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/mempool.h \
  pow.h \
  protocol.h \
  random.h \
  randomenv.h \
  reverse_iterator.h \
  reverselock.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  respend/respendaction.h \
  respend/respendlogger.h \
  respend/respendrelayer.h \
  respend/respenddetector.h \
  script/bignum.h \
  script/pushtxstate.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  script/scripttemplate.h \
  script/stackitem.h \
  span.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/pagelocker.h \
  sync.h \
  threadgroup.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txadmission.h \
  txdb.h \
  txdebugger.h \
  txlookup.h \
  txmempool.h \
  txorphanpool.h \
  ui_interface.h \
  undo.h \
  unlimited.h \
  utilhttp.h \
  utilprocess.h \
  stat.h \
  tweak.h \
  requestManager.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation/forks.h \
  validation/parallel.h \
  validation/validation.h \
  validation/verifydb.h \
  validationinterface.h \
  versionbits.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/grouptokenwallet.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libnexa_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between nexad and nexa-qt
libnexa_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libnexa_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_server_a_SOURCES = \
  globals.cpp \
  addrman.cpp \
  bandb.cpp \
  banentry.cpp \
  bitnodes.cpp \
  blockrelay/blockrelay_common.cpp \
  blockrelay/compactblock.cpp \
  blockrelay/graphene.cpp \
  blockrelay/graphene_set.cpp \
  blockrelay/mempool_sync.cpp \
  blockrelay/thinblock.cpp \
  blockstorage/blockleveldb.cpp \
  blockstorage/sequential_files.cpp \
  blockstorage/blockstorage.cpp \
  blockstorage/blockcache.cpp \
  bloom.cpp \
  capd/capd.cpp \
  capd/capd_rpc.cpp \
  chain.cpp \
  checkpoints.cpp \
  connmgr.cpp \
  consensus/adaptive_blocksize.cpp \
  consensus/grouptokens.cpp \
  consensus/tx_verify.cpp \
  DoubleSpendProof.cpp \
  DoubleSpendProofStorage.cpp \
  dosman.cpp \
  expedited.cpp \
  electrum/electrumrpcinfo.cpp \
  electrum/electrumserver.cpp \
  electrum/rostrum.cpp \
  extversionmessage.cpp \
  forks_csv.cpp \
  httprpc.cpp \
  httpserver.cpp \
  iblt.cpp \
  index/txindex.cpp \
  init.cpp \
  dbwrapper.cpp \
  logging.cpp \
  main.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  nodestate.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/client.cpp \
  rpc/electrum.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/nexa.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  respend/respendlogger.cpp \
  respend/respendrelayer.cpp \
  respend/respenddetector.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  script/scriptattributes.cpp \
  span.h \
  timedata.cpp \
  torcontrol.cpp \
  txadmission.cpp \
  txdb.cpp \
  txlookup.cpp \
  txmempool.cpp \
  txorphanpool.cpp \
  tweak.cpp \
  unlimited.cpp \
  utilhttp.cpp \
  utilprocess.cpp \
  requestManager.cpp \
  validation/forks.cpp \
  validation/parallel.cpp \
  validation/validation.cpp \
  validation/verifydb.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_ZMQ
libnexa_zmq_a_CPPFLAGS = $(NEXA_INCLUDES) $(ZMQ_CFLAGS)
libnexa_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp
endif


# wallet: shared between nexad and nexa-qt, but only linked
# when wallet enabled
libnexa_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
libnexa_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_wallet_a_SOURCES = \
  wallet/coinselection.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/grouptokenwallet.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  $(BITCOIN_CORE_H)

if TARGET_LINUX
libnexa_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
libnexa_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

libnexa_a_SOURCES = \
  cashlib/cashlib.cpp \
  base58.cpp \
  base58.h \
  merkleblock.cpp \
  merkleblock.h \
  chainparams.cpp \
  chainparams.h \
  chainparamsbase.cpp \
  chainparamsbase.h \
  script/sigcommon.cpp \
  hashwrapper.cpp \
  hashwrapper.h \
  key.cpp \
  key.h \
  keystore.cpp \
  keystore.h \
  coins.h \
  coins.cpp \
  compat/cpuid_compat.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  primitives/satoshiTransaction.h \
  primitives/satoshiblock.h \
  pubkey.cpp \
  pubkey.h \
  random.cpp \
  random.h \
  randomenv.h \
  randomenv.cpp \
  script/bitfield.cpp \
  script/bitfield.h \
  script/pushtxstate.cpp \
  script/pushtxstate.h \
  script/interpreter.cpp \
  script/interpreter.h \
  script/bignum.cpp \
  script/bignum.h \
  script/standard.cpp \
  script/standard.h \
  script/stackitem.cpp \
  script/stackitem.h \
  script/script.cpp \
  script/script.h \
  script/script_error.h \
  script/script_error.cpp \
  script/scriptattributes.cpp \
  script/scripttemplate.cpp \
  script/sign.cpp \
  script/sign.h \
  consensus/grouptokens.cpp \
  consensus/grouptokens.h \
  support/pagelocker.cpp \
  support/pagelocker.h \
  support/cleanse.cpp \
  support/cleanse.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  cashaddrenc.cpp \
  cashaddrenc.h \
  cashaddr.cpp \
  cashaddr.h \
  utiltime.cpp \
  utiltime.h \
  consensus/merkle.cpp \
  arith_uint256.cpp \
  arith_uint256.h \
  bloom.cpp \
  bloom.h \
  streams.h
endif


# crypto primitives library
crypto_libnexa_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libnexa_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libnexa_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

if USE_ASM
crypto_libnexa_crypto_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libnexa_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libnexa_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
if ENABLE_SSE41
crypto_libnexa_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libnexa_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
endif
crypto_libnexa_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libnexa_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libnexa_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
if ENABLE_AVX2
crypto_libnexa_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libnexa_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
endif
crypto_libnexa_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

# common: shared between nexad, and nexa-qt and non-server tools
libnexa_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
libnexa_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_common_a_SOURCES = \
  amount.cpp \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  base58.cpp \
  cashaddr.cpp \
  cashaddrenc.cpp \
  chain.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  config.cpp \
  consensus/adaptive_blocksize.cpp \
  consensus/adaptive_blocksize.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  consensus/grouptokens.cpp \
  consensus/grouptokens.h \
  core_read.cpp \
  core_write.cpp \
  dstencode.cpp \
  hashwrapper.cpp \
  hashwrapper.h \
  logging.h \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  primitives/satoshiTransaction.h \
  primitives/satoshiblock.h \
  protocol.cpp \
  pubkey.cpp \
  pubkey.h \
  script/scriptattributes.cpp \
  script/bitcoinconsensus.cpp \
  script/bitcoinconsensus.h \
  script/bitfield.cpp \
  script/bitfield.h \
  script/bignum.cpp \
  script/bignum.h \
  script/pushtxstate.cpp \
  script/pushtxstate.h \
  script/interpreter.cpp \
  script/interpreter.h \
  script/stackitem.cpp \
  script/stackitem.h \
  script/sigcommon.cpp \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  script/scripttemplate.cpp \
  script/sighashtype.h \
  script/sign.cpp \
  script/standard.cpp \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h \
  versionbits.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libnexa_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
libnexa_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_util_a_SOURCES = \
  support/pagelocker.cpp \
  allowed_args.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  deadlock-detection/locklocation.cpp \
  deadlock-detection/lockorder.cpp \
  deadlock-detection/threaddeadlock.cpp \
  fs.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  ui_interface.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT
libnexa_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: shared between nexa-cli and nexa-qt
libnexa_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES) $(EVENT_CFLAGS)
libnexa_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnexa_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)

nodist_libnexa_util_a_SOURCES = $(srcdir)/obj/build.h
#

# nexad binary #
nexad_SOURCES = nexad.cpp
nexad_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
nexad_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nexad_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
nexad_SOURCES += nexad-res.rc
endif

nexad_LDADD = \
  $(LIBNEXA_SERVER) \
  $(LIBNEXA_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBNEXA_UTIL) \
  $(LIBNEXA_WALLET) \
  $(LIBNEXA_ZMQ) \
  $(LIBNEXA_CRYPTO) \
  $(LIBNEXA_CRYPTO_SSE41) \
  $(LIBNEXA_CRYPTO_AVX2) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBRSM) \
  $(LIBSECP256K1)


nexad_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# nexa-cli binary #
nexa_cli_SOURCES = nexa-cli.cpp
nexa_cli_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES) $(EVENT_CFLAGS)
nexa_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nexa_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
nexa_cli_SOURCES += nexa-cli-res.rc
endif

nexa_cli_LDADD = \
  $(LIBNEXA_CLI) \
  $(LIBUNIVALUE) \
  $(LIBNEXA_UTIL) \
  $(LIBNEXA_CRYPTO) \
  $(LIBNEXA_CRYPTO_SSE41) \
  $(LIBNEXA_CRYPTO_AVX2) \
  $(LIBRSM)

nexa_cli_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# nexa tx binary #
nexa_tx_SOURCES = nexa-tx.cpp
nexa_tx_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES)
nexa_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nexa_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
nexa_tx_SOURCES += nexa-tx-res.rc
endif

nexa_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBNEXA_COMMON) \
  $(LIBNEXA_UTIL) \
  $(LIBNEXA_CRYPTO) \
  $(LIBNEXA_CRYPTO_SSE41) \
  $(LIBNEXA_CRYPTO_AVX2) \
  $(LIBSECP256K1) \
  $(LIBRSM)

nexa_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# nexa-miner binary #
nexa_miner_SOURCES = nexa-miner.cpp \
  pow.cpp \
  arith_uint256.cpp \
  arith_uint256.h \
  validation/forks.cpp \
  validation/forks.h \
  uint256.cpp \
  uint256.h


nexa_miner_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES) $(EVENT_CFLAGS)
nexa_miner_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nexa_miner_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
nexa_miner_SOURCES += nexa-miner-res.rc
endif

nexa_miner_LDADD = \
  $(LIBNEXA_CLI) \
  $(LIBUNIVALUE) \
  $(LIBNEXA_COMMON) \
  $(LIBNEXA_UTIL) \
  $(LIBNEXA_CRYPTO) \
  $(LIBNEXA_CRYPTO_SSE41) \
  $(LIBNEXA_CRYPTO_AVX2) \
  $(LIBRSM) \
  $(LIBSECP256K1)

nexa_miner_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# nexa library #
if BUILD_NEXA_LIBS
libnexa_la_SOURCES = $(libnexa_a_SOURCES) $(crypto_libnexa_crypto_a_SOURCES)

if GLIBC_BACK_COMPAT
libnexa_la_SOURCES += compat/glibc_compat.cpp
endif

libnexa_la_LDFLAGS = $(AM_LDFLAGS) $(CRYPTO_LIBS) $(BOOST_LIBS) -no-undefined $(RELDFLAGS) $(PTHREAD_FLAGS)
libnexa_la_LIBADD = $(LIBSECP256K1)
libnexa_la_CPPFLAGS = $(AM_CPPFLAGS) $(NEXA_INCLUDES) -I$(BOOST_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include $(JNI_CXXFLAGS) -DBUILD_BITCOIN_INTERNAL
libnexa_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
endif
#

CLEANFILES = $(EXTRA_LIBRARIES)

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = leveldb $(CTAES_DIST)

clean-local:
	-$(MAKE) -C rsm clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if TARGET_DARWIN
	@echo "Checking macOS dynamic libraries..."
	$(AM_V_at) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if TARGET_WINDOWS
	@echo "Checking Windows dynamic libraries..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

check-formatting:
	@echo "Checking source formatting style..."
	(cd $(top_srcdir)/src; ../contrib/devtools/clang-format.py check clang-format-12 `cat ./.formatted-files`)

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
