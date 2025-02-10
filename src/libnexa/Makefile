# This is a standalone makefile the produces libnexalight.so/.a for light client wallets.
# This is a subset of the normal libnexa.so.  It cannot execute scripts.

# It expects BUILD_DIR, TARGET, CXX, CC, LD, AR, AS, RANLIB, STRIP variables to be set
# and the object files will be built in the current directory

makefilePath := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
srcDir := $(abspath ${makefilePath}/..)

srcFilenames := $(shell cat nexalightcfiles.txt)
# $(warning ${srcFilenames})

# linuxX64
# srcFilenames += crypto/sha256_avx2.cpp crypto/sha256_sse41.cpp crypto/sha256_sse4.cpp

srcFilePath := $(addprefix $(srcDir)/, $(srcFilenames))

srcObjs := $(addprefix ${BUILD_DIR}/,$(addsuffix .o,$(basename $(notdir ${srcFilePath}))))
# $(warning ${srcObjs})

cIncludes := -I${srcDir}/libnexa -I${srcDir} -I${srcDir}/script -I${srcDir}/config  -I${srcDir}/validation -I${srcDir}/secp256k1/include -I${srcDir}/secp256k1 -I${srcDir}/secp256k1/src -I${srcDir}/libnexa/boost
cxxflags := ${CXXFLAGS} -c -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -D${PLATFORM} -DLIGHT -DBUILD_ONLY_LIBNEXA -fPIC -Wno-tautological-constant-compare -std=gnu++17 ${cIncludes}
cflags := ${CFLAGS} -c -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -D${PLATFORM} -DLIGHT -DBUILD_ONLY_LIBNEXA -fPIC -Wno-tautological-constant-compare -DHAVE_CONFIG_H -DVERIFY ${cIncludes}


all: ${BUILD_DIR}/libnexalight.a ${BUILD_DIR}/libnexalight.so

# ARE YOU GETTING?: make[1]: *** No rule to make target 'file.o', needed by '/fast/nexa/lnk/libnexa/nexa/build_LINUX_host/lightbuild/libnexalight.so'.  Stop.
# You need to add the directory of your new file into the build rules below

${BUILD_DIR}/libnexalight.a: ${srcObjs}
	${AR} rvs $@ $^

# why the flock? occasionally: lightbuild/sqlite3.o: file not recognized: file truncated
# BUT when you ls the file it is NOT truncated.  This is the last file to be built.  There appears to be a bug in make waiting before launching dependent tasks
# .o file is touched right away, so it exists, triggering this rule to run.  But it has not been fully written
${BUILD_DIR}/libnexalight.so: ${srcObjs}
	[ "$$(uname)" = "Darwin" ] && (sleep 3 && echo 'sleeping on macOS') || flock /tmp/compiled.lock -c 'echo sqlite file is ready'
	${CXX} -shared -o $@ $^

${BUILD_DIR}/%.o: %.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../script/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../primitives/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../crypto/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../capd/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../support/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../consensus/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../validation/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../secp256k1/src/%.c
	${CC} ${cflags} -o $@ $<

${BUILD_DIR}/%.o: sqlite/%.c
	[ "$$(uname)" = "Darwin" ] && (${CC} ${cflags} -o $@ $<) || flock -x /tmp/compiled.lock -c '${CC} ${cflags} -o $@ $< && sync'
