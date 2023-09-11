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

cIncludes := -I${srcDir}/cashlib -I${srcDir} -I${srcDir}/rsm/include -I${srcDir}/script -I${srcDir}/config  -I${srcDir}/validation -I${srcDir}/secp256k1/include -I${srcDir}/secp256k1 -I${srcDir}/secp256k1/src -I${srcDir}/cashlib/boost
cxxflags := ${CXXFLAGS} -c -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -D${PLATFORM} -DLIGHT -fPIC -Wno-tautological-constant-compare -std=gnu++17 ${cIncludes}
cflags := ${CFLAGS} -c -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -D${PLATFORM} -DLIGHT -fPIC -Wno-tautological-constant-compare -DHAVE_CONFIG_H -DVERIFY ${cIncludes}


all: ${BUILD_DIR}/libnexalight.a ${BUILD_DIR}/libnexalight.so


${BUILD_DIR}/libnexalight.a: ${srcObjs}
	${AR} rvs $@ $^

${BUILD_DIR}/libnexalight.so: ${srcObjs}
	${CXX} -shared -o $@ $^
# android?	${CXX} -shared -Wl,-soname,$@ -o $@ $^


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

${BUILD_DIR}/%.o: ../support/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../consensus/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../validation/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../secp256k1/src/%.c
	${CC} ${cflags} -o $@ $<

${BUILD_DIR}/%.o: sqlite/%.c
	${CC} ${cflags} -o $@ $<
