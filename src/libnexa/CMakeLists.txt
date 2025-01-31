# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.22.1)

message(STATUS "Nexa fullnode libnexa cmake is running")

set(CMAKE_C_FLAGS "")
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS "")
set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")

set(CMAKE_VERBOSE_MAKEFILE ON)

# set(CMAKE_OSX_ARCHITECTURES "zzzzarm64" CACHE STRING "" FORCE)
# set(CMAKE_OSX_DEPLOYMENT_TARGET $ENV{CMAKE_OSX_DEPLOYMENT_TARGET} CACHE STRING "Min OSX ver")
set(CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE STRING "Force unset of the deployment target for iOS" FORCE)
# set(CMAKE_OSX_SYSROOT $ENV{SYSROOT} CACHE STRING "target system root")
set(CMAKE_OSX_SYSROOT "" CACHE STRING "force unset of sysroot" FORCE)

set(COMPILE_OPTIONS "" CACHE STRING "" FORCE)
set(COMPILE_FLAGS "" CACHE STRING "" FORCE)

project(libnexa)
set(CMAKE_VERBOSE_MAKEFILE ON)
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.


add_definitions(-DLIGHT -DANDROID -Wno-tautological-constant-compare -DBOOST_SYSTEM_NO_DEPRECATED)

set(libsrc
             # Provides a relative path to your source file(s).
             libnexa.cpp
             libnexa_jvm.cpp
             libnexa_common.cpp
             libnexa_common.h
             ../config.cpp
             ../config.h
             ../base58.cpp
             ../script/interpreter.cpp
             ../script/op_parse.cpp
             ../script/script.cpp
             ../script/script.h
             ../script/scripttemplate.cpp
             ../script/scriptattributes.cpp
             ../script/stackitem.cpp
             ../script/pushtxstate.cpp
             ../script/bignum.cpp
             ../primitives/transaction.cpp
             ../primitives/block.cpp
             ../primitives/block.h
             ../support/pagelocker.cpp
             ../support/cleanse.cpp
             ../script/sigcommon.cpp
             ../script/bitfield.cpp
             ../script/bitfield.h
             ../capd/capdmsg.cpp
             ../capd/capd.h
             ../crypto/aes.cpp
             ../crypto/aes.h
             ../crypto/chacha20.cpp
             ../crypto/chacha20.h
             ../crypto/sha256.cpp
             ../crypto/hmac_sha512.cpp
             ../crypto/hmac_sha512.h
             ../crypto/sha512.cpp
             ../crypto/sha512.h
             ../crypto/ripemd160.cpp
             ../crypto/ripemd160.h
             ../crypto/sha1.cpp
             ../crypto/sha1.h
             ../dstencode.cpp
             ../dstencode.h
             ../pow.cpp
             ../hashwrapper.cpp
             ../hashwrapper.h
             ../key.cpp
             ../key.h
             ../uint256.cpp
             ../uint256.h
             ../utilstrencodings.cpp
             ../utilstrencodings.h
	     ../utilgrouptoken.cpp
             ../cashaddrenc.cpp
             ../cashaddrenc.h
             ../cashaddr.cpp
             ../cashaddr.h
             ../pubkey.cpp
             ../pubkey.h
             ../secp256k1/src/secp256k1.c
             ../chainparamsbase.cpp
             ../chainparams.cpp
             ../chainparams.h
             ../consensus/merkle.cpp
             ../consensus/grouptokens.cpp
             ../consensus/grouptokens.h
             ../arith_uint256.cpp
             ../arith_uint256.h
             ../bloom.cpp
             ../bloom.h
             ../merkleblock.cpp
             ../merkleblock.h
             ../streams.h
             ../random.cpp
             ../random.h
             ../randomenv.cpp
             ../randomenv.h
             ../validation/headervalidation.cpp
             )

add_library(objlib OBJECT ${libsrc})
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)
target_compile_features(objlib PRIVATE cxx_std_17)

# shared and static libraries built from the same object files
add_library(nexalight SHARED $<TARGET_OBJECTS:objlib>)
add_library(nexalighta STATIC $<TARGET_OBJECTS:objlib>)
target_compile_features(nexalight PRIVATE cxx_std_17)
target_compile_features(nexalighta PRIVATE cxx_std_17)

SET(OPT_SELECTION "-DHAVE_CONFIG_H -DVERIFY")
SET_SOURCE_FILES_PROPERTIES(../secp256k1/src/secp256k1.c PROPERTIES COMPILE_FLAGS ${OPT_SELECTION} )

# broken but should work
# set(Boost_USE_STATIC_LIBS OFF)
# set(Boost_USE_MULTITHREADED ON)
# set(Boost_USE_STATIC_RUNTIME OFF)
# set(Boost_DEBUG ON)
# set(Boost_NO_BOOST_CMAKE ON)
#set(BOOST_ROOT /fast/bitcoin/boostAndroid/boost_1_67_0)
#or maybe
#set(BOOST_ROOT /fast/bitcoin/boostAndroid/build/out/${ANDROID_ABI})
# set(BOOST_INCLUDEDIR /fast/bitcoin/boostAndroid/boost_1_67_0/boost)

#find_package(Boost 1.67.0 REQUIRED
#  COMPONENTS system
#  )
# HINTS /fast/bitcoin/boostAndroid/boost_1_67_0/boost
#)

# We expect that you have built boost in the libnexa subdirectory.  Run the ./buildBoostAndroid.sh script in the libnexa directory to do this.
set( Boost_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/boost/stage/lib)
set( Boost_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/boost)

# No boost libraries are currently needed (just the headers)
# file(GLOB F1 ${Boost_LIB_DIR}/libboost_thread-clang-mt-*-1_70.a)
# file(GLOB F2 ${Boost_LIB_DIR}/libboost_system-clang-mt-*-1_70.a)
#set( Boost_LIBRARIES ${F1} ${F2} )
set( Boost_LIBRARIES )

include_directories( .
  ..
  ../script
  ../config
  ../secp256k1/include
  ../secp256k1
  ../secp256k1/src
  ${Boost_INCLUDE_DIRS}
  )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

# if you need boost libraries again someday
# set_target_properties(nexalight PROPERTIES LINK_FLAGS -L/fast/bitcoin/boostAndroid/build/out/${ANDROID_ABI}/lib)


#target_compile_features(nexalighta PRIVATE cxx_std_17)
SET(CMAKE_CXX_FLAGS  "-std=c++17 ${CMAKE_CXX_FLAGS}")

target_link_libraries( # Specifies the target library.
                       nexalight
                       # Links the target library to these libraries
                       android  # base android library
                       log  # android log library
                       # ${Boost_LIBRARIES}
                       )

target_link_libraries( # Specifies the target library.
                       nexalighta
                       # Links the target library to these libraries
                       android  # base android library
                       log  # android log library
                       c++_static
                       # ${Boost_LIBRARIES}
                       )
