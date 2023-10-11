OSX_MIN_VERSION=11.0
OSX_SDK_VERSION=11.3
OSX_SDK=$(SDK_PATH)/MacOSX$(OSX_SDK_VERSION).sdk
LD64_VERSION=609

darwin_native_toolchain=native_cctools

clang_prog=$(build_prefix)/bin/clang
clangxx_prog=$(clang_prog)++
llvm_config_prog=$(build_prefix)/bin/llvm-config


cctools_TOOLS=AR RANLIB STRIP NM LIBTOOL OTOOL INSTALL_NAME_TOOL DSYMUTIL

# Make-only lowercase function
lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

# For well-known tools provided by cctools, make sure that their well-known
# variable is set to the full path of the tool, just like how AC_PATH_{TOO,PROG}
# would.
$(foreach TOOL,$(cctools_TOOLS),$(eval darwin_$(TOOL) = $$(build_prefix)/bin/$$(host)-$(call lc,$(TOOL))))

# Flag explanations:
#
#     -mlinker-version
#
#         Ensures that modern linker features are enabled. See here for more
#         details: https://github.com/bitcoin/bitcoin/pull/19407.
#
#     -B$(build_prefix)/bin
#
#         Explicitly point to our binaries (e.g. cctools) so that they are
#         ensured to be found and preferred over other possibilities.
#
#     -isysroot$(OSX_SDK) -nostdlibinc
#
#         Disable default include paths built into the compiler as well as
#         those normally included for libc and libc++. The only path that
#         remains implicitly is the clang resource dir.
#
#     -iwithsysroot / -iframeworkwithsysroot
#
#         Adds the desired paths from the SDK
#

darwin_CC=env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
              -u OBJC_INCLUDE_PATH -u OBJCPLUS_INCLUDE_PATH -u CPATH \
              -u LIBRARY_PATH \
            $(clang_prog) --target=$(host) -mmacosx-version-min=$(OSX_MIN_VERSION) \
              -B$(build_prefix)/bin -mlinker-version=$(LD64_VERSION) \
              -isysroot$(OSX_SDK) -nostdlibinc \
              -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks

darwin_CXX=env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
               -u OBJC_INCLUDE_PATH -u OBJCPLUS_INCLUDE_PATH -u CPATH \
               -u LIBRARY_PATH \
             $(clangxx_prog) --target=$(host) -mmacosx-version-min=$(OSX_MIN_VERSION) \
               -B$(build_prefix)/bin -mlinker-version=$(LD64_VERSION) \
               -isysroot$(OSX_SDK) -nostdlibinc \
               -iwithsysroot/usr/include/c++/v1 \
               -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)
