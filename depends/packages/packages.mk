packages:=boost openssl libevent zeromq libgmp

qt_native_packages = native_protobuf
qt_packages = qrencode protobuf

qt_linux_packages:=qt expat dbus libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm

qt_darwin_packages=qt
qt_mingw32_packages=qt


wallet_packages=bdb
rust_packages=rust
upnp_packages=miniupnpc

darwin_native_packages = native_biplist native_ds_store native_mac_alias

$(host_arch)_$(host_os)_native_packages += native_b2

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_clang native_libtapi native_cdrkit native_libdmg-hfsplus
endif
