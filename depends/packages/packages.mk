packages:= libgmp

openssl_packages:=openssl

boost_packages:=boost

boost_header_packages:=boost_headers

libevent_packages:=libevent

zeromq_packages:=zeromq

qt_packages = qrencode

qt_linux_packages:=qt expat dbus libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm

qt_darwin_packages=qt
qt_mingw32_packages=qt


wallet_packages=bdb
rust_packages=rust
upnp_packages=miniupnpc

$(host_arch)_$(host_os)_native_boost_packages += native_b2

darwin_native_packages = native_biplist native_ds_store native_mac_alias

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_clang native_libtapi native_cdrkit native_libdmg-hfsplus
endif
