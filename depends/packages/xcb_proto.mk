package=xcb_proto
$(package)_version=1.15.1
$(package)_download_path=https://xorg.freedesktop.org/archive/individual/proto
$(package)_file_name=xcb-proto-$($(package)_version).tar.xz
$(package)_sha256_hash=270eed15a98207fff89dc40a4a7ea31425fc7059d641227856bdd9191c2718ae

define $(package)_set_vars
  $(package)_config_opts=--disable-shared  --enable-option-checking
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf lib/python*/site-packages/xcbgen/__pycache__
endef
