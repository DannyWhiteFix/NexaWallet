package=boost
$(package)_version=1_86_0
$(package)_download_path=https://archives.boost.io/release/$(subst _,.,$($(package)_version))/source/
$(package)_file_name=boost_$($(package)_version).tar.bz2
$(package)_sha256_hash=1bed88e40401b2cb7a1f76d4bab499e352fa4d0c5f31c0dbae64e24d34d7513b

define $(package)_stage_cmds
  mkdir $($(package)_staging_prefix_dir)/include && cp -R ./boost $($(package)_staging_prefix_dir)/include
endef
