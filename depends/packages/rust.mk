package=rust
$(package)_version=1.80.1
$(package)_download_path=https://static.rust-lang.org/dist
$(package)_file_name=rust-$($(package)_version)-x86_64-unknown-linux-gnu.tar.gz
$(package)_sha256_hash=9eedaea9719914a0f4673899aa11693607f25486569913fcca5905ef1da784ec

define $(package)_stage_cmds
  ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(host_prefix)/native --disable-ldconfig
endef
