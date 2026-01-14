package=rust
$(package)_version=1.91.1
$(package)_download_path=https://static.rust-lang.org/dist
$(package)_file_name=rust-$($(package)_version)-x86_64-unknown-linux-gnu.tar.gz
$(package)_sha256_hash="1c955c040dd087e4751d15588ddec288b4208bea16f8ec5046c164877e55fff7"

define $(package)_stage_cmds
  ./install.sh --destdir=$($(package)_staging_dir) --prefix=$(host_prefix)/native --disable-ldconfig
endef
