package=libevent
$(package)_version=2.1.8
$(package)_download_path=https://github.com/libevent/libevent/archive/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_file=release-$($(package)_version)-stable.tar.gz
$(package)_sha256_hash=316ddb401745ac5d222d7c529ef1eada12f58f6376a66c1118eee803cb70f83d
$(package)_patches=no-op-add-bytes-without-arc4random-addrandom.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/no-op-add-bytes-without-arc4random-addrandom.patch && \
  ./autogen.sh
endef

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --disable-openssl --disable-libevent-regress
  # samples/ (dns-example, hello-world, event-read-fifo) aren't needed by csd
  # and add nothing but extra build time — harmless to skip regardless of the
  # arc4random_addrandom situation below.
  $(package)_config_opts+=--disable-samples
  # Modern glibc (>= 2.36, e.g. Ubuntu 22.04+/24.04) provides arc4random()/
  # arc4random_buf() but not the legacy BSD arc4random_addrandom()/
  # arc4random_stir() reseed hooks. libevent 2.1.8's evutil_rand.c calls
  # arc4random_addrandom() unconditionally from evutil_secure_rng_add_bytes(),
  # regardless of which PRNG path the rest of the file took — breaking the
  # final link of anything linking libevent (undefined reference) on any libc
  # missing just that one legacy symbol. See the patch above for the actual
  # fix (a no-op when the system arc4random family is in use, since it
  # self-reseeds and never needed this hint anyway).
  #
  # NOTE: do NOT try to "fix" this instead by forcing
  # ac_cv_func_arc4random(_buf)=no — that was tried first and made things
  # worse: glibc's <stdlib.h> still declares arc4random_buf() as a non-static
  # extern regardless of what the autoconf cache says, so libevent's bundled
  # fallback (compiled when the cache says "no") then tries to define a
  # *static* arc4random_buf(), a genuine conflicting-linkage compile error.
  # The patch is the only fix that doesn't depend on autoconf's arc4random
  # detection matching reality.
  $(package)_config_opts_release=--disable-debug-mode
  $(package)_config_opts_linux=--with-pic
  $(package)_config_opts_freebsd=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
