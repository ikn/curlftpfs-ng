EXTRA_DIST = run_tests.sh

noinst_PROGRAMS = ftpfs-ls_unittest

ftpfs_ls_unittest_SOURCES = ftpfs-ls_unittest.c ../ftpfs-ls.c ../ftpfs-ls.h ../cache.h ../cache.c
ftpfs_ls_unittest_CPPFLAGS = -DFUSE_USE_VERSION=25

if FUSE_OPT_COMPAT
ftpfs_ls_unittest_LDADD = ../compat/libcompat.la
endif

test: all
	@./run_tests.sh
