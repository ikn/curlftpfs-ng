## Process this file with automake to produce Makefile.in
SUBDIRS = compat doc

DIST_SUBDIRS = $(SUBDIRS) tests

bin_PROGRAMS = curlftpfs

curlftpfs_SOURCES = ftpfs.c ftpfs.h cache.c cache.h ftpfs-ls.c ftpfs-ls.h
curlftpfs_CPPFLAGS = -DFUSE_USE_VERSION=25

if FUSE_OPT_COMPAT
curlftpfs_LDADD = compat/libcompat.la
endif

check: test

test:
	@(cd tests; $(MAKE) test)
