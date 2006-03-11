## Process this file with automake to produce Makefile.in
SUBDIRS = compat

bin_PROGRAMS = curlftpfs

curlftpfs_SOURCES = ftpfs.c cache.c cache.h
curlftpfs_CPPFLAGS = -DFUSE_USE_VERSION=25

if FUSE_OPT_COMPAT
curlftpfs_LDADD = compat/libcompat.la
endif
