## Process this file with automake to produce Makefile.in

bin_PROGRAMS = curlftpfs

if FUSE_OPT_COMPAT
compat_sources = compat/fuse_opt.c compat/fuse_opt.h
endif

curlftpfs_SOURCES = ftpfs.c cache.c cache.h $(compat_sources)
curlftpfs_CPPFLAGS = -DFUSE_USE_VERSION=25
