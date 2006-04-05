#ifndef __CURLFTPFS_FTPFS_LS_H__
#define __CURLFTPFS_FTPFS_LS_H__

#include "cache.h"

int parse_dir(const char* list, const char* dir,
              const char* name, struct stat* sbuf,
              char* linkbuf, int linklen,
              fuse_cache_dirh_t h, fuse_cache_dirfil_t filler);

#endif  /* __CURLFTPFS_FTPFS_LS_H__ */
