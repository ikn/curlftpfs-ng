#ifndef __CURLFTPFS_FTPFS_H__
#define __CURLFTPFS_FTPFS_H__

#include <curl/curl.h>
#include <curl/easy.h>
#include <glib.h>

struct ftpfs {
  char* host;
  char* mountpoint;
  CURL* connection;
  unsigned blksize;
  GHashTable *filetab;  
  int verbose;
  int debug;
  int transform_symlinks;
  int disable_epsv;
  int tcp_nodelay;
  int disable_eprt;
  int connect_timeout;
  int use_ssl;
  int no_verify_hostname;
  char* cert;
  char* cert_type;
  char* key;
  char* key_type;
  char* key_password;
  char* engine;
  char* cacert;
  char* capath;
  char* ciphers;
  char* interface;
  char* krb4;
  char* proxy;
  int proxytunnel;
  int proxyanyauth;
  int proxybasic;
  int proxydigest;
  int proxyntlm;
  char* user;
  char* proxy_user;
  int ssl_version;
  int ip_version;
  char symlink_prefix[PATH_MAX+1];
  size_t symlink_prefix_len;
  curl_version_info_data* curl_version;
  int safe_nobody;
};

extern struct ftpfs ftpfs;

#define DEBUG(args...) \
        do { if (ftpfs.debug) fprintf(stderr, args); } while(0)

#endif   /* __CURLFTPFS_FTPFS_H__ */
