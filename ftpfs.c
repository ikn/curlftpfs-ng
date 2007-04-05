/*
    FTP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <glib.h>

#include "charset_utils.h"
#include "path_utils.h"
#include "ftpfs-ls.h"
#include "cache.h"
#include "ftpfs.h"

#define CURLFTPFS_BAD_NOBODY 0x070f02
#define CURLFTPFS_BAD_SSL 0x070f03

#define CURLFTPFS_BAD_READ ((size_t)-1)

#define MAX_BUFFER_LEN (300*1024)

struct ftpfs ftpfs;
static char error_buf[CURL_ERROR_SIZE];

struct buffer {
  uint8_t* p;
  size_t len;
  size_t size;
  off_t begin_offset;
};

static void usage(const char* progname);

static inline void buf_init(struct buffer* buf, size_t size)
{
    if (size) {
        buf->p = (uint8_t*) malloc(size);
        if (!buf->p) {
            fprintf(stderr, "ftpfs: memory allocation failed\n");
            exit(1);
        }
    } else
        buf->p = NULL;
    buf->begin_offset = 0;
    buf->len = 0;
    buf->size = size;
}

static inline void buf_free(struct buffer* buf)
{
    free(buf->p);
}

static inline void buf_finish(struct buffer *buf)
{
    buf->len = buf->size;
}


static inline void buf_clear(struct buffer *buf)
{
    buf_free(buf);
    buf_init(buf, 0);
}

static void buf_resize(struct buffer *buf, size_t len)
{
    buf->size = (buf->len + len + 63) & ~31;
    buf->p = (uint8_t *) realloc(buf->p, buf->size);
    if (!buf->p) {
        fprintf(stderr, "ftpfs: memory allocation failed\n");
        exit(1);
    }
}

static inline void buf_check_add(struct buffer *buf, size_t len)
{
    if (buf->len + len > buf->size)
        buf_resize(buf, len);
}

#define _buf_add_mem(b, d, l)    \
    buf_check_add(b, l);       \
    memcpy(b->p + b->len, d, l); \
    b->len += l;


static inline void buf_add_mem(struct buffer *buf, const void *data,
                               size_t len)
{
    _buf_add_mem(buf, data, len);
}

static inline void buf_add_buf(struct buffer *buf, const struct buffer *bufa)
{
    _buf_add_mem(buf, bufa->p, bufa->len);
}

static inline void buf_add_uint8(struct buffer *buf, uint8_t val)
{
    _buf_add_mem(buf, &val, 1);
}

static inline void buf_add_uint32(struct buffer *buf, uint32_t val)
{
    uint32_t nval = htonl(val);
    _buf_add_mem(buf, &nval, 4);
}

static inline void buf_add_uint64(struct buffer *buf, uint64_t val)
{
    buf_add_uint32(buf, val >> 32);
    buf_add_uint32(buf, val & 0xffffffff);
}

static inline void buf_add_data(struct buffer *buf, const struct buffer *data)
{
    buf_add_uint32(buf, data->len);
    buf_add_mem(buf, data->p, data->len);
}

static inline void buf_add_string(struct buffer *buf, const char *str)
{
    struct buffer data;
    data.p = (uint8_t *) str;
    data.len = strlen(str);
    buf_add_data(buf, &data);
}

static int buf_check_get(struct buffer *buf, size_t len)
{
    if (buf->len + len > buf->size) {
        fprintf(stderr, "buffer too short\n");
        return -1;
    } else
        return 0;
}

static inline int buf_get_mem(struct buffer *buf, void *data, size_t len)
{
    if (buf_check_get(buf, len) == -1)
        return -1;
    memcpy(data, buf->p + buf->len, len);
    buf->len += len;
    return 0;
}

static inline int buf_get_uint8(struct buffer *buf, uint8_t *val)
{
    return buf_get_mem(buf, val, 1);
}

static inline int buf_get_uint32(struct buffer *buf, uint32_t *val)
{
    uint32_t nval;
    if (buf_get_mem(buf, &nval, 4) == -1)
        return -1;
    *val = ntohl(nval);
    return 0;
}

static inline int buf_get_uint64(struct buffer *buf, uint64_t *val)
{
    uint32_t val1;
    uint32_t val2;
    if (buf_get_uint32(buf, &val1) == -1 || buf_get_uint32(buf, &val2) == -1)
        return -1;
    *val = ((uint64_t) val1 << 32) + val2;
    return 0;
}

static inline int buf_get_data(struct buffer *buf, struct buffer *data)
{
    uint32_t len;
    if (buf_get_uint32(buf, &len) == -1 || len > buf->size - buf->len)
        return -1;
    buf_init(data, len + 1);
    data->size = len;
    if (buf_get_mem(buf, data->p, data->size) == -1) {
        buf_free(data);
        return -1;
    }
    return 0;
}

static inline int buf_get_string(struct buffer *buf, char **str)
{
    struct buffer data;
    if (buf_get_data(buf, &data) == -1)
        return -1;
    data.p[data.size] = '\0';
    *str = (char *) data.p;
    return 0;
}

struct ftpfs_file {
  struct buffer buf;
  int dirty;
  int copied;
  off_t last_offset;
  int can_shrink;
};

enum {
  KEY_HELP,
  KEY_VERBOSE,
  KEY_VERSION,
};

#define FTPFS_OPT(t, p, v) { t, offsetof(struct ftpfs, p), v }

static struct fuse_opt ftpfs_opts[] = {
  FTPFS_OPT("ftpfs_debug=%u",     debug, 0),
  FTPFS_OPT("transform_symlinks", transform_symlinks, 1),
  FTPFS_OPT("disable_epsv",       disable_epsv, 1),
  FTPFS_OPT("skip_pasv_ip",       skip_pasv_ip, 1),
  FTPFS_OPT("ftp_port=%s",        ftp_port, 0),
  FTPFS_OPT("disable_eprt",       disable_eprt, 1),
  FTPFS_OPT("tcp_nodelay",        tcp_nodelay, 1),
  FTPFS_OPT("connect_timeout=%u", connect_timeout, 0),
  FTPFS_OPT("ssl",                use_ssl, CURLFTPSSL_ALL),
  FTPFS_OPT("ssl_control",        use_ssl, CURLFTPSSL_CONTROL),
  FTPFS_OPT("ssl_try",            use_ssl, CURLFTPSSL_TRY),
  FTPFS_OPT("no_verify_hostname", no_verify_hostname, 1),
  FTPFS_OPT("no_verify_peer",     no_verify_peer, 1),
  FTPFS_OPT("cert=%s",            cert, 0),
  FTPFS_OPT("cert_type=%s",       cert_type, 0),
  FTPFS_OPT("key=%s",             key, 0),
  FTPFS_OPT("key_type=%s",        key_type, 0),
  FTPFS_OPT("pass=%s",            key_password, 0),
  FTPFS_OPT("engine=%s",          engine, 0),
  FTPFS_OPT("cacert=%s",          cacert, 0),
  FTPFS_OPT("capath=%s",          capath, 0),
  FTPFS_OPT("ciphers=%s",         ciphers, 0),
  FTPFS_OPT("interface=%s",       interface, 0),
  FTPFS_OPT("krb4=%s",            krb4, 0),
  FTPFS_OPT("proxy=%s",           proxy, 0),
  FTPFS_OPT("proxytunnel",        proxytunnel, 1),
  FTPFS_OPT("proxy_anyauth",      proxyanyauth, 1),
  FTPFS_OPT("proxy_basic",        proxybasic, 1),
  FTPFS_OPT("proxy_digest",       proxydigest, 1),
  FTPFS_OPT("proxy_ntlm",         proxyntlm, 1),
  FTPFS_OPT("httpproxy",          proxytype, CURLPROXY_HTTP),
  FTPFS_OPT("socks4",             proxytype, CURLPROXY_SOCKS4),
  FTPFS_OPT("socks5",             proxytype, CURLPROXY_SOCKS5),
  FTPFS_OPT("user=%s",            user, 0),
  FTPFS_OPT("proxy_user=%s",      proxy_user, 0),
  FTPFS_OPT("tlsv1",              ssl_version, CURL_SSLVERSION_TLSv1),
  FTPFS_OPT("sslv3",              ssl_version, CURL_SSLVERSION_SSLv3),
  FTPFS_OPT("ipv4",               ip_version, CURL_IPRESOLVE_V4),
  FTPFS_OPT("ipv6",               ip_version, CURL_IPRESOLVE_V6),
  FTPFS_OPT("utf8",               tryutf8, 1),
  FTPFS_OPT("codepage=%s",        codepage, 0),
  FTPFS_OPT("iocharset=%s",       iocharset, 0),

  FUSE_OPT_KEY("-h",             KEY_HELP),
  FUSE_OPT_KEY("--help",         KEY_HELP),
  FUSE_OPT_KEY("-v",             KEY_VERBOSE),
  FUSE_OPT_KEY("--verbose",      KEY_VERBOSE),
  FUSE_OPT_KEY("-V",             KEY_VERSION),
  FUSE_OPT_KEY("--version",      KEY_VERSION),
  FUSE_OPT_END
};

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct ftpfs_file* fh = (struct ftpfs_file*)data;
  if (fh == NULL) return 0;
  size_t to_copy = size * nmemb;
  if (to_copy > fh->buf.len - fh->copied) {
    to_copy = fh->buf.len - fh->copied;
  }
  DEBUG(2, "write_data: %zu\n", to_copy);
  DEBUG(3, "%*s\n", (int)to_copy, (char*)ptr);
  memcpy(ptr, fh->buf.p + fh->copied, to_copy);
  fh->copied += to_copy;
  return to_copy;
}

static size_t read_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct buffer* buf = (struct buffer*)data;
  if (buf == NULL) return size * nmemb;
  buf_add_mem(buf, ptr, size * nmemb);
  DEBUG(2, "read_data: %zu\n", size * nmemb);
  DEBUG(3, "%*s\n", (int)(size * nmemb), (char*)ptr);
  return size * nmemb;
}

#define curl_easy_setopt_or_die(handle, option, ...) \
  do {\
    CURLcode res = curl_easy_setopt(handle, option, __VA_ARGS__);\
    if (res != CURLE_OK) {\
      fprintf(stderr, "Error setting curl: %s\n", error_buf);\
      exit(1);\
    }\
  }while(0);

static int ftpfs_getdir(const char* path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler) {
  int err = 0;
  CURLcode curl_res;
  char* dir_path = get_fulldir_path(path);

  DEBUG(1, "ftpfs_getdir: %s\n", dir_path);
  struct buffer buf;
  buf_init(&buf, 0);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
    err = -EIO;
  } else {
    buf_add_mem(&buf, "\0", 1);
    parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
              NULL, NULL, NULL, 0, h, filler); 
  }

  free(dir_path);
  buf_free(&buf);
  return err;
}

static int ftpfs_getattr(const char* path, struct stat* sbuf) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf, 0);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_add_mem(&buf, "\0", 1);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
                  name, sbuf, NULL, 0, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return -ENOENT;
  return 0;
}

static int check_running() {
  int running_handles = 0;
  curl_multi_perform(ftpfs.multi, &running_handles);
  return running_handles;
}

static size_t ftpfs_read_chunk(const char* full_path, char* rbuf,
                               size_t size, off_t offset,
                               struct fuse_file_info* fi,
                               int update_offset) {
  int running_handles = 0;
  int err = 0;
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;

  DEBUG(2, "ftpfs_read_chunk: %s %p %zu %lld %p %p\n",
        full_path, rbuf, size, offset, fi, fh);

  pthread_mutex_lock(&ftpfs.lock);

  DEBUG(2, "buffer size: %zu %lld\n", fh->buf.len, fh->buf.begin_offset);

  if ((fh->buf.len < size + offset - fh->buf.begin_offset) ||
      offset < fh->buf.begin_offset ||
      offset > fh->buf.begin_offset + fh->buf.len) {
    // We can't answer this from cache
    if (ftpfs.current_fh != fh ||
        offset < fh->buf.begin_offset ||
        offset > fh->buf.begin_offset + fh->buf.len ||
        !check_running()) {
      DEBUG(1, "We need to restart the connection\n");
      DEBUG(2, "%p %p\n", ftpfs.current_fh, fh);
      DEBUG(2, "%lld %lld\n", fh->buf.begin_offset, offset);

      buf_clear(&fh->buf);
      fh->buf.begin_offset = offset;
      ftpfs.current_fh = fh;

      curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
      curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
      curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &fh->buf);
      if (offset) {
        char range[15];
        snprintf(range, 15, "%lld-", offset);
        curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_RANGE, range);
      }
      curl_multi_add_handle(ftpfs.multi, ftpfs.connection);
    }

    while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(ftpfs.multi, &running_handles));

    curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_RANGE, NULL);

    while ((fh->buf.len < size + offset - fh->buf.begin_offset) &&
        running_handles) {
      struct timeval timeout;
      int rc; /* select() return code */

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd;

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);

      /* set a suitable timeout to play around with */
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      /* get file descriptors from the transfers */
      curl_multi_fdset(ftpfs.multi, &fdread, &fdwrite, &fdexcep, &maxfd);

      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

      switch(rc) {
        case -1:
          /* select error */
          break;
        case 0:
          /* timeout, do something else */
          break;
        default:
          /* one or more of curl's file descriptors say there's data to read
             or write */
          while(CURLM_CALL_MULTI_PERFORM ==
              curl_multi_perform(ftpfs.multi, &running_handles));
          break;
      }
    }

    if (running_handles == 0) {
      int msgs_left = 1;
      while (msgs_left) {
        CURLMsg* msg = curl_multi_info_read(ftpfs.multi, &msgs_left);
        if (msg == NULL ||
            msg->msg != CURLMSG_DONE ||
            msg->data.result != CURLE_OK) {
          err = 1;
        }
      }
    }
  }

  size_t to_copy = fh->buf.len + fh->buf.begin_offset - offset;
  size = size > to_copy ? to_copy : size;
  if (rbuf) {
    memcpy(rbuf, fh->buf.p + offset - fh->buf.begin_offset, size);
  }

  if (update_offset) {
    fh->last_offset = offset + size;
  }

  // Check if the buffer is growing and we can delete a part of it
  if (fh->can_shrink && fh->buf.len > MAX_BUFFER_LEN) {
    DEBUG(2, "Shrinking buffer from %zu to %zu bytes\n",
          fh->buf.len, to_copy - size);
    memmove(fh->buf.p,
            fh->buf.p + offset - fh->buf.begin_offset + size,
            to_copy - size);
    fh->buf.len = to_copy - size;
    fh->buf.begin_offset = offset + size;
  }

  pthread_mutex_unlock(&ftpfs.lock);

  if (err) return CURLFTPFS_BAD_READ;
  return size;
}

static int ftpfs_open(const char* path, struct fuse_file_info* fi) {
  DEBUG(2, "%d\n", fi->flags & O_ACCMODE);
  int err = 0;
  char *full_path = get_full_path(path);

  struct ftpfs_file* fh =
    (struct ftpfs_file*) malloc(sizeof(struct ftpfs_file));
  buf_init(&fh->buf, 0);
  fh->dirty = 0;
  fh->copied = 0;
  fh->last_offset = 0;
  fh->can_shrink = 0;
  fi->fh = (unsigned long) fh;

  if ((fi->flags & O_ACCMODE) == O_RDONLY) {
    // If it's read-only, we can load the file a bit at a time, as necessary.
    DEBUG(1, "opening %s O_RDONLY\n", path);
    fh->can_shrink = 1;
    size_t size = ftpfs_read_chunk(full_path, NULL, 1, 0, fi, 0);

    if (size == CURLFTPFS_BAD_READ) {
      err = -EACCES;
      buf_free(&fh->buf);
      free(fh);
    }
  } else if ((fi->flags & O_ACCMODE) == O_WRONLY ||
             (fi->flags & O_ACCMODE) == O_RDWR) {
    // If we want to write to the file, we have to load it all at once,
    // modify it in memory and then upload it as a whole as most FTP servers
    // don't support resume for uploads.
    DEBUG(1, "opening %s O_WRONLY or O_RDWR\n", path);
    pthread_mutex_lock(&ftpfs.lock);
    curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
    curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
    curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &fh->buf);
    CURLcode curl_res = curl_easy_perform(ftpfs.connection);
    pthread_mutex_unlock(&ftpfs.lock);

    if (curl_res != 0) {
      err = -EACCES;
      buf_free(&fh->buf);
      free(fh);
    }
  }

  free(full_path);
  return err;
}

static int ftpfs_read(const char* path, char* rbuf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
  int ret;
  char *full_path = get_full_path(path);
  size_t size_read = ftpfs_read_chunk(full_path, rbuf, size, offset, fi, 1);
  free(full_path);
  if (size_read == CURLFTPFS_BAD_READ) {
    ret = -EIO;
  } else {
    ret = size_read;
  }
  return ret;
}

static int ftpfs_mknod(const char* path, mode_t mode, dev_t rdev) {
  (void) rdev;

  int err = 0;

  if ((mode & S_IFMT) != S_IFREG)
    return -EPERM;

  char *full_path = get_full_path(path);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_INFILESIZE, 0);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_READDATA, NULL);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }

  free(full_path);
  return err;
}

static int ftpfs_chmod(const char* path, mode_t mode) {
  int err = 0;

  // We can only process a subset of the mode - so strip
  // to supported subset
  int mode_c = mode - (mode / 0x1000 * 0x1000);
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHMOD %.3o %s", mode_c, filename);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  return err;
}

static int ftpfs_chown(const char* path, uid_t uid, gid_t gid) {
  int err = 0;
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHUID %i %s", uid, filename);
  char* cmd2 = g_strdup_printf("SITE CHGID %i %s", gid, filename);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);
  header = curl_slist_append(header, cmd2);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  free(cmd2); 
  return err;
}

static int ftpfs_truncate(const char* path, off_t offset) {
  DEBUG(1, "ftpfs_truncate: %lld\n", offset);
  if (offset == 0) return ftpfs_mknod(path, S_IFREG, 0);
  return 0;
}

static int ftpfs_utime(const char* path, struct utimbuf* time) {
  (void) path;
  (void) time;
  return 0;
}

static int ftpfs_rmdir(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("RMD %s", filename);
  struct buffer buf;
  buf_init(&buf, 0);

  DEBUG(2, "%s\n", full_path);
  DEBUG(2, "%s\n", cmd);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return err;
}

static int ftpfs_mkdir(const char* path, mode_t mode) {
  (void) mode;
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("MKD %s", filename);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return err;
}

static int ftpfs_unlink(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("DELE %s", filename);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return err;
}

static int ftpfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
  (void) path;
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;
  DEBUG(1, "ftpfs_write: %zu %lld\n", size, offset);
  if (offset + size > fh->buf.size) {
    buf_resize(&fh->buf, offset + size);
  }
  while (fh->buf.len < offset + size) {
    buf_add_mem(&fh->buf, "\0", 1);
  }
  memcpy(fh->buf.p + offset, wbuf, size);
  fh->dirty = 1;

  return size;
}

static int ftpfs_flush(const char *path, struct fuse_file_info *fi) {
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;
  if (!fh->dirty) return 0;

  int err = 0;
  DEBUG(1, "ftpfs_flush: %zu\n", fh->buf.len);
  char* full_path = get_full_path(path);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_INFILESIZE, fh->buf.len);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_READDATA, fh);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_UPLOAD, 0);

  fh->dirty = 0;
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }

  free(full_path);
  return err;
}

static int ftpfs_fsync(const char *path, int isdatasync,
                      struct fuse_file_info *fi) {
  (void) isdatasync;
  return ftpfs_flush(path, fi);
}

static int ftpfs_release(const char* path, struct fuse_file_info* fi) {
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;
  ftpfs_flush(path, fi);
  pthread_mutex_lock(&ftpfs.lock);
  if (ftpfs.current_fh == fh) {
    ftpfs.current_fh = NULL;
  }
  buf_free(&fh->buf);
  free(fh);
  pthread_mutex_unlock(&ftpfs.lock);
  return 0;
}


static int ftpfs_rename(const char* from, const char* to) {
  DEBUG(1, "ftpfs_rename from %s to %s\n", from, to);
  int err = 0;
  char* rnfr = g_strdup_printf("RNFR %s", from + 1);
  char* rnto = g_strdup_printf("RNTO %s", to + 1);
  struct buffer buf;
  buf_init(&buf, 0);
  struct curl_slist* header = NULL;

  if (ftpfs.codepage) {
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &rnfr);
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &rnto);
  }

  header = curl_slist_append(header, rnfr);
  header = curl_slist_append(header, rnto);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, ftpfs.safe_nobody);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_NOBODY, 0);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(rnfr);
  free(rnto);

  return err;
}

static int ftpfs_readlink(const char *path, char *linkbuf, size_t size) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf, 0);

  pthread_mutex_lock(&ftpfs.lock);
  curl_multi_remove_handle(ftpfs.multi, ftpfs.connection);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(ftpfs.connection);
  pthread_mutex_unlock(&ftpfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_add_mem(&buf, "\0", 1);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(ftpfs.host) - 1,
                  name, NULL, linkbuf, size, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return -ENOENT;
  return 0;
}

#if FUSE_VERSION >= 25
static int ftpfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = ftpfs.blksize;
    buf->f_frsize = 512;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return 0;
}
#else
static int ftpfs_statfs(const char *path, struct statfs *buf)
{
    (void) path;

    buf->f_namelen = 255;
    buf->f_bsize = ftpfs.blksize;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return 0;
}
#endif

static struct fuse_cache_operations ftpfs_oper = {
  .oper = {
//    .init       = ftpfs_init,
    .getattr    = ftpfs_getattr,
    .readlink   = ftpfs_readlink,
    .mknod      = ftpfs_mknod,
    .mkdir      = ftpfs_mkdir,
//    .symlink    = ftpfs_symlink,
    .unlink     = ftpfs_unlink,
    .rmdir      = ftpfs_rmdir,
    .rename     = ftpfs_rename,
    .chmod      = ftpfs_chmod,
    .chown      = ftpfs_chown,
    .truncate   = ftpfs_truncate,
    .utime      = ftpfs_utime,
    .open       = ftpfs_open,
    .flush      = ftpfs_flush,
    .fsync      = ftpfs_fsync,
    .release    = ftpfs_release,
    .read       = ftpfs_read,
    .write      = ftpfs_write,
    .statfs     = ftpfs_statfs,
#if FUSE_VERSION >= 25
//    .create     = ftpfs_create,
//    .ftruncate  = ftpfs_ftruncate,
//    .fgetattr   = ftpfs_fgetattr,
#endif
  },
  .cache_getdir = ftpfs_getdir,
};

static int ftpfs_opt_proc(void* data, const char* arg, int key,
                          struct fuse_args* outargs) {
  (void) data;
  (void) outargs;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case FUSE_OPT_KEY_NONOPT:
      if (!ftpfs.host) {
        const char* prefix = "";
        if (strncmp(arg, "ftp://", 6) && strncmp(arg, "ftps://", 7)) {
          prefix = "ftp://";
        }
        ftpfs.host = g_strdup_printf("%s%s%s", prefix, arg, 
			arg[strlen(arg)-1] == '/' ? "" : "/");
        return 0;
      } else if (!ftpfs.mountpoint)
        ftpfs.mountpoint = strdup(arg);
      return 1;
    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      fuse_main(outargs->argc, outargs->argv, &ftpfs_oper.oper);
      exit(1);
    case KEY_VERBOSE:
      ftpfs.verbose = 1;
      return 0;
    case KEY_VERSION:
      fprintf(stderr, "curlftpfs %s libcurl/%s fuse/%u.%u\n",
              VERSION,
              ftpfs.curl_version->version,
              FUSE_MAJOR_VERSION,
              FUSE_MINOR_VERSION);
      exit(1);
    default:
      exit(1);
  }
}

static void usage(const char* progname) {
  fprintf(stderr,
"usage: %s <ftphost> <mountpoint>\n"
"\n"
"CurlFtpFS options:\n"
"    -o opt,[opt...]        ftp options\n"
"    -v   --verbose         make libcurl print verbose debug\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"FTP options:\n"
"    ftpfs_debug         print some debugging information\n"
"    transform_symlinks  prepend mountpoint to absolute symlink targets\n"
"    disable_epsv        use PASV, without trying EPSV first\n"
"    skip_pasv_ip        skip the IP address for PASV\n"
"    ftp_port=STR        use PORT with address instead of PASV\n"
"    disable_eprt        use PORT, without trying EPRT first\n"
"    tcp_nodelay         use the TCP_NODELAY option\n"
"    connect_timeout=N   maximum time allowed for connection in seconds\n"
"    ssl                 enable SSL/TLS for both control and data connections\n"
"    ssl_control         enable SSL/TLS only for control connection\n"
"    ssl_try             try SSL/TLS first but connect anyway\n"
"    no_verify_hostname  does not verify the hostname (SSL)\n"
"    no_verify_peer      does not verify the peer (SSL)\n"
"    cert=STR            client certificate file (SSL)\n"
"    cert_type=STR       certificate file type (DER/PEM/ENG) (SSL)\n"
"    key=STR             private key file name (SSL)\n"
"    key_type=STR        private key file type (DER/PEM/ENG) (SSL)\n"
"    pass=STR            pass phrase for the private key (SSL)\n"
"    engine=STR          crypto engine to use (SSL)\n"
"    cacert=STR          file with CA certificates to verify the peer (SSL)\n"
"    capath=STR          CA directory to verify peer against (SSL)\n"
"    ciphers=STR         SSL ciphers to use (SSL)\n"
"    interface=STR       specify network interface/address to use\n"
"    krb4=STR            enable krb4 with specified security level\n"
"    proxy=STR           use host:port HTTP proxy\n"
"    proxytunnel         operate through a HTTP proxy tunnel (using CONNECT)\n"
"    proxy_anyauth       pick \"any\" proxy authentication method\n"
"    proxy_basic         use Basic authentication on the proxy\n"
"    proxy_digest        use Digest authentication on the proxy\n"
"    proxy_ntlm          use NTLM authentication on the proxy\n"
"    httpproxy           use a HTTP proxy (default)\n"
"    socks4              use a SOCKS4 proxy\n"
"    socks5              use a SOCKS5 proxy\n"
"    user=STR            set server user and password\n"
"    proxy_user=STR      set proxy user and password\n"
"    tlsv1               use TLSv1 (SSL)\n"
"    sslv3               use SSLv3 (SSL)\n"
"    ipv4                resolve name to IPv4 address\n"
"    ipv6                resolve name to IPv6 address\n"
"    utf8                try to transfer file list with utf-8 encoding\n"
"    codepage=STR        set the codepage the server uses\n"
"    iocharset=STR       set the charset used by the client\n"
"\n", progname);
}

static void set_common_curl_stuff(CURL* easy) {
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt_or_die(easy, CURLOPT_READFUNCTION, write_data);
  curl_easy_setopt_or_die(easy, CURLOPT_ERRORBUFFER, error_buf);
  curl_easy_setopt_or_die(easy, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt_or_die(easy, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt_or_die(easy, CURLOPT_CUSTOMREQUEST, "LIST -a");

  if (ftpfs.tryutf8) {
    // We'll let the slist leak, as it will still be accessible within
    // libcurl. If we ever want to add more commands to CURLOPT_QUOTE, we'll
    // have to think of a better strategy.
    struct curl_slist *slist = NULL;

    // Adding the QUOTE here will make this command be sent with every request.
    // This is necessary to ensure that the server is still in UTF8 mode after
    // we get disconnected and automatically reconnect.
    slist = curl_slist_append(slist, "OPTS UTF8 ON");
    curl_easy_setopt_or_die(easy, CURLOPT_QUOTE, slist);
  }

  if (ftpfs.verbose) {
    curl_easy_setopt_or_die(easy, CURLOPT_VERBOSE, TRUE);
  }

  if (ftpfs.disable_epsv) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_USE_EPSV, FALSE);
  }

  if (ftpfs.skip_pasv_ip) {
#ifdef CURLOPT_FTP_SKIP_PASV_IP
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_SKIP_PASV_IP, TRUE);
#endif
  }

  if (ftpfs.ftp_port) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTPPORT, ftpfs.ftp_port);
  }

  if (ftpfs.disable_eprt) {
    curl_easy_setopt_or_die(easy, CURLOPT_FTP_USE_EPRT, FALSE);
  }

  if (ftpfs.tcp_nodelay) {
#ifdef CURLOPT_TCP_NODELAY
    /* CURLOPT_TCP_NODELAY is not defined in older versions */
    curl_easy_setopt_or_die(easy, CURLOPT_TCP_NODELAY, 1);
#endif
  }

  curl_easy_setopt_or_die(easy, CURLOPT_CONNECTTIMEOUT, ftpfs.connect_timeout);

  /* CURLFTPSSL_CONTROL and CURLFTPSSL_ALL should make the connection fail if
   * the server doesn't support SSL but libcurl only honors this beginning
   * with version 7.15.4 */
  if (ftpfs.use_ssl > CURLFTPSSL_TRY &&
      ftpfs.curl_version->version_num <= CURLFTPFS_BAD_SSL) {
    fprintf(stderr,
"WARNING: you are using libcurl %s.\n"
"This version of libcurl does not respect the mandatory SSL flag.\n" 
"It will try to send the user and password even if the server doesn't support\n"
"SSL. Please upgrade to libcurl version 7.15.4 or higher.\n"
"You can abort the connection now by pressing ctrl+c.\n",
            ftpfs.curl_version->version);
    int i;
    const int time_to_wait = 10;
    for (i = 0; i < time_to_wait; i++) {
      fprintf(stderr, "%d.. ", time_to_wait - i);
      sleep(1);
    }
    fprintf(stderr, "\n");
  }
  curl_easy_setopt_or_die(easy, CURLOPT_FTP_SSL, ftpfs.use_ssl);

  curl_easy_setopt_or_die(easy, CURLOPT_SSLCERT, ftpfs.cert);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLCERTTYPE, ftpfs.cert_type);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEY, ftpfs.key);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEYTYPE, ftpfs.key_type);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLKEYPASSWD, ftpfs.key_password);

  if (ftpfs.engine) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSLENGINE, ftpfs.engine);
    curl_easy_setopt_or_die(easy, CURLOPT_SSLENGINE_DEFAULT, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYPEER, TRUE);
  if (ftpfs.no_verify_peer) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYPEER, FALSE);
  }

  if (ftpfs.cacert || ftpfs.capath) {
    if (ftpfs.cacert) {
      curl_easy_setopt_or_die(easy, CURLOPT_CAINFO, ftpfs.cacert);
    }
    if (ftpfs.capath) {
      curl_easy_setopt_or_die(easy, CURLOPT_CAPATH, ftpfs.capath);
    }
  }

  if (ftpfs.ciphers) {
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_CIPHER_LIST, ftpfs.ciphers);
  }

  if (ftpfs.no_verify_hostname) {
    /* The default is 2 which verifies even the host string. This sets to 1
     * which means verify the host but not the string. */
    curl_easy_setopt_or_die(easy, CURLOPT_SSL_VERIFYHOST, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_INTERFACE, ftpfs.interface);
  curl_easy_setopt_or_die(easy, CURLOPT_KRB4LEVEL, ftpfs.krb4);
  
  if (ftpfs.proxy) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXY, ftpfs.proxy);
  }

  /* The default proxy type is HTTP */
  if (!ftpfs.proxytype) {
    ftpfs.proxytype = CURLPROXY_HTTP;
  }
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYTYPE, ftpfs.proxytype);
  
  /* Connection to FTP servers only make sense with a HTTP tunnel proxy */
  if (ftpfs.proxytype == CURLPROXY_HTTP || ftpfs.proxytunnel) {
    curl_easy_setopt_or_die(easy, CURLOPT_HTTPPROXYTUNNEL, TRUE);
  }

  if (ftpfs.proxyanyauth) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  } else if (ftpfs.proxyntlm) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  } else if (ftpfs.proxydigest) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  } else if (ftpfs.proxybasic) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_USERPWD, ftpfs.user);
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYUSERPWD, ftpfs.proxy_user);
  curl_easy_setopt_or_die(easy, CURLOPT_SSLVERSION, ftpfs.ssl_version);
  curl_easy_setopt_or_die(easy, CURLOPT_IPRESOLVE, ftpfs.ip_version);
}

static void checkpasswd(const char *kind, /* for what purpose */
                        char **userpwd) /* pointer to allocated string */
{
  char *ptr;
  if(!*userpwd)
    return;

  ptr = strchr(*userpwd, ':');
  if(!ptr) {
    /* no password present, prompt for one */
    char *passwd;
    char prompt[256];
    size_t passwdlen;
    size_t userlen = strlen(*userpwd);
    char *passptr;

    /* build a nice-looking prompt */
    snprintf(prompt, sizeof(prompt),
        "Enter %s password for user '%s':",
        kind, *userpwd);

    /* get password */
    passwd = getpass(prompt);
    passwdlen = strlen(passwd);

    /* extend the allocated memory area to fit the password too */
    passptr = realloc(*userpwd,
        passwdlen + 1 + /* an extra for the colon */
        userlen + 1);   /* an extra for the zero */

    if(passptr) {
      /* append the password separated with a colon */
      passptr[userlen]=':';
      memcpy(&passptr[userlen+1], passwd, passwdlen+1);
      *userpwd = passptr;
    }
  }
}

int main(int argc, char** argv) {
  int res;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  CURLcode curl_res;
  CURL* easy;

  // Initialize curl library before we are a multithreaded program
  curl_global_init(CURL_GLOBAL_ALL);
  
  memset(&ftpfs, 0, sizeof(ftpfs));

  ftpfs.curl_version = curl_version_info(CURLVERSION_NOW);
  ftpfs.safe_nobody = ftpfs.curl_version->version_num > CURLFTPFS_BAD_NOBODY;
  
  ftpfs.blksize = 4096;
  
  if (fuse_opt_parse(&args, &ftpfs, ftpfs_opts, ftpfs_opt_proc) == -1)
    exit(1);

  if (!ftpfs.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  if (!ftpfs.iocharset) {
    ftpfs.iocharset = "UTF8";
  }

  if (ftpfs.codepage) {
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &ftpfs.host);
  }

  easy = curl_easy_init();
  if (easy == NULL) {
    fprintf(stderr, "Error initializing libcurl\n");
    exit(1);
  }

  res = cache_parse_options(&args);
  if (res == -1)
    exit(1);

  checkpasswd("host", &ftpfs.user);
  checkpasswd("proxy", &ftpfs.proxy_user);

  if (ftpfs.transform_symlinks && !ftpfs.mountpoint) {
    fprintf(stderr, "cannot transform symlinks: no mountpoint given\n");
    exit(1);
  }
  if (!ftpfs.transform_symlinks)
    ftpfs.symlink_prefix_len = 0;
  else if (realpath(ftpfs.mountpoint, ftpfs.symlink_prefix) != NULL)
    ftpfs.symlink_prefix_len = strlen(ftpfs.symlink_prefix);
  else {
    perror("unable to normalize mount path");
    exit(1);
  }

  set_common_curl_stuff(easy);
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEDATA, NULL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOBODY, ftpfs.safe_nobody);
  curl_res = curl_easy_perform(easy);
  if (curl_res != 0) {
    fprintf(stderr, "Error connecting to ftp: %s\n", error_buf);
    exit(1);
  }
  curl_easy_setopt_or_die(easy, CURLOPT_NOBODY, 0);

  ftpfs.multi = curl_multi_init();
  if (ftpfs.multi == NULL) {
    fprintf(stderr, "Error initializing libcurl multi\n");
    exit(1);
  }

  ftpfs.connection = easy;
  pthread_mutex_init(&ftpfs.lock, NULL);

  res = fuse_main(args.argc, args.argv, cache_init(&ftpfs_oper));

  curl_multi_remove_handle(ftpfs.multi, easy);
  curl_easy_cleanup(easy);
  curl_multi_cleanup(ftpfs.multi);
  curl_global_cleanup();

  return res;
}
