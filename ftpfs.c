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
#include <netinet/in.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <glib.h>

#include "cache.h"

static char* MonthStrings[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

struct ftpfs {
  char* host;
  char* mountpoint;
  CURL* connection;
  GHashTable *filetab;  
  int verbose;
  int debug;
  int transform_symlinks;
  int no_epsv;
  char symlink_prefix[PATH_MAX+1];
  size_t symlink_prefix_len;
};

static struct ftpfs ftpfs;
static char error_buf[CURL_ERROR_SIZE];

struct buffer {
  uint8_t* p;
  size_t len;
  size_t size;
};

static void usage(const char* progname);
static char* get_dir_path(const char* path, int strip);
static int parse_dir(struct buffer* buf, const char* dir,
                     const char* name, struct stat* sbuf,
                     char* linkbuf, int linklen,
                     fuse_cache_dirh_t h, fuse_cache_dirfil_t filler);

#define DEBUG(args...) \
        do { if (ftpfs.debug) fprintf(stderr, args); } while(0)

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
};

enum {
  KEY_HELP,
  KEY_VERBOSE,
  KEY_VERSION,
};

#define FTPFS_OPT(t, p, v) { t, offsetof(struct ftpfs, p), v }

static struct fuse_opt ftpfs_opts[] = {
  FTPFS_OPT("ftpfs_debug",        debug, 1),
  FTPFS_OPT("transform_symlinks", transform_symlinks, 1),
  FTPFS_OPT("no_epsv",            no_epsv, 1),

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
  unsigned to_copy = size * nmemb;
  if (to_copy > fh->buf.len - fh->copied) {
    to_copy = fh->buf.len - fh->copied;
  }
  DEBUG("write_data: %d\n", to_copy);
  memcpy(ptr, fh->buf.p + fh->copied, to_copy);
  fh->copied += to_copy;
  return to_copy;
}

static size_t read_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct buffer* buf = (struct buffer*)data;
  if (buf == NULL) return 0;
  buf_add_mem(buf, ptr, size * nmemb);
  DEBUG("read_data: %d\n", size * nmemb);
  return size*nmemb;
}

static int ftpfs_getdir(const char* path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path, 0);

  DEBUG("ftpfs_getdir: %s\n", dir_path);
  struct buffer buf;
  buf_init(&buf, 0);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);

  curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    DEBUG("%s\n", error_buf);
  }
  buf_add_mem(&buf, "\0", 1);

  err = parse_dir(&buf, dir_path + strlen(ftpfs.host) - 1, NULL, NULL, NULL, 0, h, filler); 

  free(dir_path);
  buf_free(&buf);
  return 0;
}

static char* get_dir_path(const char* path, int strip) {
  char *ret;
  const char *lastdir;

  ++path;
  
  if (strip) {
    lastdir = strrchr(path, '/');
    if (lastdir == NULL) lastdir = path;
  } else {
    lastdir = path + strlen(path);
  }

  ret = g_strdup_printf("%s%.*s%s", ftpfs.host, lastdir - path, path,
		                    lastdir - path ? "/" : "");

  return ret;
}

static int parse_dir(struct buffer* buf, const char* dir,
                     const char* name, struct stat* sbuf,
                     char* linkbuf, int linklen,
                     fuse_cache_dirh_t h, fuse_cache_dirfil_t filler) {
  char *start = buf->p;
  char *end = buf->p;
  char found = 0;

  if (sbuf) memset(sbuf, 0, sizeof(struct stat));

  if (name && sbuf && name[0] == '\0') {
    sbuf->st_mode |= S_IFDIR;
    sbuf->st_mode |= 0755;
    sbuf->st_size = 1024;
    return 0;
  }

  while ((end = strchr(start, '\n')) != NULL)
  {
    char* line;
    char* file;
    struct stat stat_buf;
    memset(&stat_buf, 0, sizeof(stat_buf));

    if (end > start && *(end-1) == '\r') end--;
    
    line = (char*)malloc(end - start + 1);
    strncpy(line, start, end - start);
    line[end - start] = '\0';
    start = *end == '\r' ? end + 2 : end + 1;

    if (!strncmp(line, "total", 5)) continue;

    int i = 0;
    char *p;
    if (line[i] == 'd') {
      stat_buf.st_mode |= S_IFDIR;
    } else if (line[i] == 'l') {
      stat_buf.st_mode |= S_IFLNK;
    } else {
      stat_buf.st_mode |= S_IFREG;
    }
    for (i = 1; i < 10; ++i) {
      if (line[i] != '-') {
        stat_buf.st_mode |= 1 << (9 - i);
	}
    }

    // Advance whitespace
    while (line[i] && isspace(line[i])) ++i;

    stat_buf.st_nlink = strtol(line+i, &p, 10);
    i = p - line;

    // Advance whitespace
    while (line[i] && isspace(line[i])) ++i;
    // Advance username
    while (line[i] && !isspace(line[i])) ++i;
    // Advance whitespace
    while (line[i] && isspace(line[i])) ++i;
    // Advance group
    while (line[i] && !isspace(line[i])) ++i;

    stat_buf.st_size = strtol(line+i, &p, 10);
    i = p - line;
    ++i;

    // Date
    int month;
    for (month = 0; month < 12; ++month) {
      if (!strncmp(MonthStrings[month], line+i, 3)) break;
    }
    if (month < 12) {
      i += 3;
      int day = strtol(line+i, &p, 10);
      if (p != line+i) {
        i = p - line;
	int year_or_hour = strtol(line+i, &p, 10);
	struct tm current_time;
	time_t now = time(NULL);
	localtime_r(&now, &current_time);
	if (p != line+i) {
	  i = p - line;
	  struct tm parsed_time;
	  memset(&parsed_time, 0, sizeof(parsed_time));
	  if (*p == ':') {
	    // Hour
	    ++i;
	    int minute = strtol(line+i, &p, 10);
	    i = p - line;
	    parsed_time.tm_mday = day;
	    parsed_time.tm_mon = month;
	    parsed_time.tm_year = current_time.tm_year;
	    parsed_time.tm_hour = year_or_hour;
	    parsed_time.tm_min = minute;
	    stat_buf.st_atime = mktime(&parsed_time);
	    if (stat_buf.st_atime > now) {
	      parsed_time.tm_year--;
	      stat_buf.st_atime = mktime(&parsed_time);
	    }
	    stat_buf.st_mtime = stat_buf.st_atime;
	    stat_buf.st_ctime = stat_buf.st_atime;
	  } else {
	    // Year
	    parsed_time.tm_mday = day;
	    parsed_time.tm_mon = month;
	    parsed_time.tm_year = year_or_hour - 1900;
	    stat_buf.st_atime = mktime(&parsed_time);
	    stat_buf.st_mtime = stat_buf.st_atime;
	    stat_buf.st_ctime = stat_buf.st_atime;
	  }
	}
      }
    }

    // Symbolic links
    const char* link = strstr(line, " -> "); 

    file = line + i + 1;
    if (link) {
      file = g_strndup(file, link - file);
    } else {
      file = g_strdup(file);
    }
    DEBUG("%s\n", file);

    char *full_path = g_strdup_printf("%s%s", dir, file);
    
    if (link) {
      link += 4;
      char *reallink;
      if (link[0] == '/' && ftpfs.symlink_prefix_len) {
        reallink = g_strdup_printf("%s%s", ftpfs.symlink_prefix, link);
      } else {
        reallink = g_strdup(link);
      }
      int linksize = strlen(reallink);
      cache_add_link(full_path, reallink, linksize+1);
      DEBUG("cache_add_link: %s %s\n", full_path, reallink);
      if (linkbuf && linklen) {
        if (linksize > linklen) linksize = linklen - 1;
        strncpy(linkbuf, reallink, linksize);
        linkbuf[linksize] = '\0';
      }
      free(reallink);
    }


    if (h && filler) {
      DEBUG("filler: %s\n", file);
      filler(h, file, &stat_buf);
    } else {
      DEBUG("cache_add_attr: %s\n", full_path);
      cache_add_attr(full_path, &stat_buf);
    }

    if (name && !strcmp(name, file)) {
      if (sbuf) *sbuf = stat_buf;
      found = 1;
    }
    
    free(full_path);
    free(line);
    free(file);
  }

  if (found) return 0;
  return -ENOENT;
}

static int ftpfs_getattr(const char* path, struct stat* sbuf) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path, 1);

  DEBUG("dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf, 0);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);

  curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    DEBUG("%s\n", error_buf);
  }
  buf_add_mem(&buf, "\0", 1);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir(&buf, dir_path + strlen(ftpfs.host) - 1, name, sbuf, NULL, 0, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  return err;
}

static int ftpfs_open(const char* path, struct fuse_file_info* fi) {
  DEBUG("%d\n", fi->flags & O_ACCMODE);
  if ((fi->flags & O_ACCMODE) == O_RDONLY) {
    DEBUG("opening %s O_RDONLY\n", path);
  } else if ((fi->flags & O_ACCMODE) == O_WRONLY) {
    DEBUG("opening %s O_WRONLY\n", path);
  } else if ((fi->flags & O_ACCMODE) == O_RDWR) {
    DEBUG("opening %s O_RDWR\n", path);
  }

  char *full_path = g_strdup_printf("%s%s", ftpfs.host, path + 1);
  
  DEBUG("full_path: %s\n", full_path);
  struct buffer buf;
  buf_init(&buf, 0);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);

  int err = 0;
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EACCES;
    buf_free(&buf);
  } else {
    struct ftpfs_file* fh = (struct ftpfs_file*)
                             malloc(sizeof(struct ftpfs_file));
    fh->buf = buf;
    fh->dirty = 0;
    fh->copied = 0;
    fi->fh = (unsigned long) fh;
  }

  free(full_path);
  return err;
}

static int ftpfs_read(const char* path, char* rbuf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
  (void) path;
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;
  if (offset >= fh->buf.len) return 0;
  if (size > fh->buf.len - offset) {
    size = fh->buf.len - offset;
  }
  memcpy(rbuf, fh->buf.p + offset, size);

  return size;
}

static int ftpfs_mknod(const char* path, mode_t mode, dev_t rdev) {
  (void) rdev;

  int err = 0;

  if ((mode & S_IFMT) != S_IFREG)
    return -EPERM;

  char *full_path = g_strdup_printf("%s%s", ftpfs.host, path + 1);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_INFILESIZE, 0);
  curl_easy_setopt(ftpfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt(ftpfs.connection, CURLOPT_READFUNCTION, write_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_READDATA, NULL);

  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }

  curl_easy_setopt(ftpfs.connection, CURLOPT_UPLOAD, 0);

  free(full_path);
  return err;
}

static int ftpfs_chmod(const char* path, mode_t mode) {
  (void) path;
  (void) mode;
  return 0;
}

static int ftpfs_chown(const char* path, uid_t uid, gid_t gid) {
  (void) path;
  (void) uid;
  (void) gid;
  return 0;
}

static int ftpfs_truncate(const char* path, off_t offset) {
  DEBUG("ftpfs_truncate: %lld\n", offset);
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
  char *cmd = g_strdup_printf("RMD %s", path);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, header);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }
  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, NULL);
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(cmd);
  return err;
}

static int ftpfs_mkdir(const char* path, mode_t mode) {
  (void) mode;
  int err = 0;
  struct curl_slist* header = NULL;
  char *cmd = g_strdup_printf("MKD %s", path);
  char *full_path = g_strdup_printf("%s%s/", ftpfs.host, path + 1);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, header);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }
  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, NULL);
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(cmd);
  free(full_path);
  return err;
}

static int ftpfs_unlink(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char *cmd = g_strdup_printf("DELE %s", path);
  struct buffer buf;
  buf_init(&buf, 0);

  header = curl_slist_append(header, cmd);

  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, header);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }
  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, NULL);
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(cmd);
  return err;
}

static int ftpfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
  (void) path;
  struct ftpfs_file* fh = (struct ftpfs_file*) (uintptr_t) fi->fh;
  DEBUG("ftpfs_write: %d %lld\n", size, offset);
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
  DEBUG("ftpfs_flush: %d\n", fh->buf.len);
  char* full_path = g_strdup_printf("%s%s", ftpfs.host, path + 1);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_INFILESIZE, fh->buf.len);
  curl_easy_setopt(ftpfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt(ftpfs.connection, CURLOPT_READFUNCTION, write_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_READDATA, fh);

  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }

  fh->dirty = 0;
  curl_easy_setopt(ftpfs.connection, CURLOPT_UPLOAD, 0);

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
  buf_free(&fh->buf);
  free(fh);
  return 0;
}


static int ftpfs_rename(const char* from, const char* to) {
  int err = 0;
  char *rnfr = g_strdup_printf("RNFR %s", from);
  char *rnto = g_strdup_printf("RNTO %s", to);
  struct buffer buf;
  buf_init(&buf, 0);
  struct curl_slist* header = NULL;
  header = curl_slist_append(header, rnfr);
  header = curl_slist_append(header, rnto);

  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, header);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    err = -EPERM;
  }
  curl_easy_setopt(ftpfs.connection, CURLOPT_QUOTE, NULL);
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(rnfr);
  free(rnto);

  return err;
}

static int ftpfs_readlink(const char *path, char *linkbuf, size_t size) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path, 1);

  DEBUG("dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf, 0);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(ftpfs.connection, CURLOPT_WRITEFUNCTION, read_data);

  curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    DEBUG("%s\n", error_buf);
  }
  buf_add_mem(&buf, "\0", 1);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir(&buf, dir_path + strlen(ftpfs.host) - 1, name, NULL, linkbuf, size, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  return err;
}

#if FUSE_VERSION >= 25
static int ftpfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = 512;
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
    buf->f_bsize = 512;
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
#ifdef SSHFS_USE_INIT
//    .init       = ftpfs_init,
#endif
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
        ftpfs.host = g_strdup_printf("%s%s", arg, 
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
      fprintf(stderr, "Version 0.2\n");
      exit(1);
    default:
      exit(1);
  }
}

static void usage(const char* progname) {
  fprintf(stderr,
"usage: %s <ftphost> <mountpoint>\n"
"\n"
"    -o opt,[opt...]        mount options\n"
"    -v   --verbose         make libcurl print verbose debug\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"FTPFS options:\n"
"    -o ftpfs_debug         print some debugging information\n"
"    -o transform_symlinks  prepend mountpoint to absolute symlink targets\n"
"    -o no_epsv             make libcurl use PASV, without trying EPSV first\n"
"\n", progname);
}

int main(int argc, char** argv) {
  int res;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  CURLcode curl_res;

  memset(&ftpfs, 0, sizeof(ftpfs));
  if (fuse_opt_parse(&args, &ftpfs, ftpfs_opts, ftpfs_opt_proc) == -1)
    exit(1);

  if (!ftpfs.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  ftpfs.connection = curl_easy_init();
  if (ftpfs.connection == NULL) {
    fprintf(stderr, "Error initializing libcurl\n");
    exit(1);
  }

  res = cache_parse_options(&args);
  if (res == -1)
    exit(1);

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

  if (ftpfs.no_epsv) {
    DEBUG("Not trying EPSV mode\n");
    curl_easy_setopt(ftpfs.connection, CURLOPT_FTP_USE_EPSV, 0);
  }

  curl_easy_setopt(ftpfs.connection, CURLOPT_ERRORBUFFER, error_buf);
  curl_easy_setopt(ftpfs.connection, CURLOPT_URL, ftpfs.host);
  curl_easy_setopt(ftpfs.connection, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  if (ftpfs.verbose) curl_easy_setopt(ftpfs.connection, CURLOPT_VERBOSE, 1);
  curl_res = curl_easy_perform(ftpfs.connection);
  if (curl_res != 0) {
    fprintf(stderr, "Error connecting to ftp: %s\n", error_buf);
    exit(1);
  }

  res = fuse_main(args.argc, args.argv, cache_init(&ftpfs_oper));

  curl_easy_cleanup(ftpfs.connection);
  
  return res;
}
