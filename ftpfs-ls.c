#define _XOPEN_SOURCE
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "ftpfs.h"
#include "ftpfs-ls.h"

static int parse_dir_unix(const char *line,
                          struct stat *sbuf,
                          char *file,
                          char *link) {
  char mode[12];
  long nlink = 1;
  char user[33];
  char group[33];
  long size;
  char month[4];
  char day[3];
  char year[6];
  char date[20];
  struct tm tm;
  time_t tt;
  int res;

  memset(file, 0, sizeof(char)*1024);
  memset(&tm, 0, sizeof(tm));
  memset(&tt, 0, sizeof(tt));

  res = sscanf(line, "%11s%*[ \t]%lu%*[ \t]%32s%*[ \t]%32s%*[ \t]%lu%*[ \t]%3s%*[ \t]%2s%*[ \t]%5s%*[ \t]%1023c",
               mode, &nlink, user, group, &size, month, day, year, file);
  if (res < 9) {
    res = sscanf(line, "%11s%*[ \t]%32s%*[ \t]%32s%*[ \t]%lu%*[ \t]%3s%*[ \t]%2s%*[ \t]%5s%*[ \t]%1023c",
                 mode, user, group, &size, month, day, year, file);
    if (res < 8) {
      return 0;
    }
  }

  char *link_marker = strstr(file, " -> ");
  if (link_marker) {
    strcpy(link, link_marker + 4);
    *link_marker = '\0';
  }

  int i = 0;
  if (mode[i] == 'd') {
    sbuf->st_mode |= S_IFDIR;
  } else if (mode[i] == 'l') {
    sbuf->st_mode |= S_IFLNK;
  } else {
    sbuf->st_mode |= S_IFREG;
  }
  for (i = 1; i < 10; ++i) {
    if (mode[i] != '-') {
      sbuf->st_mode |= 1 << (9 - i);
    }
  }

  sbuf->st_nlink = nlink;

  sbuf->st_size = size;
  if (ftpfs.blksize) {
    sbuf->st_blksize = ftpfs.blksize;
    sbuf->st_blocks =
      ((size + ftpfs.blksize - 1) & ~(ftpfs.blksize - 1)) >> 9;
  }

  sprintf(date,"%s,%s,%s", year, month, day);
  tt = time(NULL);
  gmtime_r(&tt, &tm);
  tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
  if(strchr(year, ':'))
    strptime(date, "%H:%M,%b,%d", &tm);
  else
    strptime(date, "%Y,%b,%d", &tm);

  sbuf->st_atime = sbuf->st_ctime = sbuf->st_mtime = mktime(&tm);

  return 1;
}

static int parse_dir_win(const char *line,
                         struct stat *sbuf,
                         char *file,
                         char *link) {
  char date[9];
  char hour[8];
  char size[33];
  struct tm tm;
  time_t tt;
  int res;
  (void)link;

  memset(file, 0, sizeof(char)*1024);
  memset(&tm, 0, sizeof(tm));
  memset(&tt, 0, sizeof(tt));

  res = sscanf(line, "%8s%*[ \t]%7s%*[ \t]%32s%*[ \t]%1023c",
               date, hour, size, file);
  if (res < 4) {
    return 0;
  }

  DEBUG("date: %s hour: %s size: %s file: %s\n", date, hour, size, file);

  tt = time(NULL);
  gmtime_r(&tt, &tm);
  tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
  strptime(date, "%m-%d-%y", &tm);
  strptime(hour, "%I:%M%p", &tm);

  sbuf->st_atime = sbuf->st_ctime = sbuf->st_mtime = mktime(&tm);

  sbuf->st_nlink = 1;

  if (!strcmp(size, "<DIR>")) {
    sbuf->st_mode |= S_IFDIR;
  } else {
    int nsize = strtol(size, NULL, 0);
    sbuf->st_mode |= S_IFREG;
    sbuf->st_size = nsize;
    if (ftpfs.blksize) {
      sbuf->st_blksize = ftpfs.blksize;
      sbuf->st_blocks =
        ((nsize + ftpfs.blksize - 1) & ~(ftpfs.blksize - 1)) >> 9;
    }
  }

  return 1;
}

static int parse_dir_netware(const char *line,
                             struct stat *sbuf,
                             char *file,
                             char *link) {
  (void) line;
  (void) sbuf;
  (void) file;
  (void) link;
  return 0;
}


int parse_dir(const char* list, const char* dir,
              const char* name, struct stat* sbuf,
              char* linkbuf, int linklen,
              fuse_cache_dirh_t h, fuse_cache_dirfil_t filler) {
  char *file;
  char *link;
  const char *start = list;
  const char *end = list;
  char found = 0;
  struct stat stat_buf;

  if (sbuf) memset(sbuf, 0, sizeof(struct stat));

  if (name && sbuf && name[0] == '\0') {
    sbuf->st_mode |= S_IFDIR;
    sbuf->st_mode |= 0755;
    sbuf->st_size = 1024;
    sbuf->st_nlink = 1;
    return 0;
  }

  file = (char *)malloc(1024*sizeof(char));
  link = (char *)malloc(1024*sizeof(char));

  while ((end = strchr(start, '\n')) != NULL) {
    char* line;

    memset(&stat_buf, 0, sizeof(stat_buf));

    if (end > start && *(end-1) == '\r') end--;

    line = (char*)malloc(end - start + 1);
    strncpy(line, start, end - start);
    line[end - start] = '\0';
    start = *end == '\r' ? end + 2 : end + 1;

    file[0] = link[0] = '\0';
    int res = parse_dir_unix(line, &stat_buf, file, link) ||
              parse_dir_win(line, &stat_buf, file, link) ||
              parse_dir_netware(line, &stat_buf, file, link);

    if (res) {
      char *full_path = g_strdup_printf("%s%s", dir, file);

      if (link[0]) {
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

      DEBUG("comparing %s %s\n", name, file);
      if (name && !strcmp(name, file)) {
        if (sbuf) *sbuf = stat_buf;
        found = 1;
      }
    }

    free(line);
  }

  free(file);
  free(link);

  return !found;
}
