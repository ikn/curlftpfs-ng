/*
    FTP file system
    Copyright (C) 2007 Robson Braga Araujo <robsonbraga@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "path_utils.h"
#include "charset_utils.h"
#include "ftpfs.h"

#include <string.h>
#include <stdlib.h>
#include <glib.h>

char* get_file_name(const char* path) {
  const char* filename = strrchr(path, '/');
  if (filename == NULL) filename = path;
  else ++filename;

  char* ret = strdup(filename);
  if (ftpfs.codepage) {
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &ret);
  }
  
  return ret;
}

char* get_full_path(const char* path) {
  char* ret;
  char* converted_path = NULL;
  
  ++path;

  if (ftpfs.codepage && strlen(path)) {
    converted_path = strdup(path);
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &converted_path);
    path = converted_path;
  }

  const char *const escaped_path = g_uri_escape_string(path, "/", FALSE);
  ret = g_strdup_printf("%s%s", ftpfs.host, escaped_path);

  free(converted_path);
  free((char *) escaped_path);

  return ret;
}

char* get_fulldir_path(const char* path) {
  char* ret;
  char* converted_path = NULL;

  ++path;

  if (ftpfs.codepage && strlen(path)) {
    converted_path = strdup(path);
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &converted_path);
    path = converted_path;
  }

  const char *const escaped_path = g_uri_escape_string(path, "/", FALSE);
  ret = g_strdup_printf(
    "%s%s%s", ftpfs.host, escaped_path, strlen(escaped_path) ? "/" : "");

  free(converted_path);
  free((char *) escaped_path);

  return ret;
}

char* get_dir_path(const char* path) {
  char* ret;
  char* converted_path = NULL;
  const char *lastdir;

  ++path;

  if (ftpfs.codepage) {
    converted_path = g_strdup(path);
    convert_charsets(ftpfs.iocharset, ftpfs.codepage, &converted_path);
    path = converted_path;
  }

  const char *const escaped_path = g_uri_escape_string(path, "/", FALSE);
  lastdir = strrchr(escaped_path, '/');
  if (lastdir == NULL) lastdir = escaped_path;

  ret = g_strdup_printf("%s%.*s%s",
                        ftpfs.host,
                        lastdir - escaped_path,
                        escaped_path,
                        lastdir - escaped_path ? "/" : "");

  free(converted_path);
  free((char *) escaped_path);

  return ret;
}
