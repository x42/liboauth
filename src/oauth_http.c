/*
 * oAuth string functions in POSIX-C.
 *
 * Copyright LGPL 2007 Robin Gareus <robin@mediamatic.nl>
 * 
 *  This package is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This package is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this package; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */
/* vi: sts=2 sw=2 ts=2 */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "oauth.h"

#ifdef HAVE_CURL
#include <curl/curl.h>

struct MemoryStruct {
  char *data;
  size_t size;
};

static size_t
WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)data;

  mem->data = (char *)realloc(mem->data, mem->size + realsize + 1);
  if (mem->data) {
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
  }
  return realsize;
}

/**
 * cURL http post function.
 * the returned string needs to be freed by the caller
 *
 * @param u url to retrieve
 * @param p post parameters 
 * @return returned HTTP
 */
char *oauth_curl_post (char *u, char *p) {

  CURL *curl;
  CURLcode res;

  struct MemoryStruct chunk;
  chunk.data=NULL;
  chunk.size = 0;

  curl = curl_easy_init();
  if(!curl) return NULL;
  curl_easy_setopt(curl, CURLOPT_URL, u);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "liboauth-agent/0.1");
  res = curl_easy_perform(curl);
  if (res) {
    // error
    return NULL;
  }

  curl_easy_cleanup(curl);
  return (chunk.data);
}

/**
 *
 */
char *oauth_curl_get (char *u, char *p) {
  ;
}
#endif // no cURL.

#define _OAUTH_ENV_HTTPCMD "OAUTH_HTTP_CMD"
//#define _OAUTH_DEF_HTTPCMD "curl -A 'liboauth-agent/0.1' -d '%p' '%u' "
#define _OAUTH_DEF_HTTPCMD "curl -A 'liboauth-agent/0.1' -d '%s' '%s' "

#include <stdio.h>

char *oauth_exec_post (char *u, char *p) {
  char cmd[1024];
  char *cmdtpl = getenv(_OAUTH_ENV_HTTPCMD);
  if (!cmdtpl) cmdtpl = strdup (_OAUTH_DEF_HTTPCMD);
  // add URL and post param - error if no '%p' or '%u' present in definition
  // TODO shell-escape cmd
  snprintf(cmd, 1024, cmdtpl, p, u);
  printf("DEBUG: executing: %s\n",cmd);
  FILE *in = popen (cmd, "r");
  size_t len = 0;
  size_t alloc = 0;
  char *data = NULL;
  int rcv = 1;
  while (in && rcv > 0 && !feof(in)) {
    alloc +=1024;
    data = realloc(data, alloc * sizeof(char));
    rcv = fread(data, sizeof(char), 1024, in);
    len += rcv;
  }
  pclose(in);
  if (data) printf("DEBUG: return: %s\n",data);
  else printf("DEBUG: NULL data\n");
  return (data);
}


char *oauth_http_post (char *u, char *p) {
  return oauth_exec_post(u,p);

#ifdef HAVE_CURL
  return oauth_curl_post(u,p);
#else // no cURL.
  return NULL;
#endif
}
