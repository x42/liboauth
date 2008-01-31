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
#include <sys/stat.h>

struct MemoryStruct {
  char *data;
  size_t size;
};

static size_t
WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)data;

  mem->data = (char *)xrealloc(mem->data, mem->size + realsize + 1);
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

/**
 * cURL http post raw data from file.
 * the returned string needs to be freed by the caller
 *
 * @param u url to retrieve
 * @param fn filename of the file to post along
 * @param len length of the file in bytes. set to '0' for autodetection
 * @param customheader specify custom HTTP header (or NULL for default)
 * @return returned HTTP or NULL on error
 */
char *oauth_curl_post_file (char *u, char *fn, size_t len, char *customheader) {
  CURL *curl;
  CURLcode res;

  struct MemoryStruct chunk;
  chunk.data=NULL;
  chunk.size = 0;

  struct curl_slist *slist=NULL;
  if (customheader)
    slist = curl_slist_append(slist, customheader);
  else
    slist = curl_slist_append(slist, "Content-Type: image/jpeg;");

  if (!len) {
    struct stat statbuf;
    if (stat(fn, &statbuf) == -1) return(NULL);
    len = statbuf.st_size;
  }

  FILE *f = fopen(fn,"r");
  if (!f) return NULL;

  curl = curl_easy_init();
  if(!curl) return NULL;
  curl_easy_setopt(curl, CURLOPT_URL, u);
  curl_easy_setopt(curl, CURLOPT_POST, 1);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist); 
  curl_easy_setopt(curl, CURLOPT_READDATA, f);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "liboauth-agent/0.1");
  res = curl_easy_perform(curl);
  if (res) {
    // error
    return NULL;
  }
  fclose(f);

  curl_easy_cleanup(curl);
  return (chunk.data);
}

#endif // no cURL.

#define _OAUTH_ENV_HTTPCMD "OAUTH_HTTP_CMD"
#define _OAUTH_DEF_HTTPCMD "curl -sA 'liboauth-agent/0.1' -d '%p' '%u' "
// alternative: "wget -q -U 'liboauth-agent/0.1' --post-data='%p' '%u' "

#include <stdio.h>

/**
 * send POST via a command line HTTP client.
 */
char *oauth_exec_post (char *u, char *p) {
  char cmd[1024];
  char *cmdtpl = getenv(_OAUTH_ENV_HTTPCMD);
  if (!cmdtpl) cmdtpl = strdup (_OAUTH_DEF_HTTPCMD);
  else cmdtpl = strdup (cmdtpl); // clone getenv() string.

  // add URL and post param - error if no '%p' or '%u' present in definition
  char *t1,*t2, *tmp;
  t1=strstr(cmdtpl, "%p");
  t2=strstr(cmdtpl, "%u");
  if (!t1 || !t2) {
	fprintf(stderr, "invalid HTTP command. set the '%s' environement variable.\n",_OAUTH_ENV_HTTPCMD);
	return(NULL); // FIXME
  }
  *(++t1)= 's'; *(++t2)= 's';
  // TODO: check if there are exactly two '%' in cmdtpl
  if (t1 > t2) { t1=u; t2=p; } else { t1=p; t2=u; }
  snprintf(cmd, 1024, cmdtpl, t1, t2);
  // FIXME shell-escape cmd ?!
  //printf("DEBUG: executing: %s\n",cmd);
  FILE *in = popen (cmd, "r");
  size_t len = 0;
  size_t alloc = 0;
  char *data = NULL;
  int rcv = 1;
  while (in && rcv > 0 && !feof(in)) {
    alloc +=1024;
    data = xrealloc(data, alloc * sizeof(char));
    rcv = fread(data, sizeof(char), 1024, in);
    len += rcv;
  }
  pclose(in);
  free(cmdtpl);
  //printf("DEBUG: read %i bytes\n",len);
  data[len]=0;
  //if (data) printf("DEBUG: return: %s\n",data);
  //else printf("DEBUG: NULL data\n");
  return (data);
}

/**
 * do a HTTP POST request, wait for it to finish 
 * and return the content of the reply.
 * (requires libcurl or a command-line HTTP client)
 *
 * @param u url to query
 * @param p postargs to send along with the HTTP request.
 * @return  In case of an error NULL is returned; otherwise a pointer to the
 * replied content from HTTP server. latter needs to be freed by caller.
 */
char *oauth_http_post (char *u, char *p) {
#ifdef HAVE_CURL
  return oauth_curl_post(u,p);
#else // no cURL.
  return oauth_exec_post(u,p);
#endif
}

/**
 * http post raw data from file.
 * the returned string needs to be freed by the caller
 *
 * @param u url to retrieve
 * @param fn filename of the file to post along
 * @param len length of the file in bytes. set to '0' for autodetection
 * @param customheader specify custom HTTP header (or NULL for default)
 * @return returned HTTP reply or NULL on error
 */
char *oauth_post_file (char *u, char *fn, size_t len, char *contenttype){
#ifdef HAVE_CURL
  return oauth_curl_post_file (u, fn, len, contenttype);
#else
  fprintf(stderr, "Warning: oauth_post_file requires curl. curl is not available.\n");
#endif
}
