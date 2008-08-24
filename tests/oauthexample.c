/**
 * Test and example code for liboauth.
 *
 * Copyright 2008 Robin Gareus <robin@gareus.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

int parse_reply(const char *reply, char **token, char **secret) {
  int rc;
  int ok=1;
  char **rv = NULL;
  rc = split_url_parameters(reply, &rv);
  qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
  if( rc==2 
      && !strncmp(rv[0],"oauth_token=",11)
      && !strncmp(rv[1],"oauth_token_secret=",18) ) {
    ok=0;
    if (token)  *token =strdup(&(rv[0][12]));
    if (secret) *secret=strdup(&(rv[1][19]));
    printf("key:    '%s'\nsecret: '%s'\n",*token, *secret); // XXX 
  }
  if(rv) free(rv);
  return ok;
}

/** 
 * a example requesting and parsing a request-token from an oAuth service-provider
 * using the oauth-HTTP POST function.
 */
int request_token_example_post(void) {
  const char *request_token_uri = "http://term.ie/oauth/example/request_token.php";
  const char *access_token_uri = "http://term.ie/oauth/example/access_token.php";
  const char *test_call_uri = "http://term.ie/oauth/example/echo_api.php?method=foo&bar=baz";
  const char *c_key         = "key"; //< consumer key
  const char *c_secret      = "secret"; //< consumer secret
  char *t_key    = NULL; //< access token key
  char *t_secret = NULL; //< access token secret

  char *req_url = NULL;
  char *postarg = NULL;

  printf("Request token..\n");
  req_url = oauth_sign_url(request_token_uri, &postarg, OA_HMAC, c_key, c_secret, NULL, NULL);
  char *reply = oauth_http_post(req_url,postarg);
  if (req_url) free(req_url);
  if (postarg) free(postarg);
  if (!reply) return(1);
  if (parse_reply(reply, &t_key, &t_secret)) return(2);
  free(reply);

  printf("Access token..\n");

  req_url = oauth_sign_url(access_token_uri, &postarg, OA_HMAC, c_key, c_secret, t_key, t_secret);
  reply = oauth_http_post(req_url,postarg);
  if (req_url) free(req_url);
  if (postarg) free(postarg);
  if (!reply) return(3);
  if(t_key) free(t_key);
  if(t_secret) free(t_secret);
  if (parse_reply(reply, &t_key, &t_secret)) return(4);
  free(reply);

  printf("make some request..\n");

  req_url = oauth_sign_url(test_call_uri, &postarg, OA_HMAC, c_key, c_secret, t_key, t_secret);
  reply = oauth_http_post(req_url,postarg);
  printf("%s\n",reply);
  if(req_url) free(req_url);
  if(postarg) free(postarg);

  if (strcmp(reply,"bar=baz&method=foo")) return (5);

  if(reply) free(reply);
  if(t_key) free(t_key);
  if(t_secret) free(t_secret);

  return(0);
}


/**
 * Main Test and Example Code.
 * 
 * compile:
 *  gcc -lssl -loauth -o oauthexample oauthexample.c
 */

int main (int argc, char **argv) {
  switch(request_token_example_post()) {
    case 1:
      printf("HTTP request for an oauth request-token failed.\n");
      break;
    case 2:
      printf("did not receive a request-token.\n");
      break;
    case 3:
      printf("HTTP request for an oauth access-token failed.\n");
      break;
    case 4:
      printf("did not receive an access-token.\n");
      break;
    case 5:
      printf("test call 'echo-api' did not respond correctly.\n");
      break;
    default:
      printf("request ok.\n");
      break;
  }
  return(0);
}
