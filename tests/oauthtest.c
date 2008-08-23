/**
 * Test and example code for liboauth.
 *
 * Copyright 2007, 2008 Robin Gareus <robin@gareus.org>
 * 
 * This code contains examples from http://wiki.oauth.net/ may they be blessed.
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

#define TEST_UNICODE

#ifdef TEST_UNICODE
#include <locale.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

int loglevel = 1; //< report each successful test

/**
 * test parameter encodinf
 */
int test_encoding(char *param, char *expected) {
  int rv=0;
  char *testcase=NULL;
  testcase = url_escape(param);
  if (strcmp(testcase,expected)) {
    rv=1;
    printf("parameter encoding test for '%s' failed.\n"
           " got: '%s' expected: '%s'\n", param, testcase, expected);
  } 
  else if (loglevel) printf("parameter encoding ok. ('%s')\n", testcase);
  if (testcase) free(testcase);
  return (rv);
}

#ifdef TEST_UNICODE
int test_uniencoding(wchar_t *src, char *expected) {
// check unicode: http://www.thescripts.com/forum/thread223350.html
  const char *encoding = "en_US.UTF-8"; // or try en_US.ISO-8859-1 etc.
  //wchar_t src[] = {0x0080, 0};

  if(setlocale(LC_CTYPE, encoding) == NULL) {
    printf("requested encoding unavailable\n");
    return -1;
  }

  size_t n = wcstombs(NULL, src, 0);
  char *dst = malloc(n + 1);
  if(dst == NULL) {
    printf("memory allocation failed\n");
    return -2;
  }
  if(wcstombs(dst, src, n + 1) != n) {
    printf("conversion failed\n");
    free(dst);
    return -3;
  }
  return test_encoding(dst, expected);
}
#endif

int test_normalize(char *param, char *expected) {
  int rv=2;
  int  i, argc;
  char **argv = NULL;
  char *tmp;

  argc = split_url_parameters(param, &argv);
  qsort(argv, argc, sizeof(char *), oauth_cmpstringp);
  char *testcase= serialize_url(argc,0, argv);

  rv=strcmp(testcase,expected);
  if (rv) {
    printf("parameter normalization test failed for: '%s'.\n"
           " got: '%s' expected: '%s'\n", param, testcase, expected);
  }
  else if (loglevel) printf("parameter normalization ok. ('%s')\n", testcase);
  for (i=0;i<argc;i++) free(argv[i]);
  if (argv) free(argv);
  if (testcase) free(testcase);
  return (rv);
}

int test_request(char *http_method, char *request, char *expected) {
  int rv=2;
  int  i, argc;
  char **argv = NULL;
  char *tmp;

  argc = split_url_parameters(request, &argv);
  qsort(&argv[1], argc-1, sizeof(char *), oauth_cmpstringp);
  char *query= serialize_url(argc,1, argv);
  char *testcase = catenc(3, http_method, argv[0], query);

  rv=strcmp(testcase,expected);
  if (rv) {
    printf("request concatenation test failed for: '%s'.\n"
           " got: '%s' expected: '%s'\n", request, testcase, expected);
  }
  else if (loglevel) printf("request concatenation ok.\n");
  for (i=0;i<argc;i++) free(argv[i]);
  if (argv) free(argv);
  if (query) free(query);
  if (testcase) free(testcase);
  return (rv);
}

int test_sha1(char *c_secret, char *t_secret, char *base, char *expected) {
  int rv=0;
  char *okey = catenc(2, c_secret, t_secret);
  char *b64d = oauth_sign_hmac_sha1(base, okey);
  if (strcmp(b64d,expected)) {
    printf("HMAC-SHA1 invalid. base:'%s' secrets:'%s'\n"
           " got: '%s' expected: '%s'\n", base, okey, b64d, expected);
    rv=1;
  } else if (loglevel) printf("HMAC-SHA1 test sucessful.\n");
  free(b64d);
  free(okey);
  return (rv);
}

/** 
 * a example requesting and parsing a request-token from an oAuth service-provider
 * excercising the oauth-HTTP function.
 */
void request_token_example(void) {
  const char *request_token_uri = "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token";
  const char *req_c_key         = "17b09ea4c9a4121145936f0d7d8daa28047583796"; //< consumer key
  const char *req_c_secret      = "942295b08ffce77b399419ee96ac65be"; //< consumer secret
  char *res_t_key    = NULL; //< reply key
  char *res_t_secret = NULL; //< reply secret

  char *req_url = NULL;
  char *postarg = NULL;

  req_url = oauth_sign_url(request_token_uri, &postarg, OA_HMAC, req_c_key, req_c_secret, NULL, NULL);

  printf("request URL:%s\n\n", req_url);
  char *reply = oauth_http_post(req_url,postarg);
  if (!reply) 
    printf("HTTP request for an oauth request-token failed.\n");
  else {
    printf("HTTP-reply: %s\n", reply);
    //example reply: 
    //"oauth_token=2a71d1c73d2771b00f13ca0acb9836a10477d3c56&oauth_token_secret=a1b5c00c1f3e23fb314a0aa22e990266"

    //parse reply
    int rc;
    char **rv = NULL;
    rc = split_url_parameters(reply, &rv);
    qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
    if( rc==2 
	&& !strncmp(rv[0],"oauth_token=",11)
	&& !strncmp(rv[1],"oauth_token_secret=",18) ){
	  res_t_key=strdup(&(rv[0][12]));
	  res_t_secret=strdup(&(rv[1][19]));
	  printf("key:    '%s'\nsecret: '%s'\n",res_t_key, res_t_secret);
    }
    if(rv) free(rv);
  }

  if(req_url) free(req_url);
  if(postarg) free(postarg);
  if(reply) free(reply);
  if(res_t_key) free(res_t_key);
  if(res_t_secret) free(res_t_secret);
}

/**
 * Test and Example Code.
 * 
 * compile:
 *  gcc -lssl -loauth -o oauthtest
 */
int main (int argc, char **argv) {

  if (loglevel) printf("\n *** testing liboauth against http://wiki.oauth.net/TestCases (july 2008) ***\n");

#if 1 // http://wiki.oauth.net/TestCases
  int fail=0;

  fail|=test_encoding("abcABC123","abcABC123");
  fail|=test_encoding("-._~","-._~");
  fail|=test_encoding("%","%25");
  fail|=test_encoding("+","%2B");
  fail|=test_encoding("&=*","%26%3D%2A");

 #ifdef TEST_UNICODE
  wchar_t src[] = {0x000A, 0};
                   fail|=test_uniencoding(src,"%0A");
  src[0] = 0x0020; fail|=test_uniencoding(src,"%20");
  src[0] = 0x007F; fail|=test_uniencoding(src,"%7F");
  src[0] = 0x0080; fail|=test_uniencoding(src,"%C2%80");
  src[0] = 0x3001; fail|=test_uniencoding(src,"%E3%80%81");
 #endif

  fail|=test_normalize("name", "name=");
  fail|=test_normalize("a=b", "a=b");
  fail|=test_normalize("a=b&c=d", "a=b&c=d");
  fail|=test_normalize("a=x!y&a=x+y", "a=x%20y&a=x%21y");
  fail|=test_normalize("x!y=a&x=a", "x=a&x%21y=a");

  fail|=test_request("GET", "http://example.com/" "?" 
      "n=v",
  // expect:
      "GET&http%3A%2F%2Fexample.com%2F&n%3Dv");

  fail|=test_request("GET", "http://example.com" "?" 
      "n=v",
  // expect:
      "GET&http%3A%2F%2Fexample.com%2F&n%3Dv");

  fail|=test_request("POST", "https://photos.example.net/request_token" "?" 
      "oauth_version=1.0"
      "&oauth_consumer_key=dpf43f3p2l4k3l03"
      "&oauth_timestamp=1191242090"
      "&oauth_nonce=hsu94j3884jdopsl"
      "&oauth_signature_method=PLAINTEXT"
      "&oauth_signature=ignored",
  // expect:
      "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0");

  fail|=test_request("GET", "http://photos.example.net/photos" "?" 
      "file=vacation.jpg&size=original"
      "&oauth_version=1.0"
      "&oauth_consumer_key=dpf43f3p2l4k3l03"
      "&oauth_token=nnch734d00sl2jdk"
      "&oauth_timestamp=1191242096"
      "&oauth_nonce=kllo9940pd9333jh"
      "&oauth_signature=ignored"
      "&oauth_signature_method=HMAC-SHA1",
  // expect:
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");

  fail|=test_sha1("cs","","bs","egQqG5AJep5sJ7anhXju1unge2I=");
  fail|=test_sha1("cs","ts","bs","VZVjXceV7JgPq/dOTnNmEfO0Fv8=");
  fail|=test_sha1("kd94hf93k423kf44","pfkkdhi9sl3r4s00","GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal","tR3+Ty81lMeYAr/Fid0kMTYa/WM=");

  if (fail) {
    printf("\n !!! One or more tests from http://wiki.oauth.net/TestCases failed.\n\n");
  } else {
    printf(" *** http://wiki.oauth.net/TestCases verified sucessfully.\n");
  }
#endif

#if 1 // HMAC-SHA1 selftest.
  // see http://oauth.net/core/1.0/#anchor25 
  char *b64d;
  char *testurl = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3D"
      "vacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce"
      "%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26o"
      "auth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk"
      "%26oauth_version%3D1.0%26size%3Doriginal";

  char *testkey = "kd94hf93k423kf44&pfkkdhi9sl3r4s00";
  b64d = oauth_sign_hmac_sha1(testurl , testkey);
  if (strcmp(b64d,"tR3+Ty81lMeYAr/Fid0kMTYa/WM=")) {
    printf("\n !!! HMAC-SHA1 signature selftest failed.\n\n");
    fail|=1;
  } else 
    printf(" *** HMAC-SHA1 signature selftest successful.\n");
  free(b64d);
#endif

#if 0
  b64d = oauth_sign_rsa_sha1(testurl , "");
  printf("rsa sig: '%s'\n",b64d);
  free(b64d);
#else
  printf(" --- RSA-SHA1 skipped. RSA signature is not yet implemented.\n");
#endif


  // example code.

  const char *url      = "http://base.url/&just=append?post=or_get_parameters"
                         "&arguments=will_be_formatted_automatically?&dont_care"
			 "=about_separators";
			 //< the url to sign
  const char *c_key    = "1234567890abcdef1234567890abcdef123456789";
  			//< consumer key
  const char *c_secret = "01230123012301230123012301230123";
  			//< consumer secret
  const char *t_key    = "0987654321fedcba0987654321fedcba098765432";
  			//< token key
  const char *t_secret = "66666666666666666666666666666666";
  			//< token secret

#if 0 // example sign GET request
  char *geturl = NULL;
  geturl = oauth_sign_url(url, NULL, OA_HMAC, c_key, c_secret, t_key, t_secret);
  printf("GET: URL:%s\n\n", geturl);
  if(geturl) free(geturl);
#endif

#if 0 // POST sign example
  char *postargs = NULL, *post = NULL;
  post = oauth_sign_url(url, &postargs, OA_HMAC, c_key, c_secret, t_key, t_secret);
  printf("POST: URL:%s\n      PARAM:%s\n\n", post, postargs);
  if(post) free(post);
  if(postargs) free(postargs);
#endif

#if 0 // request-token request
  request_token_example();
#endif

  return (fail?1:0);
}
