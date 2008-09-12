/**
 *  @brief self-test and example code for liboauth.
 *  @file oauthtest.c
 *  @author Robin Gareus <robin@gareus.org>
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

#define TEST_UNICODE //< include unicode encoding tests

#ifdef TEST_UNICODE
#include <locale.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

int loglevel = 1; //< report each successful test

/*
 * test parameter encoding
 */
int test_encoding(char *param, char *expected) {
  int rv=0;
  char *testcase=NULL;
  testcase = oauth_url_escape(param);
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
/*
 * test unicode paramter encoding
 */
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

/*
 * test request normalization
 */
int test_normalize(char *param, char *expected) {
  int rv=2;
  int  i, argc;
  char **argv = NULL;
  char *tmp;

  argc = oauth_split_url_parameters(param, &argv);
  qsort(argv, argc, sizeof(char *), oauth_cmpstringp);
  char *testcase= oauth_serialize_url(argc,0, argv);

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

/*
 * test request concatenation
 */
int test_request(char *http_method, char *request, char *expected) {
  int rv=2;
  int  i, argc;
  char **argv = NULL;
  char *tmp;

  argc = oauth_split_url_parameters(request, &argv);
  qsort(&argv[1], argc-1, sizeof(char *), oauth_cmpstringp);
  char *query= oauth_serialize_url(argc,1, argv);
  char *testcase = oauth_catenc(3, http_method, argv[0], query);

  rv=strcmp(testcase,expected);
  if (rv) {
    printf("request concatenation test failed for: '%s'.\n"
           " got:      '%s'\n expected: '%s'\n", request, testcase, expected);
  }
  else if (loglevel) printf("request concatenation ok.\n");
  for (i=0;i<argc;i++) free(argv[i]);
  if (argv) free(argv);
  if (query) free(query);
  if (testcase) free(testcase);
  return (rv);
}

/*
 * test hmac-sha1 checksum
 */
int test_sha1(char *c_secret, char *t_secret, char *base, char *expected) {
  int rv=0;
  char *okey = oauth_catenc(2, c_secret, t_secret);
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

/* 
 * a example requesting and parsing a request-token from an oAuth service-provider
 * excercising the oauth-HTTP GET function. - it is almost the same as 
 * \ref request_token_example_post below. 
 */
void request_token_example_get(void) {
  const char *request_token_uri = "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token";
  const char *req_c_key         = "17b09ea4c9a4121145936f0d7d8daa28047583796"; //< consumer key
  const char *req_c_secret      = "942295b08ffce77b399419ee96ac65be"; //< consumer secret
  char *res_t_key    = NULL; //< replied key
  char *res_t_secret = NULL; //< replied secret

  char *req_url = NULL;

  req_url = oauth_sign_url(request_token_uri, NULL, OA_HMAC, req_c_key, req_c_secret, NULL, NULL);

  printf("request URL:%s\n\n", req_url);
  char *reply = oauth_http_get(req_url,NULL);
  if (!reply) 
    printf("HTTP request for an oauth request-token failed.\n");
  else {
    printf("HTTP-reply: %s\n", reply);
    //example reply: 
    //"oauth_token=2a71d1c73d2771b00f13ca0acb9836a10477d3c56&oauth_token_secret=a1b5c00c1f3e23fb314a0aa22e990266"

    //parse reply
    int rc;
    char **rv = NULL;
    rc = oauth_split_url_parameters(reply, &rv);
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
  if(reply) free(reply);
  if(res_t_key) free(res_t_key);
  if(res_t_secret) free(res_t_secret);
}

/*
 * a example requesting and parsing a request-token from an oAuth service-provider
 * using the oauth-HTTP POST function.
 */
void request_token_example_post(void) {
#if 1
  const char *request_token_uri = "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token";
  const char *req_c_key         = "17b09ea4c9a4121145936f0d7d8daa28047583796"; //< consumer key
  const char *req_c_secret      = "942295b08ffce77b399419ee96ac65be"; //< consumer secret
#else
  const char *request_token_uri = "http://term.ie/oauth/example/request_token.php";
  const char *req_c_key         = "key"; //< consumer key
  const char *req_c_secret      = "secret"; //< consumer secret
#endif
  char *res_t_key    = NULL; //< replied key
  char *res_t_secret = NULL; //< replied secret

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
    rc = oauth_split_url_parameters(reply, &rv);
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


/*
 * Main Test and Example Code.
 * 
 * compile:
 *  gcc -lssl -loauth -o oauthtest oauthtest.c
 */
int main (int argc, char **argv) {
  int fail=0;

  if (loglevel) printf("\n *** testing liboauth against http://wiki.oauth.net/TestCases (july 2008) ***\n");

#if 1 // Eran's test-cases - http://groups.google.com/group/oauth/browse_frm/thread/243f4da439fd1f51?hl=en
  fail|=test_encoding("1234=asdf=4567","1234%3Dasdf%3D4567");
  fail|=test_encoding("asdf-4354=asew-5698","asdf-4354%3Dasew-5698");
  fail|=test_encoding("erks823*43=asd&123ls%23","erks823%2A43%3Dasd%26123ls%2523");
  fail|=test_encoding("dis9$#$Js009%==","dis9%24%23%24Js009%25%3D%3D");
  fail|=test_encoding("3jd834jd9","3jd834jd9");
  fail|=test_encoding("12303202302","12303202302");
  fail|=test_encoding("taken with a 30% orange filter","taken%20with%20a%2030%25%20orange%20filter");
  fail|=test_encoding("mountain & water view","mountain%20%26%20water%20view");

  fail|=test_request("GET", "http://example.com:80/photo" "?" 
      "oauth_version=1.0"
      "&oauth_consumer_key=1234=asdf=4567"
      "&oauth_timestamp=12303202302"
      "&oauth_nonce=3jd834jd9"
      "&oauth_token=asdf-4354=asew-5698"
      "&oauth_signature_method=HMAC-SHA1"
      "&title=taken with a 30% orange filter"
      "&file=mountain \001 water view"
      "&format=jpeg"
      "&include=date"
      "&include=aperture",
  "GET&http%3A%2F%2Fexample.com%2Fphoto&file%3Dmountain%2520%2526%2520water%2520view%26format%3Djpeg%26include%3Daperture%26include%3Ddate%26oauth_consumer_key%3D1234%253Dasdf%253D4567%26oauth_nonce%3D3jd834jd9%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D12303202302%26oauth_token%3Dasdf-4354%253Dasew-5698%26oauth_version%3D1.0%26title%3Dtaken%2520with%2520a%252030%2525%2520orange%2520filter" );

  char *tmptst;
  tmptst = oauth_sign_url(
      "http://example.com:80/photo" "?" 
      "oauth_version=1.0"
      "&oauth_timestamp=12303202302"
      "&oauth_nonce=3jd834jd9"
      "&title=taken with a 30% orange filter"
      "&file=mountain \001 water view"
      "&format=jpeg"
      "&include=date"
      "&include=aperture",
   NULL, OA_HMAC, "1234=asdf=4567", "erks823*43=asd&123ls%23", "asdf-4354=asew-5698", "dis9$#$Js009%==");
  if (strcmp(tmptst,"http://example.com/photo?file=mountain%20%26%20water%20view&format=jpeg&include=aperture&include=date&oauth_consumer_key=1234%3Dasdf%3D4567&oauth_nonce=3jd834jd9&oauth_signature_method=HMAC-SHA1&oauth_timestamp=12303202302&oauth_token=asdf-4354%3Dasew-5698&oauth_version=1.0&title=taken%20with%20a%2030%25%20orange%20filter&oauth_signature=jMdUSR1vOr3SzNv3gZ5DDDuGirA%3D")) {
  	printf(" got '%s'\n expected: '%s'\n",tmptst, "http://example.com/photo?file=mountain%20%26%20water%20view&format=jpeg&include=aperture&include=date&oauth_consumer_key=1234%3Dasdf%3D4567&oauth_nonce=3jd834jd9&oauth_signature_method=HMAC-SHA1&oauth_timestamp=12303202302&oauth_token=asdf-4354%3Dasew-5698&oauth_version=1.0&title=taken%20with%20a%2030%25%20orange%20filter&oauth_signature=jMdUSR1vOr3SzNv3gZ5DDDuGirA%3D");
	fail|=1;
  }
  if(tmptst) free(tmptst);
#endif

#if 1 // http://wiki.oauth.net/TestCases
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
    printf("HMAC-SHA1 signature test failed.\n");
    fail|=1;
  } else if (loglevel)
    printf("HMAC-SHA1 signature test successful.\n");
  free(b64d);
#endif

#if 1 // rsa-signature based on http://wiki.oauth.net/TestCases example
  b64d = oauth_sign_rsa_sha1(
    "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacaction.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3D13917289812797014437%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1196666512%26oauth_version%3D1.0%26size%3Doriginal",

    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V\n"
    "A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d\n"
    "7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ\n"
    "hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H\n"
    "X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm\n"
    "uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw\n"
    "rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z\n"
    "zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn\n"
    "qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG\n"
    "WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno\n"
    "cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+\n"
    "3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8\n"
    "AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54\n"
    "Lw03eHTNQghS0A==\n"
    "-----END PRIVATE KEY-----");

//printf("rsa-sig: '%s'\n",b64d);
  if (strcmp(b64d,"jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=")) {
    printf("RSA-SHA1 signature test failed.\n");
    fail|=1;
  } else if (loglevel)
    printf("RSA-SHA1 signature test successful.\n");
  free(b64d);

  int ok = oauth_verify_rsa_sha1(
    "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacaction.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3D13917289812797014437%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1196666512%26oauth_version%3D1.0%26size%3Doriginal",

    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0\n"
    "IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV\n"
    "BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n"
    "gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY\n"
    "zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb\n"
    "mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3\n"
    "DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d\n"
    "4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb\n"
    "WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J\n"
    "-----END CERTIFICATE-----\n", 
    "jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=");
  if (ok != 1) {
    printf("RSA-SHA1 verify-signature test failed.\n");
    fail|=1;
  } else if (loglevel)
    printf("RSA-SHA1 verify-signature test successful.\n");
#else
  printf("RSA-SHA1 skipped. RSA signature is not yet implemented.\n");
#endif


  if (fail) {
    printf("\n !!! One or more tests from http://wiki.oauth.net/TestCases failed.\n\n");
  } else {
    printf(" *** http://wiki.oauth.net/TestCases verified sucessfully.\n");
  }

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

// These two will make a request to http://oauth-sandbox.mediamatic.nl/
// requesting an access token. - it's intended both as test (verify signature) 
// and example code.
#if 0 // POST a request-token request
  request_token_example_post();
#endif
#if 0 // GET a request-token
  request_token_example_get();
#endif


  return (fail?1:0);
}
