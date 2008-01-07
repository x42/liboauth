#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <oauth.h>
/*
static int cmpstringp(const void *p1, const void *p2) {
  char *v1,*v2;
  char *t1,*t2;
  int rv;

  v1=url_escape(* (char * const *)p1);
  v2=url_escape(* (char * const *)p2);
  char *tmp;
  if ((t1=strstr(v1,"%3D"))) {
    t1[0]='\0'; t1[1]='='; t1[2]='=';
  }
  if ((t2=strstr(v2,"%3D"))) {
    t2[0]='\0'; t2[1]='='; t2[2]='=';
  }
  rv=strcmp(v1,v2);
  if (rv!=0) {
    if (v1) free(v1);
    if (v2) free(v2);
    return rv;
  }

  t1[0]='='; t2[0]='=';
  rv=strcmp(t1,t2);
  if (v1) free(v1);
  if (v2) free(v2);
  return rv;
}
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
  else printf("parameter encoding ok.\n");
  if (testcase) free(testcase);
  return (rv);
}

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
  else printf("parameter normalization ok.\n");
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
  else printf("request concatenation ok.\n");
  for (i=0;i<argc;i++) free(argv[i]);
  if (argv) free(argv);
  if (query) free(query);
  if (testcase) free(testcase);
  return (rv);
}

/**
 * Test and Example Code.
 * 
 * compile:
 *  gcc -lssl -loauth -o oauthtest
 */
int main (int argc, char **argv) {
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

#if 0 // example request-token request
  const char *request_token_uri  = "http://localhost/mm/trunk/www/module/OAuth/request_token";
  const char *access_token_uri   = "http://localhost/mm/trunk/www/module/OAuth/access_token";
  const char *req_c_key    = "58d602f54c9168cbb070dc0bd47deef40477c0a6e";
  			//< consumer key
  const char *req_c_secret = "58b2eae9e4a5029a5b7a4beffaae40f0";
  			//< consumer secret
  char *res_t_key    = NULL; //< token key
  char *res_t_secret = NULL; //< token secret
  /// see ./OAuth.mod.php -> httpRequest_consumer_connect()
  /// http://localhost/mm/trunk/www/module/OAuth/consumer/connect?consumer_key=58d602f54c9168cbb070dc0bd47deef40477c0a6e
  char *req_url = NULL;
  char *postarg = NULL;

  req_url = oauth_sign_url(request_token_uri, &postarg, OA_HMAC, req_c_key, req_c_secret, NULL, NULL);
  printf("request URL:%s\n\n", req_url);
  char *reply = oauth_http_post(req_url,postarg);
  printf("reply: %s\n", reply);
  int rc;
  char **rv = NULL;
  rc = split_url_parameters(reply, &rv);
  // TODO: sort parameters. 
  if( rc==2 
      && !strncmp(rv[0],"oauth_token=",11)
      && !strncmp(rv[1],"oauth_token_secret=",18) ){
        res_t_key=xstrdup(&(rv[0][12]));
        res_t_secret=xstrdup(&(rv[1][19]));
        printf("token-key:    '%s'\ntoken-secret: '%s'\n",res_t_key, res_t_secret);
  }

  if(req_url) free(req_url);
  if(postarg) free(postarg);
  if(reply) free(reply);
  //if(rv) free(rv);
  if(res_t_key) free(res_t_key);
  if(res_t_secret) free(res_t_secret);

  //example reply: 
  //"oauth_token=2a71d1c73d2771b00f13ca0acb9836a10477d3c56&oauth_token_secret=a1b5c00c1f3e23fb314a0aa22e990266"
#endif

#if 0 // example sign GET request
  char *geturl = NULL;
  geturl = oauth_sign_url(url, NULL, OA_HMAC, c_key, c_secret, t_key, t_secret);
  printf("GET: URL:%s\n\n", geturl);
  if(geturl) free(geturl);
#endif

#if 0 // POST example
  char *postargs = NULL, *post = NULL;
  post = oauth_sign_url(url, &postargs, OA_HMAC, c_key, c_secret, t_key, t_secret);
  printf("POST: URL:%s\n      PARAM:%s\n\n", post, postargs);
  if(post) free(post);
  if(postargs) free(postargs);
#endif

#if 1 // http://wiki.oauth.net/TestCases

  test_encoding("abcABC123","abcABC123");
  test_encoding("-._~","-._~");
  test_encoding("%","%25");
  test_encoding("&=*","%26%3D%2A");

  test_normalize("name", "name=");
  test_normalize("a=b", "a=b");
  test_normalize("a=b&c=d", "a=b&c=d");
  test_normalize("a=x!y&a=x+y", "a=x%20y&a=x%21y");
  test_normalize("x!y=a&x=a", "x=a&x%21y=a");

  test_request("GET", "http://example.com" "?" 
      "n=v",
      "GET&http%3A%2F%2Fexample.com&n%3Dv");

  test_request("POST", "https://photos.example.net/request_token" "?" 
      "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03"
      "&oauth_timestamp=1191242090&oauth_nonce=hsu94j3884jdopsl"
      "&oauth_signature_method=PLAINTEXT&oauth_signature=ignored",
      "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0");

  test_request("GET", "http://photos.example.net/photos" "?" 
      "file=vacation.jpg&size=original"
      "&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03"
      "&oauth_token=nnch734d00sl2jdk"
      "&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh"
      "&oauth_signature=ignored&oauth_signature_method=HMAC-SHA1",
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");

/*
  //urgc = split_url_parameters("a=b&c=d", &urgv);
  //urgc = split_url_parameters("http:?a=x!y&a=x z", &urgv);
  //urgc = split_url_parameters("http:?a=x!y&a=x+z", &urgv);
  //urgc = split_url_parameters("http:?x!y=a&x=a", &urgv);
  //urgc = split_url_parameters("http://example.com?n=v", &urgv);
  //urgc = split_url_parameters("https://photos.example.net/request_token" "?" "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1191242090&oauth_nonce=hsu94j3884jdopsl&oauth_signature_method=PLAINTEXT&oauth_signature=ignored", &urgv);
  urgc = split_url_parameters("http://photos.example.net/photos" "&" "file=vacation.jpg&size=original&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh&oauth_signature=ignored&oauth_signature_method=HMAC-SHA1", &urgv);
  //if (strcmp(odat,"POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0")) {
  if (strcmp(odat,"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal")) {
  	printf("parameter encoding testcase failed.\n");
  	printf("        : '%s'\n", "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");
  }
  if (query) free(query);
  if (odat) free(odat);
  #endif
*/
#endif

// check unicode: http://www.thescripts.com/forum/thread223350.html
#if 1
  const char *encoding = "en_US.UTF-8"; // or try en_US.ISO-8859-1 etc.
  wchar_t src[] = {0x4F60, 0x597D, 0};

  if(setlocale(LC_CTYPE, encoding) == NULL) {
    fprintf(stderr, "requested encoding unavailable\n");
    //return NULL;
  }

  size_t n = wcstombs(NULL, src, 0);
  char *dst = malloc(n + 1);
  if(dst == NULL) {
    fprintf(stderr, "memory allocation failed\n");
    //return NULL;
  }
  if(wcstombs(dst, src, n + 1) != n) {
    fprintf(stderr, "conversion failed\n");
    free(dst);
    //return NULL;
  }
#endif

#if 0 // HMAC-SHA1 selftest.
  // see http://oauth.net/core/1.0/#anchor25 
  char *b64d;
  char *testurl = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3D"
      "vacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce"
      "%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26o"
      "auth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk"
      "%26oauth_version%3D1.0%26size%3Doriginal";

  char *testkey = "kd94hf93k423kf44&pfkkdhi9sl3r4s00";
  b64d = oauth_sign_hmac_sha1(testurl , testkey);
  if (!strcmp(b64d,"tR3+Ty81lMeYAr/Fid0kMTYa/WM")) 
    printf("HMAC-SHA1 signature selftest failed.\n"); 
  else 
    printf("HMAC-SHA1 signature selftest successful.\n");
  free(b64d);
#endif

  return (0);
}
