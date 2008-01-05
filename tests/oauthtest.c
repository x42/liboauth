#include <stdio.h>
#include <oauth.h>

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

#if 1 // example request-token request
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
