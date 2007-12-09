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
  if (!strcmp(b64d,"tR3+Ty81lMeYAr/Fid0kMTYa/WM")) 
    printf("HMAC-SHA1 signature selftest failed.\n"); 
  else 
    printf("HMAC-SHA1 signature selftest successful.\n");
  free(b64d);
#endif

  return (0);
}
