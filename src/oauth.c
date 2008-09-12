/*
 * oAuth string functions in POSIX-C.
 *
 * Copyright 2007, 2008 Robin Gareus <robin@gareus.org>
 * 
 * The base64 functions are by Jan-Henrik Haukeland, <hauk@tildeslash.com>
 * and escape_url() was inspired by libcurl's curl_escape under ISC-license
 * many thanks to Daniel Stenberg <daniel@haxx.se>.
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
 * 
 */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#define WIPE_MEMORY ///< overwrite sensitve data before free()ing it.

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/hmac.h>

#include "xmalloc.h"
#include "oauth.h"

#ifndef WIN // getpid() on POSIX systems
#include <sys/types.h>
#include <unistd.h>
#endif

/**
 * Base64 encode one byte
 */
char oauth_b64_encode(unsigned char u) {
  if(u < 26)  return 'A'+u;
  if(u < 52)  return 'a'+(u-26);
  if(u < 62)  return '0'+(u-52);
  if(u == 62) return '+';
  return '/';
}

/**
 * Decode a single base64 character.
 */
unsigned char oauth_b64_decode(char c) {
  if(c >= 'A' && c <= 'Z') return(c - 'A');
  if(c >= 'a' && c <= 'z') return(c - 'a' + 26);
  if(c >= '0' && c <= '9') return(c - '0' + 52);
  if(c == '+')             return 62;
  return 63;
}

/**
 * Return TRUE if 'c' is a valid base64 character, otherwise FALSE
 */
int oauth_b64_is_base64(char c) {
  if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
     (c >= '0' && c <= '9') || (c == '+')             ||
     (c == '/')             || (c == '=')) {
    return 1;
  }
  return 0;
}

/**
 * Base64 encode and return size data in 'src'. The caller must free the
 * returned string.
 *
 * @param size The size of the data in src
 * @param src The data to be base64 encode
 * @return encoded string otherwise NULL
 */
char *oauth_encode_base64(int size, unsigned char *src) {
  int i;
  char *out, *p;

  if(!src) return NULL;
  if(!size) size= strlen((char *)src);
  out= (char*) xcalloc(sizeof(char), size*4/3+4);
  p= out;

  for(i=0; i<size; i+=3) {
    unsigned char b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0;
    b1= src[i];
    if(i+1<size) b2= src[i+1];
    if(i+2<size) b3= src[i+2];
      
    b4= b1>>2;
    b5= ((b1&0x3)<<4)|(b2>>4);
    b6= ((b2&0xf)<<2)|(b3>>6);
    b7= b3&0x3f;
      
    *p++= oauth_b64_encode(b4);
    *p++= oauth_b64_encode(b5);
      
    if(i+1<size) *p++= oauth_b64_encode(b6);
    else *p++= '=';
      
    if(i+2<size) *p++= oauth_b64_encode(b7);
    else *p++= '=';
  }
  return out;
}

/**
 * Decode the base64 encoded string 'src' into the memory pointed to by
 * 'dest'. 
 *
 * @param dest Pointer to memory for holding the decoded string.
 * Must be large enough to recieve the decoded string.
 * @param src A base64 encoded string.
 * @return the length of the decoded string if decode
 * succeeded otherwise 0.
 */
int oauth_decode_base64(unsigned char *dest, const char *src) {
  if(src && *src) {
    unsigned char *p= dest;
    int k, l= strlen(src)+1;
    unsigned char *buf= (unsigned char*) xcalloc(sizeof(unsigned char), l);

    /* Ignore non base64 chars as per the POSIX standard */
    for(k=0, l=0; src[k]; k++) {
      if(oauth_b64_is_base64(src[k])) {
        buf[l++]= src[k];
      }
    } 
    
    for(k=0; k<l; k+=4) {
      char c1='A', c2='A', c3='A', c4='A';
      unsigned char b1=0, b2=0, b3=0, b4=0;
      c1= buf[k];

      if(k+1<l) c2= buf[k+1];
      if(k+2<l) c3= buf[k+2];
      if(k+3<l) c4= buf[k+3];
      
      b1= oauth_b64_decode(c1);
      b2= oauth_b64_decode(c2);
      b3= oauth_b64_decode(c3);
      b4= oauth_b64_decode(c4);
      
      *p++=((b1<<2)|(b2>>4) );
      
      if(c3 != '=') *p++=(((b2&0xf)<<4)|(b3>>2) );
      if(c4 != '=') *p++=(((b3&0x3)<<6)|b4 );
    }
    free(buf);
    dest[p-dest]='\0';
    return(p-dest);
  }
  return 0;
}

/**
 * Escape 'string' according to RFC3986 and
 * http://oauth.net/core/1.0/#encoding_parameters
 *
 * @param string The data to be encoded
 * @return encoded string otherwise NULL
 * The caller must free the returned string.
 */
char *oauth_url_escape(const char *string) {
  if (!string) return xstrdup("");
  size_t alloc = strlen(string)+1;
  char *ns = NULL, *testing_ptr = NULL;
  unsigned char in; 
  size_t newlen = alloc;
  int strindex=0;
  size_t length;

  ns = (char*) xmalloc(alloc);

  length = alloc-1;
  while(length--) {
    in = *string;

    switch(in){
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o':
    case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F': case 'G': case 'H': case 'I': case 'J':
    case 'K': case 'L': case 'M': case 'N': case 'O':
    case 'P': case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case '_': case '~': case '.': case '-':
      ns[strindex++]=in;
      break;
    default:
      newlen += 2; /* this'll become a %XX */
      if(newlen > alloc) {
        alloc *= 2;
	testing_ptr = (char*) xrealloc(ns, alloc);
	ns = testing_ptr;
      }
      snprintf(&ns[strindex], 4, "%%%02X", in);
      strindex+=3;
      break;
    }
    string++;
  }
  ns[strindex]=0;
  return ns;
}

/**
 * returns base64 encoded HMAC-SHA1 signature for
 * given message and key.
 * both data and key need to be urlencoded.
 *
 * the returned string needs to be freed by the caller
 *
 * @param m message to be signed
 * @param k key used for signing
 * @return signature string.
 */
char *oauth_sign_hmac_sha1 (const char *m, const char *k) {
  return(oauth_sign_hmac_sha1_raw (m, strlen(m), k, strlen(k)));
}

char *oauth_sign_hmac_sha1_raw (const char *m, const size_t ml, const char *k, const size_t kl) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int resultlen = 0;
  
  HMAC(EVP_sha1(), k, kl, 
      (unsigned char*) m, ml,
      result, &resultlen);

  return(oauth_encode_base64(resultlen, result));
}

/**
 * returns plaintext signature for the given key.
 *
 * the returned string needs to be freed by the caller
 *
 * @param m message to be signed
 * @param k key used for signing
 * @return signature string
 */
char *oauth_sign_plaintext (const char *m, const char *k) {
  return(xstrdup(k));
}

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

/**
 * returns RSA-SHA1 signature for given data.
 * the returned signature needs to be freed by the caller.
 *
 * @param m message to be signed
 * @param k private-key PKCS and Base64-encoded 
 * @return base64 encoded signature string.
 */
char *oauth_sign_rsa_sha1 (const char *m, const char *k) {
  unsigned char *sig = NULL;
  unsigned char *passphrase = NULL;
  unsigned int len=0;
  EVP_MD_CTX md_ctx;

  EVP_PKEY *pkey;
  BIO *in;
  in = BIO_new_mem_buf((unsigned char*) k, strlen(k));
  pkey = PEM_read_bio_PrivateKey(in, NULL, 0, passphrase); // generate sign
  BIO_free(in);

  if (pkey == NULL) {
  //fprintf(stderr, "liboauth/ssl: can not read private key\n");
	  return xstrdup("liboauth/ssl: can not read private key");
  }

  len = EVP_PKEY_size(pkey);
  sig = xmalloc((len+1)*sizeof(char));

  EVP_SignInit(&md_ctx, EVP_sha1());
  EVP_SignUpdate(&md_ctx, m, strlen(m));
  if (EVP_SignFinal (&md_ctx, sig, &len, pkey)) {
	  char *tmp;
    sig[len] = '\0';
		tmp = oauth_encode_base64(len,sig);
		OPENSSL_free(sig);
	  EVP_PKEY_free(pkey);
		return tmp;
  }
  return xstrdup("liboauth/ssl: rsa-sha1 signing failed");
}

/**
 * verify RSA-SHA1 signature.
 *
 * returns the output of EVP_VerifyFinal() for a given message,
 * cert/pubkey and signature
 *
 * @param m message to be verified
 * @param c public-key or x509 certificate
 * @param s base64 encoded signature
 * @return 1 for a correct signature, 0 for failure and -1 if some other error occurred
 */
int oauth_verify_rsa_sha1 (const char *m, const char *c, const char *s) {
  EVP_MD_CTX md_ctx;
  EVP_PKEY *pkey;
  BIO *in;

  in = BIO_new_mem_buf((unsigned char*)c, strlen(c));
  X509 *cert = NULL;
  cert = PEM_read_bio_X509(in, NULL, 0, NULL);
	if (cert)  {
    pkey = (EVP_PKEY *) X509_get_pubkey(cert); 
		X509_free(cert);
	} else {
    pkey = PEM_read_bio_PUBKEY(in, NULL, 0, NULL);
	}
  BIO_free(in);
  if (pkey == NULL) {
  //fprintf(stderr, "could not read cert/pubkey.\n");
	  return -2;
  }

	unsigned char *b64d;
  b64d= (unsigned char*) xmalloc(sizeof(char)*strlen(s));
  int slen = oauth_decode_base64(b64d, s);

	EVP_VerifyInit(&md_ctx, EVP_sha1());
	EVP_VerifyUpdate(&md_ctx, m, strlen(m));
	int err = EVP_VerifyFinal(&md_ctx, b64d, slen, pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
	EVP_PKEY_free(pkey);
	free(b64d);
	return (err);
}

/**
 * encode strings and concatenate with '&' separator.
 * The number of strings to be concatenated must be
 * given as first argument.
 * all arguments thereafter must be of type (char *) 
 *
 * @param len the number of arguments to follow this parameter
 * @param ... string to escape and added
 *
 * @return pointer to memory holding the concatenated 
 * strings - needs to be free(d) by the caller. or NULL
 * in case we ran out of memory.
 */
char *oauth_catenc(int len, ...) {
  va_list va;
  char *rv = (char*) xmalloc(sizeof(char));
  *rv='\0';
  va_start(va, len);
  int i;
  for(i=0;i<len;i++) {
    char *arg = va_arg(va, char *);
    char *enc;
    int len;
    enc = oauth_url_escape(arg);
    if(!enc) break;
    len = strlen(enc) + 1 + ((i>0)?1:0);
    if(rv) len+=strlen(rv);
    rv=(char*) xrealloc(rv,len*sizeof(char));

    if(i>0) strcat(rv, "&");
    strcat(rv, enc);
    free(enc);
  }
  va_end(va);
  return(rv);
}

/**
 * splits the given url into a parameter array. 
 * (see \ref oauth_serialize_url and \ref oauth_serialize_url_parameters for the reverse)
 *
 * NOTE: Request-parameters-values may include an ampersand character.
 * However if unescaped this function will use them as parameter delimiter. 
 * If you need to make such a request, this function since version 0.3.5 allows
 * to use the ASCII SOH (0x01) character as alias for '&' (0x26).
 * (the motivation is convenience: SOH is /untypeable/ and much more 
 * unlikely to appear than '&' - If you plan to sign fancy URLs you 
 * should not split a query-string, but rather provide the parameter array
 * directly to \ref oauth_serialize_url)
 *
 * @param url the url or query-string to parse. 
 * @param argv pointer to a (char *) array where the results are stored.
 *  The array is re-allocated to match the number of parameters and each 
 *  parameter-string is allocated with strdup. - The memory needs to be freed
 *  by the caller.
 * @param qesc use query parameter escape (vs post-param-escape) - if set
 *        to 1 all '+' are treated as spaces ' '
 * 
 * @return number of parameter(s) in array.
 */
int oauth_split_post_paramters(const char *url, char ***argv, short qesc) {
  int argc=0;
  char *token, *tmp, *t1;
  if (!argv) return 0;
  if (!url) return 0;
  t1=xstrdup(url);

  // '+' represents a space, in a URL query string
  while ((qesc&1) && (tmp=strchr(t1,'+'))) *tmp=' ';

  tmp=t1;
  while((token=strtok(tmp,"&?"))) {
    if(!strncasecmp("oauth_signature=",token,16)) continue;
    (*argv)=(char**) xrealloc(*argv,sizeof(char*)*(argc+1));
    while (!(qesc&2) && (tmp=strchr(token,'\001'))) *tmp='&';
    (*argv)[argc]=xstrdup(token);
	  if (argc==0 && strstr(token, ":/")) {
			// HTTP does not allow empty absolute paths, so the URL 
			// 'http://example.com' is equivalent to 'http://example.com/' and should
			// be treated as such for the purposes of OAuth signing (rfc2616, section 3.2.1)
			// see http://groups.google.com/group/oauth/browse_thread/thread/c44b6f061bfd98c?hl=en
			char *slash=strstr(token, ":/");
			while (slash && *(++slash) == '/')  ; // skip slashes eg /xxx:[\/]*/
#if 0
			// skip possibly unescaped slashes in the userinfo - they're not allowed by RFC2396 but have been seen.
			// the hostname/IP may only contain alphanumeric characters - so we're safe there.
			if (slash && strchr(slash,'@')) slash=strchr(slash,'@'); 
#endif
			if (slash && !strchr(slash,'/')) {
#ifdef DEBUG_OAUTH
			  fprintf(stderr, "\nliboauth: added trailing slash to URL: '%s'\n\n", token);
#endif
				free((*argv)[argc]);
				(*argv)[argc]= (char*) xmalloc(sizeof(char)*(2+strlen(token))); 
				strcpy((*argv)[argc],token);
				strcat((*argv)[argc],"/");
		  }
		}
	  if (argc==0 && (tmp=strstr((*argv)[argc],":80/"))) {
			  memmove(tmp, tmp+3, strlen(tmp+2));
		}
    tmp=NULL;
    argc++;
  }

  free(t1);
  return argc;
}

int oauth_split_url_parameters(const char *url, char ***argv) {
  return oauth_split_post_paramters(url, argv, 1);
}

/**
 * build a url query sting from an array.
 *
 * @param argc the total number of elements in the array
 * @param start element in the array at which to start concatenating.
 * @param argv parameter-array to concatenate.
 * @return url string needs to be freed by the caller.
 *
 */
char *oauth_serialize_url (int argc, int start, char **argv) {
  char  *tmp, *t1;
  int i;
  int	first=0;
  char *query = (char*) xmalloc(sizeof(char)); 
  *query='\0';
  for(i=start; i< argc; i++) {
    int len = 0;
    if (query) len+=strlen(query);

		if (i==start && i==0 && strstr(argv[i], ":/")) {
      tmp=xstrdup(argv[i]);
      len+=strlen(tmp)+2;
		} else if(!(t1=strchr(argv[i], '='))) {
    // see http://oauth.net/core/1.0/#anchor14
    // escape parameter names and arguments but not the '='
      tmp=xstrdup(argv[i]);
      tmp=(char*) xrealloc(tmp,(strlen(tmp)+2)*sizeof(char));
      strcat(tmp,"=");
      len+=strlen(tmp)+2;
    } else {
      *t1=0;
      tmp = oauth_url_escape(argv[i]);
      *t1='=';
      t1 = oauth_url_escape((t1+1));
      tmp=(char*) xrealloc(tmp,(strlen(tmp)+strlen(t1)+2)*sizeof(char));
      strcat(tmp,"=");
      strcat(tmp,t1);
      free(t1);
      len+=strlen(tmp)+2;
    }
    query=(char*) xrealloc(query,len*sizeof(char));
    strcat(query, ((i==start||first)?"":"&"));
		first=0;
    strcat(query, tmp);
		if (i==start && i==0 && strstr(tmp, ":/")) {
			strcat(query, "?");
			first=1;
		}
    free(tmp);
  }
  return (query);
}

/**
 * build a query parameter string from an array.
 *
 * This function is a shortcut for \ref oauth_serialize_url (argc, 1, argv). 
 * It strips the leading host/path, which is usually the first 
 * element when using oauth_split_url_parameters on an URL.
 *
 * @param argc the total number of elements in the array
 * @param argv parameter-array to concatenate.
 * @return url string needs to be freed by the caller.
 */
char *oauth_serialize_url_parameters (int argc, char **argv) {
  return oauth_serialize_url(argc, 1, argv);
}

/**
 * generate a random string between 15 and 32 chars length
 * and return a pointer to it. The value needs to be freed by the
 * caller
 *
 * @return zero terminated random string.
 */
char *oauth_gen_nonce() {
  char *nc;
  static int rndinit = 1;
  const char *chars = "abcdefghijklmnopqrstuvwxyz"
  	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789_";
  unsigned int max = strlen( chars );
  int i, len;

  if(rndinit) {srand(time(NULL) 
#ifndef WIN // quick windows check.
  	* getpid()
#endif
	); rndinit=0;} // seed random number generator - FIXME: we can do better ;)

  len=15+floor(rand()*16.0/(double)RAND_MAX);
  nc = (char*) xmalloc((len+1)*sizeof(char));
  for(i=0;i<len; i++) {
    nc[i] = chars[ rand() % max ];
  }
  nc[i]='\0';
  return (nc);
}

/**
 * string compare function for oauth parameters.
 *
 * used with qsort. needed to normalize request parameters.
 * see http://oauth.net/core/1.0/#anchor14
 */
int oauth_cmpstringp(const void *p1, const void *p2) {
  char *v1,*v2;
  char *t1,*t2;
  int rv;
  // TODO: this is not fast - we should escape the 
  // array elements (once) before sorting.
  v1=oauth_url_escape(* (char * const *)p1);
  v2=oauth_url_escape(* (char * const *)p2);

  // '=' signs are not "%3D" !
  if ((t1=strstr(v1,"%3D"))) {
    t1[0]='\0'; t1[1]='='; t1[2]='=';
  }
  if ((t2=strstr(v2,"%3D"))) {
    t2[0]='\0'; t2[1]='='; t2[2]='=';
  }

  // compare parameter names
  rv=strcmp(v1,v2);
  if (rv!=0) {
    if (v1) free(v1);
    if (v2) free(v2);
    return rv;
  }

  // if parameter names are equal, sort by value.
  if (t1) t1[0]='='; 
  if (t2) t2[0]='='; 
  rv=strcmp(t1,t2);
  if (v1) free(v1);
  if (v2) free(v2);
  return rv;
}

/**
 * search array for parameter.
 */
int oauth_param_exists(char **argv, int argc, char *param) {
	int i;
	size_t l= strlen(param);
	for (i=0;i<argc;i++)
		if (strlen(argv[i])>l && !strncmp(argv[i],param,l) && argv[i][l] == '=') return 1;
	return 0;
}

/**
 * calculate oAuth-signature for a given request URL, parameters and oauth-tokens.
 *
 * if 'postargs' is NULL a "GET" request is signed and the 
 * signed URL is returned. Else this fn will modify 'postargs' 
 * to point to memory that contains the signed POST-variables 
 * and returns the base URL.
 *
 * both, the return value and (if given) 'postargs' need to be freed
 * by the caller.
 *
 * @param url The request URL to be signed. append all GET or POST 
 * query-parameters separated by either '?' or '&' to this parameter.
 *
 * @param postargs This parameter points to an area where the return value
 * is stored. If 'postargs' is NULL, no value is stored.
 *
 * @param method specify the signature method to use. It is of type 
 * \ref OAuthMethod and most likely \ref OA_HMAC.
 *
 * @param c_key consumer key
 * @param c_secret consumer secret
 * @param t_key token key
 * @param t_secret token secret
 *
 * @return the signed url or NULL if an error occurred.
 *
 */
char *oauth_sign_url (const char *url, char **postargs, 
  OAuthMethod method, 
  const char *c_key, //< consumer key - posted plain text
  const char *c_secret, //< consumer secret - used as 1st part of secret-key 
  const char *t_key, //< token key - posted plain text in URL
  const char *t_secret //< token secret - used as 2st part of secret-key
  ) {

  // split url arguments
  int  argc;
  char **argv = NULL;
  char *tmp;

  if (postargs)
    argc = oauth_split_post_paramters(url, &argv, 0);
  else
    argc = oauth_split_url_parameters(url, &argv);

#define ADD_TO_ARGV \
  argv=(char**) xrealloc(argv,sizeof(char*)*(argc+1)); \
  argv[argc++]=xstrdup(oarg); 
  // add oAuth specific arguments
  char oarg[1024];
	if (!oauth_param_exists(argv,argc,"oauth_nonce")) {
		snprintf(oarg, 1024, "oauth_nonce=%s", (tmp=oauth_gen_nonce()));
		ADD_TO_ARGV;
		free(tmp);
	}

	if (!oauth_param_exists(argv,argc,"oauth_timestamp")) {
		snprintf(oarg, 1024, "oauth_timestamp=%li", time(NULL));
		ADD_TO_ARGV;
	}

  if (t_key) {
    snprintf(oarg, 1024, "oauth_token=%s", t_key);
    ADD_TO_ARGV;
  }

  snprintf(oarg, 1024, "oauth_consumer_key=%s", c_key);
  ADD_TO_ARGV;

  snprintf(oarg, 1024, "oauth_signature_method=%s",
      method==0?"HMAC-SHA1":method==1?"RSA-SHA1":"PLAINTEXT");
  ADD_TO_ARGV;

	if (!oauth_param_exists(argv,argc,"oauth_version")) {
		snprintf(oarg, 1024, "oauth_version=1.0");
		ADD_TO_ARGV;
	}

  // sort parameters
  qsort(&argv[1], argc-1, sizeof(char *), oauth_cmpstringp);

  // serialize URL
  char *query= oauth_serialize_url_parameters(argc, argv);

  // generate signature
  char *okey, *odat, *sign;
  okey = oauth_catenc(2, c_secret, t_secret);
  odat = oauth_catenc(3, postargs?"POST":"GET", argv[0], query);
#ifdef DEBUG_OAUTH
  fprintf (stderr, "\nliboauth: data to sign='%s'\n\n", odat);
  fprintf (stderr, "\nliboauth: key='%s'\n\n", okey);
#endif
  switch(method) {
    case OA_RSA:
      sign = oauth_sign_rsa_sha1(odat,okey);
    	break;
    case OA_PLAINTEXT:
      sign = oauth_sign_plaintext(odat,okey);
    	break;
    default:
      sign = oauth_sign_hmac_sha1(odat,okey);
  }
#ifdef WIPE_MEMORY
	memset(okey,0, strlen(okey));
	memset(odat,0, strlen(odat));
#endif
  free(odat); 
  free(okey);

  // append signature to query args.
  snprintf(oarg, 1024, "oauth_signature=%s",sign);
  ADD_TO_ARGV;
  free(sign);

  // build URL params
  char *result = oauth_serialize_url(argc, (postargs?1:0), argv);

  if(postargs) { 
    *postargs = result;
    result = xstrdup(argv[0]);
    free(argv[0]);
  }
  if(argv) free(argv);
  if(query) free(query);

  return result;
}
// vi: sts=2 sw=2 ts=2
