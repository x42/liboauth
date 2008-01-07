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
 * compile:
 *   gcc -o oauth-c oauth.c -lssl -lm -DMAIN
 * this compiles the example main() function which runs a signature self-test.
 *
 * using oauth_sign_url(..) in C or C++ is straight forward. see main() for an
 * examples of signing POST and GET requests.
 *
 */
/* vi: sts=2 sw=2 ts=2 */

/** \enum OAuthMethod
 * signature method to used for signing the request.
 */ 
typedef enum { 
	OA_HMAC=0, ///< use HMAC-SHA1 request signing method
	OA_RSA, ///< use RSA signature (not implemented)
	OA_PLAINTEXT ///< use plain text signature (for testing only)
	} OAuthMethod;

/**
 * Base64 encode one byte
 */
char oauth_b64_encode(unsigned char u);

/**
 * Decode a single base64 character.
 */
unsigned char oauth_b64_decode(char c);

/**
 * Return TRUE if 'c' is a valid base64 character, otherwise FALSE
 */
int oauth_b64_is_base64(char c);

/**
 * Base64 encode and return size data in 'src'. The caller must free the
 * returned string.
 *
 * @param size The size of the data in src
 * @param src The data to be base64 encode
 * @return encoded string otherwise NULL
 */
char *oauth_encode_base64(int size, unsigned char *src);

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
int oauth_decode_base64(unsigned char *dest, const char *src);

/**
 * Escape 'string' according to RFC3986 and
 * http://oauth.googlecode.com/svn/spec/branches/1.0/drafts/7/spec.html#encoding_parameters
 *
 * @param string The data to be encoded
 * @return encoded string otherwise NULL
 * The caller must free the returned string.
 */
char *url_escape(const char *string);

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
char *oauth_sign_hmac_sha1 (char *m, char *k);

/**
 * returns plaintext signature for the given key.
 *
 * the returned string needs to be freed by the caller
 *
 * @param m message to be signed
 * @param k key used for signing
 * @return signature string
 */
char *oauth_sign_plaintext (char *m, char *k);

/**
 * returns RSA signature for given data.
 * data needs to be urlencoded.
 *
 * THIS FUNCTION IS NOT YET IMPLEMENTED!
 *
 * the returned string needs to be freed by the caller.
 *
 * @param m message to be signed
 * @param k key used for signing
 * @return signature string.
 */
char *oauth_sign_rsa_sha1 (char *m, char *k);

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
char *catenc(int len, ...);

/**
 * generate a random string between 15 and 32 chars length
 * and return a pointer to it. The value needs to be freed by the
 * caller
 *
 * @return zero terminated random string.
 */
char *gen_nonce();

/**
 * sign an oAuth request URL.
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
  );

/**
 * string compare function for oauth parameters.
 *
 * used with qsort. needed to normalize request parameters:
 * http://oauth.net/core/1.0/#anchor14
 */
int oauth_cmpstringp(const void *p1, const void *p2);
 
