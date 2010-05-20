/*
 * hash algorithms used in oAuth 
 *
 * Copyright 2007-2010 Robin Gareus <robin@gareus.org>
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

#ifdef USE_GPL
/*
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xmalloc.h"
#include "oauth.h" // base64 encode fn's.
#include <openssl/hmac.h>

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

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

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
  sig = (unsigned char*)xmalloc((len+1)*sizeof(char));

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

int oauth_verify_rsa_sha1 (const char *m, const char *c, const char *s) {
  EVP_MD_CTX md_ctx;
  EVP_PKEY *pkey;
  BIO *in;
  X509 *cert = NULL;
  unsigned char *b64d;
  int slen, err;

  in = BIO_new_mem_buf((unsigned char*)c, strlen(c));
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

  b64d= (unsigned char*) xmalloc(sizeof(char)*strlen(s));
  slen = oauth_decode_base64(b64d, s);

  EVP_VerifyInit(&md_ctx, EVP_sha1());
  EVP_VerifyUpdate(&md_ctx, m, strlen(m));
  err = EVP_VerifyFinal(&md_ctx, b64d, slen, pkey);
  EVP_MD_CTX_cleanup(&md_ctx);
  EVP_PKEY_free(pkey);
  free(b64d);
  return (err);
}


/** 
 * http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
 */
char *oauth_body_hash_file(char *filename) {
  unsigned char fb[BUFSIZ];
  EVP_MD_CTX ctx;
  size_t len=0;
  unsigned char *md;
  FILE *F= fopen(filename, "r");
  if (!F) return NULL;

  EVP_MD_CTX_init(&ctx);
  EVP_DigestInit(&ctx,EVP_sha1());
  while (!feof(F) && (len=fread(fb,sizeof(char),BUFSIZ, F))>0) {
    EVP_DigestUpdate(&ctx, fb, len);
  }
  fclose(F);
  len=0;
  md=(unsigned char*) calloc(EVP_MD_size(EVP_sha1()),sizeof(unsigned char));
  EVP_DigestFinal(&ctx, md,(unsigned int*) &len);
  EVP_MD_CTX_cleanup(&ctx);
  return oauth_body_hash_encode(len, md);
}

char *oauth_body_hash_data(size_t length, const char *data) {
  EVP_MD_CTX ctx;
  size_t len=0;
  unsigned char *md;
  md=(unsigned char*) calloc(EVP_MD_size(EVP_sha1()),sizeof(unsigned char));
  EVP_MD_CTX_init(&ctx);
  EVP_DigestInit(&ctx,EVP_sha1());
  EVP_DigestUpdate(&ctx, data, length);
  EVP_DigestFinal(&ctx, md,(unsigned int*) &len);
  EVP_MD_CTX_cleanup(&ctx);
  return oauth_body_hash_encode(len, md);
}

// vi: sts=2 sw=2 ts=2
