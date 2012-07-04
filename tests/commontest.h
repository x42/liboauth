int test_encoding(char *param, char *expected);
#ifdef TEST_UNICODE
int test_uniencoding(wchar_t *src, char *expected);
#endif
int test_normalize(char *param, char *expected);
int test_request(char *http_method, char *request, char *expected);
int test_sha1(char *c_secret, char *t_secret, char *base, char *expected);
int test_sign_get(char const * const url, OAuthMethod method, const char *c_key, const char *c_secret, const char *t_key, const char *t_secret, const char *expected);
