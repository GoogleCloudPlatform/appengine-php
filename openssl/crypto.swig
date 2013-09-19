// Copyright 2008 Google Inc.
// Author: ushankar@google.com (Umesh Shankar)

// Java applications using SWIG-wrapped OpenSSL should first call
// GoogleInit.initialize to invoke OpenSSL initialization.

%include base/google.swig
%include cpointer.i
%pointer_functions(int, intp)

%{
#include "openssl/aes.h"
#include "openssl/cast.h"
// EVP_CIPHER_CTX_ST includes a member called final:
// rename to avoid conflict in Java.
#define final final_
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#ifdef  __cplusplus
extern "C" {
#endif

//
// AES support
//

void AES_cbc_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                        size_t length, const AES_KEY *key,
                                        unsigned char *ivec, const int enc) {
  AES_cbc_encrypt(in_out + offset, in_out + offset, length, key, ivec, enc);
}

void AES_ctr128_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                           size_t length, const AES_KEY *key,
                                           unsigned char *ivec,
                                           unsigned char *ecount_buf) {
  unsigned int num = 0;
  AES_ctr128_encrypt(in_out + offset, in_out + offset, length, key, ivec,
                     ecount_buf, &num);
}

//
// CAST support
//

void CAST_cbc_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                         size_t length, const CAST_KEY *key,
                                         unsigned char *ivec, const int enc) {
  CAST_cbc_encrypt(in_out + offset, in_out + offset, length, key, ivec, enc);
}

void CAST_cfb64_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                           size_t length, const CAST_KEY *key,
                                           unsigned char *ivec, const int enc) {
  int num = 0;
  CAST_cfb64_encrypt(in_out + offset, in_out + offset, length, key, ivec,
                     &num, enc);
}

//
// EVP support
//

int EVP_CipherInit_ex_helper(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                             const unsigned char *key, int enc) {
  return EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL, enc);
}

int EVP_CipherUpdate_helper_same_buffer(EVP_CIPHER_CTX *ctx,
                                        unsigned char *in_out, size_t offset,
                                        size_t length, int *outl) {
  return EVP_CipherUpdate(ctx, in_out + offset, outl, in_out + offset, length);
}

int EVP_CipherFinal_ex_helper(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              size_t offset, int *outl) {
  return EVP_CipherFinal_ex(ctx, out + offset, outl);
}

// Can be used only with CBC mode.
int EVP_SetIv_helper(EVP_CIPHER_CTX *ctx, const unsigned char *iv) {
  return EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1);
}

//
// SHA support
//

SHA_CTX *SHA_CTX_new() {
  return (SHA_CTX *) malloc(sizeof(SHA_CTX));
}

void SHA_CTX_free(SHA_CTX *c) {
  free(c);
}

// Helpers to handle offsets and lengths for Java functions.
int SHA1_Update_helper(SHA_CTX *c, const void *data, size_t offset,
                       size_t length) {
  return SHA1_Update(c, ((unsigned char *) data)+offset, length);
}

void SHA1_helper(const unsigned char *d, size_t offset, size_t length,
                 unsigned char *md) {
  SHA1(d+offset, length, md);
}

SHA256_CTX *SHA256_CTX_new() {
  return (SHA256_CTX *) malloc(sizeof(SHA256_CTX));
}

void SHA256_CTX_free(SHA256_CTX *c) {
  free(c);
}

int SHA224_Update_helper(SHA256_CTX *c, const void *data, size_t offset,
                         size_t length) {
  return SHA224_Update(c, ((unsigned char *) data)+offset, length);
}

void SHA224_helper(const unsigned char *d, size_t offset, size_t length,
                   unsigned char *md) {
  SHA224(d+offset, length, md);
}

int SHA256_Update_helper(SHA256_CTX *c, const void *data, size_t offset,
                         size_t length) {
  return SHA256_Update(c, ((unsigned char *) data)+offset, length);
}

void SHA256_helper(const unsigned char *d, size_t offset, size_t length,
                   unsigned char *md) {
  SHA256(d+offset, length, md);
}


//
// HMAC support
//

int HMAC_SHA1(const unsigned char *key, int key_len,
              const unsigned char *data, size_t data_size, unsigned char *sig) {
  unsigned int sig_len = 0;
  HMAC(EVP_sha1(), key, key_len, data, data_size, sig, &sig_len);
  return (sig_len == SHA_DIGEST_LENGTH);
}

int HMAC_SHA1_helper(const unsigned char *key, int key_len,
                     const unsigned char *data, size_t offset, size_t data_size,
                     unsigned char *sig) {
  return HMAC_SHA1(key, key_len, data + offset, data_size, sig);
}

int HMAC_SHA256(const unsigned char *key, int key_len,
                const unsigned char *data, size_t data_size,
                unsigned char *sig) {
  unsigned int sig_len = 0;
  HMAC(EVP_sha256(), key, key_len, data, data_size, sig, &sig_len);
  return (sig_len == SHA256_DIGEST_LENGTH);
}

int HMAC_SHA256_helper(const unsigned char *key, int key_len,
                       const unsigned char *data, size_t offset,
                       size_t data_size, unsigned char *sig) {
  return HMAC_SHA256(key, key_len, data + offset, data_size, sig);
}

int HMAC_SHA512(const unsigned char *key, int key_len,
                const unsigned char *data, size_t data_size,
                unsigned char *sig) {
  unsigned int sig_len = 0;
  HMAC(EVP_sha512(), key, key_len, data, data_size, sig, &sig_len);
  return (sig_len == SHA512_DIGEST_LENGTH);
}

int HMAC_SHA512_helper(const unsigned char *key, int key_len,
                       const unsigned char *data, size_t offset,
                       size_t data_size, unsigned char *sig) {
  return HMAC_SHA512(key, key_len, data + offset, data_size, sig);
}

//
// RSA support
//

RSA *RSA_new_from_parts(const unsigned char *n, int n_len,
                        const unsigned char *e, int e_len,
                        const unsigned char *d, int d_len,
                        const unsigned char *p, int p_len,
                        const unsigned char *q, int q_len,
                        const unsigned char *dmp1, int dmp1_len,
                        const unsigned char *dmq1, int dmq1_len,
                        const unsigned char *iqmp, int iqmp_len) {
  RSA *rsa = RSA_new();
  if (rsa == NULL) goto err;

  if (n_len > 0 &&
      (rsa->n = BN_bin2bn(n, n_len, NULL)) == NULL) goto err;
  if (e_len > 0 &&
      (rsa->e = BN_bin2bn(e, e_len, NULL)) == NULL) goto err;
  if (d_len > 0 &&
      (rsa->d = BN_bin2bn(d, d_len, NULL)) == NULL) goto err;
  if (p_len > 0 &&
      (rsa->p = BN_bin2bn(p, p_len, NULL)) == NULL) goto err;
  if (q_len > 0 &&
      (rsa->q = BN_bin2bn(q, q_len, NULL)) == NULL) goto err;
  if (dmp1_len > 0 &&
      (rsa->dmp1 = BN_bin2bn(dmp1, dmp1_len, NULL)) == NULL) goto err;
  if (dmq1_len > 0 &&
      (rsa->dmq1 = BN_bin2bn(dmq1, dmq1_len, NULL)) == NULL) goto err;
  if (iqmp_len > 0 &&
      (rsa->iqmp = BN_bin2bn(iqmp, iqmp_len, NULL)) == NULL) goto err;
  return rsa;

err:
  if (rsa) {
    RSA_free(rsa);
  }
  return NULL;
}

// Helper for RSA_generate_key_ex to avoid having to SWIG wrap BIGNUMs.
int RSA_generate_key_ex_helper(RSA *rsa, int bits, unsigned long e) {
  BIGNUM bn_e;
  BN_init(&bn_e);
  BN_set_word(&bn_e, e);
  return RSA_generate_key_ex(rsa, bits, &bn_e, NULL);
}

typedef struct {
  unsigned char *data;
  unsigned int len;
} BYTE_ARRAY_RESULT;

// Helpers to make calling RSA_sign easier.
BYTE_ARRAY_RESULT RSA_sign_helper(int type, const unsigned char *m, unsigned int m_length,
        RSA *rsa) {
  unsigned int siglen = RSA_size(rsa);
  unsigned char *sigret = (unsigned char *) malloc(siglen);
  BYTE_ARRAY_RESULT result;
  if (sigret == NULL) goto err;

  if (RSA_sign(type, m, m_length, sigret, &siglen, rsa) != 1) {
    goto err;
  }

  result.data = sigret;
  result.len = siglen;
  return result;

err:
  if (sigret)
    free(sigret);
  result.data = NULL;
  result.len = 0;
  return result;
}

BYTE_ARRAY_RESULT bn_to_byte_array_result(BIGNUM *bn) {
  BYTE_ARRAY_RESULT result;
  int len = BN_num_bytes(bn);
  int copied_len = 0;
  unsigned char *bn_bin = (unsigned char *) malloc(len);
  if (!bn_bin) {
    goto err;
  }

  copied_len = BN_bn2bin(bn, bn_bin);

  if (copied_len != len) {
    goto err;
  }

  result.data = bn_bin;
  result.len = len;
  return result;

err:
  if (bn_bin)
    free(bn_bin);
  result.data = NULL;
  result.len = 0;
  return result;
}

BYTE_ARRAY_RESULT RSA_get_modulus(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->n);
}

BYTE_ARRAY_RESULT RSA_get_public_exponent(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->e);
}

BYTE_ARRAY_RESULT RSA_get_private_exponent(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->d);
}

BYTE_ARRAY_RESULT RSA_get_p(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->p);
}

BYTE_ARRAY_RESULT RSA_get_q(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->q);
}

BYTE_ARRAY_RESULT RSA_get_dmp1(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->dmp1);
}

BYTE_ARRAY_RESULT RSA_get_dmq1(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->dmq1);
}

BYTE_ARRAY_RESULT RSA_get_iqmp(const RSA *rsa) {
  return bn_to_byte_array_result(rsa->iqmp);
}

#ifdef  __cplusplus
}
#endif
%}

%typemap(jni) unsigned char* "jbyteArray"
%typemap(jtype) unsigned char* "byte[]"
%typemap(jstype) unsigned char* "byte[]"
%typemap(javain) unsigned char* "$javainput"

%typemap(jni) const unsigned char*, const void* "jbyteArray"
%typemap(jtype) const unsigned char*, const void* "byte[]"
%typemap(jstype) const unsigned char*, const void* "byte[]"
%typemap(javain) const unsigned char*, const void* "$javainput"

%typemap(in) unsigned char * {
  $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) unsigned char * {
  JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(in) const unsigned char *, const void * {
  $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) const unsigned char *, const void * {
  JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char* ""
%typemap(freearg) const unsigned char*, const void* ""


/* Create a type that lets us easily wrap functions that need to return a byte
 * array. To use this, return a BYTE_ARRAY_RESULT ba where ba.data is memory
 * allocated with malloc and ba.len is the length of the allocated array. The
 * "out" typemap below will convert this to a java byte[] and free your
 * allocated memory.
 */
%typemap(jni) BYTE_ARRAY_RESULT "jbyteArray"
%typemap(jtype) BYTE_ARRAY_RESULT "byte[]"
%typemap(jstype) BYTE_ARRAY_RESULT "byte[]"
%typemap(javaout) BYTE_ARRAY_RESULT {
  return $jnicall;
}

%typemap(out) BYTE_ARRAY_RESULT {
  if ($1.data == NULL) {
    $result = NULL;
  } else {
    $result = JCALL1(NewByteArray, jenv, $1.len);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, $1.len, (jbyte *) $1.data);
    free($1.data);
  }
}


%module Aes

#ifndef HEADER_AES_H
#define HEADER_AES_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_AES
#error AES is disabled.
#endif

#define AES_ENCRYPT    1
#define AES_DECRYPT    0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

const char *AES_options(void);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     const unsigned long length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);

// The function wraps AES_cbc_encrypt to let Java users use the same array
// as input (plain text) and output (cipher text). Passing one array through JNI
// is cheaper than passing two.
void AES_cbc_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                        size_t length, const AES_KEY *key,
                                        unsigned char *ivec, const int enc);

// The function wraps AES_ctr128_encrypt to let Java users use the same array
// as input (plain text) and output (cipher text). Passing one array through JNI
// is cheaper than passing two.
void AES_ctr128_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                           size_t length, const AES_KEY *key,
                                           unsigned char *ivec,
                                           unsigned char *ecount_buf);

void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        const unsigned long length, const AES_KEY *key,
                        unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      const unsigned long length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      const unsigned long length, const AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        const unsigned long length, const AES_KEY *key,
                        unsigned char *ivec, int *num);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                        const unsigned long length, const AES_KEY *key,
                        unsigned char ivec[AES_BLOCK_SIZE],
                        unsigned char ecount_buf[AES_BLOCK_SIZE],
                        unsigned int *num);

/* For IGE, see also http://www.links.org/files/openssl-ige.pdf */
/* NB: the IV is _two_ blocks long */
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     const unsigned long length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        const unsigned long length, const AES_KEY *key,
                        const AES_KEY *key2, const unsigned char *ivec,
                        const int enc);


#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_AES_H */


%module Cast

#ifndef HEADER_CAST_H
#define HEADER_CAST_H

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_CAST
#error CAST is disabled.
#endif

#define CAST_ENCRYPT    1
#define CAST_DECRYPT    0

#define CAST_LONG unsigned long

#define CAST_BLOCK_SIZE    8
#define CAST_KEY_LENGTH    16

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct cast_key_st
    {
    CAST_LONG data[32];
    int short_key;    /* Use reduced rounds for short key */
    };

typedef struct cast_key_st CAST_KEY;

// TODO(bleichen): At some point the headers in OpenSSL will be changed
//   and the CAST_KEYs will be declared const. Then we should change the
//   headers here too. Otherwise JNI, will transport the keys forth and back.
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_ecb_encrypt(const unsigned char *in,unsigned char *out,CAST_KEY *key,
              int enc);
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
              CAST_KEY *ks, unsigned char *iv, int enc);
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, CAST_KEY *schedule, unsigned char *ivec,
                        int *num, int enc);
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, CAST_KEY *schedule, unsigned char *ivec,
                        int *num);

// The function wraps CAST_cbc_encrypt to let Java users use the same array
// as input (plain text) and output (cipher text). Passing one array through JNI
// is cheaper than passing two.
void CAST_cbc_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                         size_t length, const CAST_KEY *key,
                                         unsigned char *ivec, const int enc);

void CAST_cfb64_encrypt_helper_same_buffer(unsigned char *in_out, size_t offset,
                                           size_t length, const CAST_KEY *key,
                                           unsigned char *ivec, const int enc);

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_CAST_H */


%module sha

#ifndef HEADER_SHA_H
#define HEADER_SHA_H

#ifdef  __cplusplus
extern "C" {
#endif

#if defined(OPENSSL_NO_SHA) || (defined(OPENSSL_NO_SHA0) && defined(OPENSSL_NO_SHA1))
#error SHA is disabled.
#endif

#define SHA_DIGEST_LENGTH 20

#ifndef OPENSSL_NO_SHA1
SHA_CTX *SHA_CTX_new();
void SHA_CTX_free(SHA_CTX *c);

int SHA1_Init(SHA_CTX *c);
int SHA1_Update_helper(SHA_CTX *c, const void *data, size_t offset,
                       size_t length);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
void SHA1_helper(const unsigned char *d, size_t offset, size_t length,
                 unsigned char *md);
#endif

#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32

#ifndef OPENSSL_NO_SHA256
SHA256_CTX *SHA256_CTX_new();
void SHA256_CTX_free(SHA256_CTX *c);

int SHA224_Init(SHA256_CTX *c);
int SHA224_Update_helper(SHA256_CTX *c, const void *data, size_t offset,
                         size_t length);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
void SHA224_helper(const unsigned char *d, size_t offset, size_t length,
                   unsigned char *md);

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update_helper(SHA256_CTX *c, const void *data, size_t offset,
                         size_t length);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
void SHA256_helper(const unsigned char *d, size_t offset, size_t length,
                   unsigned char *md);
#endif

#ifdef  __cplusplus
}
#endif

#endif


%module hmac

#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_HMAC
#error HMAC is disabled.
#endif

#include <openssl/evp.h>

#define HMAC_MAX_MD_CBLOCK    128    /* largest known is SHA512 */

#ifdef  __cplusplus
extern "C" {
#endif

// Returns 0 if the digest length was not the expected 20 bytes,
// 1 otherwise
int HMAC_SHA1(const unsigned char *key, int key_len,
              const unsigned char *data, size_t data_size, unsigned char *sig);

// The function wraps HMAC_SHA1 function to let Java users specify offset
// for the data array.
int HMAC_SHA1_helper(const unsigned char *key, int key_len,
              const unsigned char *data, size_t offset, size_t data_size,
              unsigned char *sig);

// Returns 0 if the digest length was not the expected 32 bytes,
// 1 otherwise
int HMAC_SHA256(const unsigned char *key, int key_len,
                const unsigned char *data, size_t data_size,
                unsigned char *sig);

// The function wraps HMAC_SHA256 function to let Java users specify offset
// for the data array.
int HMAC_SHA256_helper(const unsigned char *key, int key_len,
                      const unsigned char *data, size_t offset,
                      size_t data_size, unsigned char *sig);

// Returns 0 if the digest length was not the expected 64 bytes,
// 1 otherwise
int HMAC_SHA512(const unsigned char *key, int key_len,
                const unsigned char *data, size_t data_size,
                unsigned char *sig);

// The function wraps HMAC_SHA512 function to let Java users specify offset
// for the data array.
int HMAC_SHA512_helper(const unsigned char *key, int key_len,
                      const unsigned char *data, size_t offset,
                      size_t data_size, unsigned char *sig);

#ifdef  __cplusplus
}
#endif

#endif


%module rsa

#define NID_sha1   64
#define NID_sha224 675
#define NID_sha256 672

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#ifdef OPENSSL_NO_RSA
#error RSA is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

RSA *RSA_new_from_parts(const unsigned char *n, int n_len,
                        const unsigned char *e, int e_len,
                        const unsigned char *d, int d_len,
                        const unsigned char *p, int p_len,
                        const unsigned char *q, int q_len,
                        const unsigned char *dmp1, int dmp1_len,
                        const unsigned char *dmq1, int dmq1_len,
                        const unsigned char *iqmp, int iqmp_len);

int RSA_generate_key_ex_helper(RSA *rsa, int bits, unsigned long e);

BYTE_ARRAY_RESULT RSA_sign_helper(int type, const unsigned char *m,
    unsigned int m_length, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
        const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

RSA *   RSA_new(void);
void    RSA_free (RSA *r);

int     RSA_check_key(const RSA *);

int     RSA_size(const RSA *);

BYTE_ARRAY_RESULT RSA_get_modulus(const RSA *);

BYTE_ARRAY_RESULT RSA_get_public_exponent(const RSA *);

BYTE_ARRAY_RESULT RSA_get_private_exponent(const RSA *);

BYTE_ARRAY_RESULT RSA_get_p(const RSA *);

BYTE_ARRAY_RESULT RSA_get_q(const RSA *);

BYTE_ARRAY_RESULT RSA_get_dmp1(const RSA *);

BYTE_ARRAY_RESULT RSA_get_dmq1(const RSA *);

BYTE_ARRAY_RESULT RSA_get_iqmp(const RSA *);

#ifdef  __cplusplus
}
#endif
#endif


%module evp

#ifndef HEADER_ENVELOPE_H
#define HEADER_ENVELOPE_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct evp_cipher_ctx_st
    {
    const EVP_CIPHER *cipher;
    ENGINE *engine; /* functional reference if 'cipher' is ENGINE-provided */
    int encrypt;            /* encrypt or decrypt */
    int buf_len;            /* number we have left */

    unsigned char  oiv[EVP_MAX_IV_LENGTH];  /* original iv */
    unsigned char  iv[EVP_MAX_IV_LENGTH];   /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];/* saved partial block */
    int num;                                /* used by cfb/ofb/ctr mode */

    void *app_data;         /* application stuff */
    int key_len;            /* May change for variable length cipher */
    unsigned long flags;    /* Various flags */
    void *cipher_data; /* per EVP data */
    int final_used;
    int block_mask;
    /* renamed in SWIG to avoid conflict in Java */
    unsigned char final_[EVP_MAX_BLOCK_LENGTH];/* possible final block */
    } EVP_CIPHER_CTX;

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

int EVP_CipherInit_ex_helper(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                             const unsigned char *key, int enc);
int EVP_CipherUpdate_helper_same_buffer(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                        size_t offset, size_t length,
                                        int *outl);
int EVP_CipherFinal_ex_helper(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              size_t offset, int *outl);
int EVP_SetIv_helper(EVP_CIPHER_CTX *ctx, const unsigned char *iv);

#ifndef OPENSSL_NO_AES
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
#endif

#ifdef  __cplusplus
}
#endif
#endif
