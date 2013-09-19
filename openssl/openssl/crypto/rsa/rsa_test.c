/* test vectors from p1ovect1.txt */

#include <stdio.h>
#include <string.h>

#include "e_os.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#ifdef OPENSSL_NO_RSA
int main(int argc, char *argv[])
{
    printf("No RSA support\n");
    return(0);
}
#else
#include <openssl/rsa.h>

#define SetKey \
  key->n = BN_bin2bn(n, sizeof(n)-1, key->n); \
  key->e = BN_bin2bn(e, sizeof(e)-1, key->e); \
  key->d = BN_bin2bn(d, sizeof(d)-1, key->d); \
  key->p = BN_bin2bn(p, sizeof(p)-1, key->p); \
  key->q = BN_bin2bn(q, sizeof(q)-1, key->q); \
  key->dmp1 = BN_bin2bn(dmp1, sizeof(dmp1)-1, key->dmp1); \
  key->dmq1 = BN_bin2bn(dmq1, sizeof(dmq1)-1, key->dmq1); \
  key->iqmp = BN_bin2bn(iqmp, sizeof(iqmp)-1, key->iqmp); \
  memcpy(c, ctext_ex, sizeof(ctext_ex) - 1); \
  return (sizeof(ctext_ex) - 1);

static int key1(RSA *key, unsigned char *c)
    {
    static unsigned char n[] =
"\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
"\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
"\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
"\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
"\xF5";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
"\x0A\x03\x37\x48\x62\x64\x87\x69\x5F\x5F\x30\xBC\x38\xB9\x8B\x44"
"\xC2\xCD\x2D\xFF\x43\x40\x98\xCD\x20\xD8\xA1\x38\xD0\x90\xBF\x64"
"\x79\x7C\x3F\xA7\xA2\xCD\xCB\x3C\xD1\xE0\xBD\xBA\x26\x54\xB4\xF9"
"\xDF\x8E\x8A\xE5\x9D\x73\x3D\x9F\x33\xB3\x01\x62\x4A\xFD\x1D\x51";

    static unsigned char p[] =
"\x00\xD8\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
"\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x12"
"\x0D";
    
    static unsigned char q[] =
"\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
"\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
"\x89";

    static unsigned char dmp1[] =
"\x59\x0B\x95\x72\xA2\xC2\xA9\xC4\x06\x05\x9D\xC2\xAB\x2F\x1D\xAF"
"\xEB\x7E\x8B\x4F\x10\xA7\x54\x9E\x8E\xED\xF5\xB4\xFC\xE0\x9E\x05";

    static unsigned char dmq1[] =
"\x00\x8E\x3C\x05\x21\xFE\x15\xE0\xEA\x06\xA3\x6F\xF0\xF1\x0C\x99"
"\x52\xC3\x5B\x7A\x75\x14\xFD\x32\x38\xB8\x0A\xAD\x52\x98\x62\x8D"
"\x51";

    static unsigned char iqmp[] =
"\x36\x3F\xF7\x18\x9D\xA8\xE9\x0B\x1D\x34\x1F\x71\xD0\x9B\x76\xA8"
"\xA9\x43\xE1\x1D\x10\xB2\x4D\x24\x9F\x2D\xEA\xFE\xF8\x0C\x18\x26";

    static unsigned char ctext_ex[] =
"\x1b\x8f\x05\xf9\xca\x1a\x79\x52\x6e\x53\xf3\xcc\x51\x4f\xdb\x89"
"\x2b\xfb\x91\x93\x23\x1e\x78\xb9\x92\xe6\x8d\x50\xa4\x80\xcb\x52"
"\x33\x89\x5c\x74\x95\x8d\x5d\x02\xab\x8c\x0f\xd0\x40\xeb\x58\x44"
"\xb0\x05\xc3\x9e\xd8\x27\x4a\x9d\xbf\xa8\x06\x71\x40\x94\x39\xd2";

    SetKey;
    }

static int key2(RSA *key, unsigned char *c)
    {
    static unsigned char n[] =
"\x00\xA3\x07\x9A\x90\xDF\x0D\xFD\x72\xAC\x09\x0C\xCC\x2A\x78\xB8"
"\x74\x13\x13\x3E\x40\x75\x9C\x98\xFA\xF8\x20\x4F\x35\x8A\x0B\x26"
"\x3C\x67\x70\xE7\x83\xA9\x3B\x69\x71\xB7\x37\x79\xD2\x71\x7B\xE8"
"\x34\x77\xCF";

    static unsigned char e[] = "\x3";

    static unsigned char d[] =
"\x6C\xAF\xBC\x60\x94\xB3\xFE\x4C\x72\xB0\xB3\x32\xC6\xFB\x25\xA2"
"\xB7\x62\x29\x80\x4E\x68\x65\xFC\xA4\x5A\x74\xDF\x0F\x8F\xB8\x41"
"\x3B\x52\xC0\xD0\xE5\x3D\x9B\x59\x0F\xF1\x9B\xE7\x9F\x49\xDD\x21"
"\xE5\xEB";

    static unsigned char p[] =
"\x00\xCF\x20\x35\x02\x8B\x9D\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92"
"\xEA\x0D\xA3\xB4\x32\x04\xB5\xCF\xCE\x91";

    static unsigned char q[] =
"\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
"\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5F";
    
    static unsigned char dmp1[] =
"\x00\x8A\x15\x78\xAC\x5D\x13\xAF\x10\x2B\x22\xB9\x99\xCD\x74\x61"
"\xF1\x5E\x6D\x22\xCC\x03\x23\xDF\xDF\x0B";

    static unsigned char dmq1[] =
"\x00\x86\x55\x21\x4A\xC5\x4D\x8D\x4E\xCD\x61\x77\xF1\xC7\x36\x90"
"\xCE\x2A\x48\x2C\x8B\x05\x99\xCB\xE0\x3F";

    static unsigned char iqmp[] =
"\x00\x83\xEF\xEF\xB8\xA9\xA4\x0D\x1D\xB6\xED\x98\xAD\x84\xED\x13"
"\x35\xDC\xC1\x08\xF3\x22\xD0\x57\xCF\x8D";

    static unsigned char ctext_ex[] =
"\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
"\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
"\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
"\x62\x51";

    SetKey;
    }

static int key3(RSA *key, unsigned char *c)
    {
    static unsigned char n[] =
"\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
"\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
"\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
"\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
"\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
"\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
"\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
"\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
"\xCB";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
"\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
"\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
"\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
"\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
"\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
"\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
"\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
"\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
"\xC1";

    static unsigned char p[] =
"\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
"\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
"\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
"\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
"\x99";

    static unsigned char q[] =
"\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
"\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
"\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
"\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
"\x03";

    static unsigned char dmp1[] =
"\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
"\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
"\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
"\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    static unsigned char dmq1[] =
"\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
"\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
"\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
"\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";
    
    static unsigned char iqmp[] =
"\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
"\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
"\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
"\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
"\xF7";

    static unsigned char ctext_ex[] =
"\xb8\x24\x6b\x56\xa6\xed\x58\x81\xae\xb5\x85\xd9\xa2\x5b\x2a\xd7"
"\x90\xc4\x17\xe0\x80\x68\x1b\xf1\xac\x2b\xc3\xde\xb6\x9d\x8b\xce"
"\xf0\xc4\x36\x6f\xec\x40\x0a\xf0\x52\xa7\x2e\x9b\x0e\xff\xb5\xb3"
"\xf2\xf1\x92\xdb\xea\xca\x03\xc1\x27\x40\x05\x71\x13\xbf\x1f\x06"
"\x69\xac\x22\xe9\xf3\xa7\x85\x2e\x3c\x15\xd9\x13\xca\xb0\xb8\x86"
"\x3a\x95\xc9\x92\x94\xce\x86\x74\x21\x49\x54\x61\x03\x46\xf4\xd4"
"\x74\xb2\x6f\x7c\x48\xb4\x2e\xe6\x8e\x1f\x57\x2a\x1f\xc4\x02\x6a"
"\xc4\x56\xb4\xf5\x9f\x7b\x62\x1e\xa1\xb9\xd8\x8f\x64\x20\x2f\xb1";

    SetKey;
    }

static const char two_prime_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpgIBAAKCAQEAkzpPyWoKaygE+rcFVt+gqk+qq5SgqSXvxZbS1GYWYiwTe5HQ\n"
"NgoQEW16kbbkdFfBPXq+JAU6BAtzkVOxdBDhh9yRKJwe5fK5/KJINLZ47W2V+/LA\n"
"ThykFQA8imgr1s7Vs59mAqcNCKMjm+U2lhMi+Wmmh4ibhT+DnKsaG22NFvReve5L\n"
"WVb4nVjN0oOFWUOEY0/mGoZmDbWgh4m2E4JD2jSSO2jElXEvFcLgQ2c8CAA2EMO0\n"
"RkxObvVEqQREnc7HBXnuEc+vLNeaMtOlMNQ6eEM3dCKQJAQR15UIUqRxQWiUsKDD\n"
"7E7SxDBxmGSc43x27zOjK7GHY9JcCfyQLZL0VwIBAwKCAQBiJt/bnAbyGq38egOP\n"
"P8BxinHHuGsbbp/ZDzc4RA7sHWJSYTV5XAq2SPxhJJhNj9Yo/H7CriatXPe2N8ui\n"
"teuv6GDFvWnuodFTFtrNzvtI87lSodWJaG1jVX2xmsfkiePNFO6sb14Fwhe9Q3m5\n"
"YhdQ8RmvsGeuKle9x2a887NkoeMWdJ7qAlyrlNiXAkIMLLpUua/gRZOtf7MQapZQ\n"
"S6/PyCdiLYPpJsaUwe9cjgZCU+VWr8KZAaqacbzoITMqLaM2rBuGGfjNH4CkJpi4\n"
"n2Ji1Rp/7tvfgdMh2zOS7v/iLzJ3c2pYqyHz4+G8TxJyprXC+yeeyMqrZKCHB53v\n"
"yg/bAoIAgQDm003AoZEOYv2w3cYwuIzLFMFLaTDdzYZnyzcUxQPStGmrPeUWgQ/l\n"
"UPQYsey8cemAmQbko/5EhEotHgd/InBtT9STC4uZzh6rzUzS0xBHXAmfbYLACHXj\n"
"PYPCGVAp7B+EKczxVu69VF3mGd8NHKS7Cv6ERCkd+VyAllsktPcCGwKCAIEAo0jx\n"
"nFjCXzj72BI58Y5zoc94EuDtKrvvrCOyv9YM6W4eq+o/aDanH+Wr4IaldjKY3XW1\n"
"K7zLigMAfC7K+LwZ5OOjMb0dICsJrW9M7UjU34f58Ea5hkxLcedIeNztx4ICRNOm\n"
"sxBfYoH8uOQO9Brdqz+8Y3lbOWle6qkV/pDs2nUCggCBAJniM9XBC17sqSCT2XXQ\n"
"Xdy4gNzwyz6JBEUyJLiDV+HNm8d+mLmrX+41+BB2ndL2m6sQr0MX/thYMXNpWlTB\n"
"oEjf4wyyXRE0FHKI3eHiCto9W7+eVyqwTpd+V9a7isadalgb3fY59H44PplmlLNo\n"
"bdIHVFgtcL6mPasO523N+gFnAoIAgGzbS72QgZTQp+Vhe/Ze98E0+rdAnhx9SnLC\n"
"dyqOs0ZJacfxf5rPGhVDx+sEbk7MZej5I3J93Qasqv10h1B9ZpiXwiEovhVyBnOf\n"
"iJ4wjepapqAvJlmIMkvvhaXonoUBVtiNGcy1lOxWqHtCtKK8k8d/0uz7kiZGP0cb\n"
"Y/8LSJGjAoIAgCxKuaRGe/9Qfr9gRzsrZoLcDlNlcenaKrgyk0K3/+pnZvG8hyhl\n"
"KXnKq5NW2pXBJkQ9J8GRxpvZ7J23SecW7pmHUJWB1FxbWl0KQ6Wnj1qASaC3EIXH\n"
"9EI0hrZfP4iex/VZKTloSPLXCFuSjmvqpWNfwPvk4bJ9t0DpVQa/WCVv\n"
"-----END RSA PRIVATE KEY-----\n";

static const unsigned char two_prime_encrypted_msg[] = {
  0x63, 0x0a, 0x30, 0x45, 0x43, 0x11, 0x45, 0xb7, 0x99, 0x67, 0x90, 0x35, 0x37,
  0x27, 0xff, 0xbc, 0xe0, 0xbf, 0xa6, 0xd1, 0x47, 0x50, 0xbb, 0x6c, 0x1c, 0xaa,
  0x66, 0xf2, 0xff, 0x9d, 0x9a, 0xa6, 0xb4, 0x16, 0x63, 0xb0, 0xa1, 0x7c, 0x7c,
  0x0c, 0xef, 0xb3, 0x66, 0x52, 0x42, 0xd7, 0x5e, 0xf3, 0xa4, 0x15, 0x33, 0x40,
  0x43, 0xe8, 0xb1, 0xfc, 0xe0, 0x42, 0x83, 0x46, 0x28, 0xce, 0xde, 0x7b, 0x01,
  0xeb, 0x28, 0x92, 0x70, 0xdf, 0x8d, 0x54, 0x9e, 0xed, 0x23, 0xb4, 0x78, 0xc3,
  0xca, 0x85, 0x53, 0x48, 0xd6, 0x8a, 0x87, 0xf7, 0x69, 0xcd, 0x82, 0x8c, 0x4f,
  0x5c, 0x05, 0x55, 0xa6, 0x78, 0x89, 0xab, 0x4c, 0xd8, 0xa9, 0xd6, 0xa5, 0xf4,
  0x29, 0x4c, 0x23, 0xc8, 0xcf, 0xf0, 0x4c, 0x64, 0x6b, 0x4e, 0x02, 0x17, 0x69,
  0xd6, 0x47, 0x83, 0x30, 0x43, 0x02, 0x29, 0xda, 0xda, 0x75, 0x3b, 0xd7, 0xa7,
  0x2b, 0x31, 0xb3, 0xe9, 0x71, 0xa4, 0x41, 0xf7, 0x26, 0x9b, 0xcd, 0x23, 0xfa,
  0x45, 0x3c, 0x9b, 0x7d, 0x28, 0xf7, 0xf9, 0x67, 0x04, 0xba, 0xfc, 0x46, 0x75,
  0x11, 0x3c, 0xd5, 0x27, 0x43, 0x53, 0xb1, 0xb6, 0x9e, 0x18, 0xeb, 0x11, 0xb4,
  0x25, 0x20, 0x30, 0x0b, 0xe0, 0x1c, 0x17, 0x36, 0x22, 0x10, 0x0f, 0x99, 0xb5,
  0x50, 0x14, 0x73, 0x07, 0xf0, 0x2f, 0x5d, 0x4c, 0xe3, 0xf2, 0x86, 0xc2, 0x05,
  0xc8, 0x38, 0xed, 0xeb, 0x2a, 0x4a, 0xab, 0x76, 0xe3, 0x1a, 0x75, 0x44, 0xf7,
  0x6e, 0x94, 0xdc, 0x25, 0x62, 0x7e, 0x31, 0xca, 0xc2, 0x73, 0x51, 0xb5, 0x03,
  0xfb, 0xf9, 0xf6, 0xb5, 0x8d, 0x4e, 0x6c, 0x21, 0x0e, 0xf9, 0x97, 0x26, 0x57,
  0xf3, 0x52, 0x72, 0x07, 0xf8, 0xb4, 0xcd, 0xb4, 0x39, 0xcf, 0xbf, 0x78, 0xcc,
  0xb6, 0x87, 0xf9, 0xb7, 0x8b, 0x6a, 0xce, 0x9f, 0xc8,
};

static const char three_prime_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIE1wIBAQKCAQBikenqs11sKa4hg7u1grGe6uBkWx4vXiwKgD0p1Pqa50TmIb2Y\n"
"wD3gU1mu0z7+xMLEWlqJB/RP3LBq1D6ZfXqXJk7hk8pu7Qf8tPqVHnN7hghqudQp\n"
"sH5Zt51762du8Ltez7nNWJPw54gXbA12Hrknmk0CFrZJbaeDI00CSAwMHw6FIeMG\n"
"dgpz5sEh+jAYeClcMdAprm99h9gvFvq8Z4qUcVmb7CJAVZ/ClLW9eAHJ7xjIbQ3c\n"
"U0KyXKtlBb01CIUb+OlHvP7FrkcpY0SOTbdHqw3YdmhPxwcC5Iawz9gZrfSFdos7\n"
"TkCNKXqKBzbzeK4Xpo9TWGVMhp7Xi+w4T5nHAgEDAoIBAEG2m/HM6PLGdBZX0nkB\n"
"y79HQELnaXTpcrGq03E4pxHvg0QWfmXVfpWM5nSM1KnYgdg8PFtaot/odZyNfxD+\n"
"UboZieu33EnzWqh4pw4UTP0EBZx74sWjBO7ZTP19R7ANmz1wkYEsqyuHrRFoJPwr\n"
"1O5eKOttq94PdxVYdjnJWTp/GZ3Gfobk1Thwnq65+zMz0QwtqwEg4YspmdPrhwVy\n"
"qkNYZI6eMdtFmyusWIBdM6JDBZbMyi0EX9a3PYuPLaOl+HP118AZ/xDm7jomL+Fk\n"
"PRHNLeQKhCfjyxZiGefjDRPoCVpT0CBWFfWzZ6yhtZRrq9xxx78K3nb1A6Aw2Ced\n"
"ACsCVwDxT8KGEwYX92l+N99nxTKgdBwyaQ+fCIgksVG8vJK6cx+cdcIUbU/EWs/a\n"
"RDUAa0I7nxTxBbNRIra+nODBXEhh305McrgFNXys8bugOyrq94bp0v8eHQJWAMqx\n"
"OfaixjtlRS85AM1u1lX3cTeJwud6wBqmL+oXfKoqkY/Ux1CLq46ZOzORvAIQWEtY\n"
"QJvEj0grp0T9BwTwmGdW6iWSiy5LSqHTwqS0m1lwMqbYi9kCVwCg39cEDK66pPD+\n"
"z+pFLiHATWghm1+/WwVty4vTKGHRohUS+SwNnjUtkd/m2CNVnNbSag32A8zgwc8p\n"
"vesrktrr6jQy9yVYzlMd9n0VfMdHT69GjKoUEwJWAIcg0U8XLtJDg3TQqzOfOY6k\n"
"9iUGge+nKrxuypwPqHFxtl/jL4sHx7RmJ3e2fVa1kDI61b0ttNrHxNior1igZZo5\n"
"8W5hsh7c3GvigcMjEjugIcSQXTsCVwDmiqq4bSyBQ7XWoCtCSakKUfoYyDLqVBjz\n"
"YMK1SkMFk5wB2Sjtc/qCvBJky8QkqT6ufEuPlFd7FBBB3GISjLJKfPZT1Mbk2tGi\n"
"AA49MPcFTx2CvFLZsTCCAQowggEGAlYAhBJP9ztlUzRsbE133/0fthbiJRXKycFB\n"
"mlDa64hPPbMBAETErOcUYqZW3sW3wx0HvX1kxX5FJVbtetIU204n1B/4lKfvB87b\n"
"JLfdcVxjyTP+3kBS6wJVWAw1T3zuN3hISDOlP/4VJA9Bbg6HMSuBEYs8nQWKKSIA\n"
"qtiDHe9i7G7klIPP12iv06jt2P7Yw49I/IwN54lv4r/7DcVKBTSSGHqToOhChiKp\n"
"6YA3RwJVYHar3iv1oiyqDJmB7nIsfSJZKjXqUE5Ha5ItMKEBpZ4mbifK9fKHXTGv\n"
"6TLNEP1N2/mGBRIbAYRVl1/ieCfZ5CZ9qw7gG2/LSxTd3NyL6J/QYpbKzw==\n"
"-----END RSA PRIVATE KEY-----\n";

static const unsigned char three_prime_encrypted_msg[] = {
  0x58, 0xd9, 0xea, 0x8a, 0xf6, 0x3d, 0xb4, 0xd9, 0xf7, 0xbb, 0x02, 0xc5, 0x58,
  0xd2, 0xa9, 0x46, 0x80, 0x70, 0x70, 0x16, 0x07, 0x64, 0x32, 0x4c, 0x4e, 0x92,
  0x61, 0xb7, 0xff, 0x92, 0xdc, 0xfc, 0xf8, 0xf0, 0x2c, 0x84, 0x56, 0xbc, 0xe5,
  0x93, 0x76, 0xe5, 0xa3, 0x72, 0x98, 0xf2, 0xdf, 0xef, 0x99, 0x53, 0xf6, 0xd8,
  0x4b, 0x09, 0xac, 0xa9, 0xa3, 0xdb, 0x63, 0xa1, 0xb5, 0x09, 0x8e, 0x40, 0x84,
  0x8f, 0x4d, 0xd5, 0x1d, 0xac, 0x6c, 0xaa, 0x6b, 0x15, 0xe7, 0xb1, 0x0c, 0x67,
  0xd2, 0xb2, 0x81, 0x58, 0x30, 0x0e, 0x18, 0x27, 0xa1, 0x9b, 0x96, 0xad, 0xae,
  0x76, 0x1a, 0x32, 0xf7, 0x10, 0x0b, 0x53, 0x85, 0x31, 0xd6, 0x2a, 0xf6, 0x1c,
  0x9f, 0xc2, 0xc7, 0xb1, 0x05, 0x63, 0x0b, 0xa5, 0x07, 0x1f, 0x1c, 0x01, 0xf0,
  0xe0, 0x06, 0xea, 0x20, 0x69, 0x41, 0x19, 0x57, 0x92, 0x17, 0xf7, 0x0c, 0x5c,
  0x66, 0x75, 0x0e, 0xe5, 0xb3, 0xf1, 0x67, 0x3b, 0x27, 0x47, 0xb2, 0x8e, 0x1c,
  0xb6, 0x3f, 0xdd, 0x76, 0x42, 0x31, 0x13, 0x68, 0x96, 0xdf, 0x3b, 0xd4, 0x87,
  0xd9, 0x16, 0x44, 0x71, 0x52, 0x2e, 0x54, 0x3e, 0x09, 0xcd, 0x71, 0xc1, 0x1e,
  0x5e, 0x96, 0x13, 0xc9, 0x1e, 0xa4, 0xe6, 0xe6, 0x97, 0x2c, 0x6b, 0xf2, 0xa9,
  0x5c, 0xc6, 0x60, 0x2a, 0xbc, 0x82, 0xf8, 0xcb, 0xd4, 0xd7, 0xea, 0x8a, 0xa1,
  0x8a, 0xd9, 0xa5, 0x14, 0x8b, 0x9e, 0xf9, 0x25, 0x02, 0xd2, 0xab, 0x0c, 0x42,
  0xca, 0x2d, 0x45, 0xa3, 0x56, 0x5e, 0xa2, 0x2a, 0xc8, 0x60, 0xa5, 0x87, 0x5d,
  0x85, 0x5c, 0xde, 0xc7, 0xa2, 0x47, 0xc3, 0x99, 0x29, 0x23, 0x79, 0x36, 0x88,
  0xad, 0x40, 0x3e, 0x27, 0x7d, 0xf0, 0xb6, 0xfa, 0x95, 0x20, 0x3c, 0xec, 0xfc,
  0x56, 0x3b, 0x20, 0x91, 0xee, 0x98, 0x10, 0x2c, 0x82,
};

static const char six_prime_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIFJAIBAQKCAQAcBDlEubhxHBz33BEbhTsr6Kbr6+m2hpdzXXVG0TUl+DCaw1dE\n"
"iaZEWeM6YLUzhHKkA8UaIJhwveg7wZuKOiRFtmpztNBsGManlNMkcPAtDKWyO8Uz\n"
"kJ1WjTP2k32nlYgF3/VlWLlb0wecFo50/Lh2r2KZbNTFs2nlZN84ACUk6bFKhab0\n"
"tiNoZ0osvZ0BOwSMcJSCdkUMi5WKBxwy5wmXOv3KV+lXDK4royXR8g00oeYvexs2\n"
"U4OVuSZuTzYm+Eeu3+hN9rL/AyN0+qVty8uAEsN38Bm38msZXN4K1+6MSC9QJKUu\n"
"zCrtwjXgPSkxF9aPRKpbM720iIfZKT+U53XjAgEDAoIBABKte4MmevYSvfqSthJY\n"
"0h1FxJ1H8SRZukzo+NngzhlQIGcs5NhbxC2RQesFT/S0IMe81uJcoCfPuLM7XOte\n"
"lreZS4rDcK9/2F/ryxp5RGiXhNgph2S6GC6VZhp92TU6XJJ6gRtsqfj6BSMYW7L4\n"
"dxzFG30mX0hpG8Q0726hFdKyrLio7R7u3LW5XHklSLvlndjl4pTf1TIihL/CqqRU\n"
"uynbE0ooPYM6/6OuOAj8NoSRMNH9gmTxD66615pDWANeXwHLi5CNdzRvN0C2bSIj\n"
"kLL9MrWWRb+ujMRiA2xokFkxGsv7pAuUFRPaGo2nCzRik+q+bnHCHcidrGbMMYf/\n"
"masCLAClV0Fmh2gCat+XsP5rNMQziCvOgq8tM1qtdS2spdY6LWVDaPtEnrglBe2X\n"
"AiwA0nc0JKxgmsRoNOVqo9zisFhcNYNax6fBC36epYUyR5Mi7rZZ6eNhlNAOywIr\n"
"bjorma+arEc/unX+8iMtd7AdNFcfc3eRyPjJHcPkJsjuLPCngxR6w1lJDwIsAIxP\n"
"eBhy6xHYRXiY8cKTQcrlks5Xkdpv1gepvxkDdtpiF0nO5pvs67iKtIcCLACjwimm\n"
"p+E86c8PUFEczMhbCJyXJDqGI6gLu1SmuXA9HdAbo6zZsgOA12fsMIICLTCCAIgC\n"
"LACXXTvyzLrZd2eq0iKno0kIx7gnoVlLp6XSdAXnWjXXJXkYIIol7DtSr8vbAitk\n"
"6NKh3dHmT5px4WxvwjCwhSVvwOYyb8Phoq6aPCPkw6YQFbFunXzhyofnAite7yUp\n"
"7fZSFdNgtojPD+IkpASXnJ1YE7sAbTn2rSF+ViwuBgbEbUSseR/lMIIAiQIsANvx\n"
"ePmklOo5ij8jSCojj9IYl9LfD7grM6Doj7xOQv1Uxw/eum26lqfOZz0CLACSoPtR\n"
"GGNG0QbUwjAcF7U2uw/h6gp6x3fAmwp9iYH+OIS1Pybz0bnFNETTAitMvR1EyBkj\n"
"2LOWZktiyz7mbBHfspLTyDS5plovGfQLsuaOpq+jrqSzksR5MIIAhQIrAImrMPx7\n"
"N5QRn00xO6wJV+Zk7KDI+AQa+SqkSzYYu1/czfDIy5fR3xMSPwIqW8d1/ad6YrZq\n"
"M3YnyAY6mZidwIX6rWdQxxgyJBB86pMz9dsyZTaUt2F/AioWbJahUG86ksB1Q7Vr\n"
"nBcJ0/BnaUWS+3tQqEKbM5Kr1eZJsyaZVRY6OWMwggCHAisAwSUZHW4Yyy1k4ua2\n"
"HOSqnLnuGNT3X2ZA8OExOPJTAIvM5A23gbTmHBmvAisAgMNmE567Mh5DQe8kE0Mc\n"
"aHv0EI36P5mAoJYg0KGMqwfd7V56VniZaBEfAisAsFnqZ5NCvwdUOEHLc6QOwq5W\n"
"GUHJirIvqAqxThI5LsCUmsaj5K+KFga4\n"
"-----END RSA PRIVATE KEY-----\n";

static const unsigned char six_prime_encrypted_msg[] = {
  0x0a, 0xcb, 0x6c, 0x02, 0x9d, 0x1a, 0x7c, 0xf3, 0x4e, 0xff, 0x16, 0x88, 0xee,
  0x22, 0x1d, 0x8d, 0xd2, 0xfd, 0xde, 0x83, 0xb3, 0xd9, 0x35, 0x2c, 0x82, 0xe0,
  0xff, 0xe6, 0x79, 0x6d, 0x06, 0x21, 0x74, 0xa8, 0x04, 0x0c, 0xe2, 0xd3, 0x98,
  0x3f, 0xbf, 0xd0, 0xe9, 0x88, 0x24, 0xe2, 0x05, 0xa4, 0x45, 0x51, 0x87, 0x6b,
  0x1c, 0xef, 0x5f, 0x2d, 0x61, 0xb6, 0xf1, 0x4c, 0x1f, 0x3d, 0xbf, 0x4b, 0xf2,
  0xda, 0x09, 0x97, 0x81, 0xde, 0x91, 0xb7, 0x0d, 0xb4, 0xc2, 0xab, 0x41, 0x64,
  0x9d, 0xd9, 0x39, 0x46, 0x79, 0x66, 0x43, 0xf1, 0x34, 0x21, 0x56, 0x2f, 0xc6,
  0x68, 0x40, 0x4a, 0x2d, 0x73, 0x96, 0x50, 0xe1, 0xb0, 0xaf, 0x49, 0x39, 0xb4,
  0xf0, 0x3a, 0x78, 0x38, 0x70, 0xa9, 0x91, 0x5d, 0x5e, 0x07, 0xf4, 0xec, 0xbb,
  0xc4, 0xe5, 0x8a, 0xb8, 0x06, 0xba, 0xdf, 0xc6, 0x48, 0x78, 0x4b, 0xca, 0x2a,
  0x8a, 0x92, 0x64, 0xe3, 0xa6, 0xae, 0x87, 0x97, 0x12, 0x16, 0x46, 0x67, 0x59,
  0xdf, 0xf2, 0xf3, 0x89, 0x6f, 0xe8, 0xa9, 0x13, 0x57, 0x63, 0x4e, 0x07, 0x98,
  0xcc, 0x73, 0xa0, 0x84, 0x9d, 0xe8, 0xb3, 0x50, 0x59, 0xb5, 0x51, 0xb3, 0x41,
  0x7d, 0x55, 0xfe, 0xd9, 0xf0, 0xc6, 0xff, 0x6e, 0x96, 0x4f, 0x22, 0xb2, 0x0d,
  0x6b, 0xc9, 0x83, 0x2d, 0x98, 0x98, 0xb2, 0xd1, 0xb7, 0xe4, 0x50, 0x83, 0x1a,
  0xa9, 0x02, 0x9f, 0xaf, 0x54, 0x74, 0x2a, 0x2c, 0x63, 0x10, 0x79, 0x45, 0x5c,
  0x95, 0x0d, 0xa1, 0x9b, 0x55, 0xf3, 0x1e, 0xb7, 0x56, 0x59, 0xf1, 0x59, 0x8d,
  0xd6, 0x15, 0x89, 0xf6, 0xfe, 0xc0, 0x00, 0xdd, 0x1f, 0x2b, 0xf0, 0xf7, 0x5d,
  0x64, 0x84, 0x76, 0xd3, 0xc2, 0x92, 0x35, 0xac, 0xb5, 0xf9, 0xf6, 0xa8, 0x05,
  0x89, 0x4c, 0x95, 0x41, 0x4e, 0x34, 0x25, 0x11, 0x14,
};

static int
test_multi_prime_key(int nprimes, const char* pem, unsigned pem_size, const unsigned char* enc, unsigned enc_size) {
	unsigned char out[256];
	int len;

	BIO* bio = BIO_new_mem_buf((void*)pem, pem_size);
	RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (!RSA_check_key(rsa))
		{
		printf("%d-prime key failed to parse.\n", nprimes);
		return -1;
		}
	BIO_free(bio);

	memset(out, 0, sizeof(out));
	len = RSA_private_decrypt(enc_size, enc, out, rsa, RSA_PKCS1_PADDING);
	if (len != 11 || memcmp(out, "hello world", 11) != 0)
		{
		printf("%d-prime key failed to decrypt.\n", nprimes);
		return -1;
		}

	RSA_free(rsa);
	return 0;
}

static int pad_unknown(void)
{
    unsigned long l;
    while ((l = ERR_get_error()) != 0)
      if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
	return(1);
    return(0);
}

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int main(int argc, char *argv[])
    {
    int err=0;
    int v;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    unsigned char ctext_ex[256];
    int plen;
    int clen = 0;
    int num;
#ifndef QUICK_DEBUG
    int n;
#endif

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or OAEP may fail */

    plen = sizeof(ptext_ex) - 1;

    for (v = 0; v < 6; v++)
	{
	key = RSA_new();
	switch (v%3) {
    case 0:
	clen = key1(key, ctext_ex);
	break;
    case 1:
	clen = key2(key, ctext_ex);
	break;
    case 2:
	clen = key3(key, ctext_ex);
	break;
	}
	if (v/3 >= 1) key->flags |= RSA_FLAG_NO_CONSTTIME;

	num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
				 RSA_PKCS1_PADDING);
	if (num != clen)
	    {
	    printf("PKCS#1 v1.5 encryption failed!\n");
	    err=1;
	    goto oaep;
	    }
  
	num = RSA_private_decrypt(num, ctext, ptext, key,
				  RSA_PKCS1_PADDING);
	if (num != plen || memcmp(ptext, ptext_ex, num) != 0)
	    {
	    printf("PKCS#1 v1.5 decryption failed!\n");
	    err=1;
	    }
	else
	    printf("PKCS #1 v1.5 encryption/decryption ok\n");

    oaep:
	ERR_clear_error();
	num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
				 RSA_PKCS1_OAEP_PADDING);
	if (num == -1 && pad_unknown())
	    {
	    printf("No OAEP support\n");
	    goto next;
	    }
	if (num != clen)
	    {
	    printf("OAEP encryption failed!\n");
	    err=1;
	    goto next;
	    }

	num = RSA_private_decrypt(num, ctext, ptext, key,
				  RSA_PKCS1_OAEP_PADDING);
	if (num != plen || memcmp(ptext, ptext_ex, num) != 0)
	    {
	    printf("OAEP decryption (encrypted data) failed!\n");
	    err=1;
	    }
	else if (memcmp(ctext, ctext_ex, num) == 0)
	    printf("OAEP test vector %d passed!\n", v);
    
	/* Different ciphertexts (rsa_oaep.c without -DPKCS_TESTVECT).
	   Try decrypting ctext_ex */

	num = RSA_private_decrypt(clen, ctext_ex, ptext, key,
				  RSA_PKCS1_OAEP_PADDING);

	if (num != plen || memcmp(ptext, ptext_ex, num) != 0)
	    {
	    printf("OAEP decryption (test vector data) failed!\n");
	    err=1;
	    }
	else
	    printf("OAEP encryption/decryption ok\n");
#ifndef QUICK_DEBUG
	/* Try decrypting corrupted ciphertexts */
	for(n = 0 ; n < clen ; ++n)
	    {
	    int b;
	    unsigned char saved = ctext[n];
	    for(b = 0 ; b < 256 ; ++b)
		{
		if(b == saved)
		    continue;
		ctext[n] = b;
		num = RSA_private_decrypt(num, ctext, ptext, key,
					  RSA_PKCS1_OAEP_PADDING);
		if(num > 0)
		    {
		    printf("Corrupt data decrypted!\n");
		    err = 1;
		    }
		}
	    }
#endif
    next:
	RSA_free(key);
	}

	if (test_multi_prime_key(2, two_prime_key, sizeof(two_prime_key), two_prime_encrypted_msg, sizeof(two_prime_encrypted_msg)))
		err = 1;
	if (test_multi_prime_key(3, three_prime_key, sizeof(three_prime_key), three_prime_encrypted_msg, sizeof(three_prime_encrypted_msg)))
		err = 1;
	if (test_multi_prime_key(6, six_prime_key, sizeof(six_prime_key), six_prime_encrypted_msg, sizeof(six_prime_encrypted_msg)))
		err = 1;

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);

    CRYPTO_mem_leaks_fp(stderr);

#ifdef OPENSSL_SYS_NETWARE
    if (err) printf("ERROR: %d\n", err);
#endif
    return err;
    }
#endif
