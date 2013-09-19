// Copyright 2012 Google Inc. All Rights Reserved.
// Author: mhalcrow@google.com (Mike Halcrow)

#include "openssl/ssl.h"
#include "openssl/evp.h"

#include "testing/base/public/gunit.h"

namespace {

static const unsigned char* kAad =
    reinterpret_cast<const unsigned char*>("Some text AAD");

class GcmTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_EQ(sizeof(key), sizeof(iv));
    for (int i = 0; i < sizeof(key); ++i) {
      key[i] = rand() % 256;  // Don't care about seeding for test
      iv[i] = 0;
    }
    ASSERT_EQ(sizeof(plaintext), sizeof(ciphertext));
    for (int i = 0; i < sizeof(plaintext); ++i) {
      ciphertext[i] = 0;
      plaintext[i] = i % 256;
    }
    memset(tag, 0, sizeof(tag));
    EVP_CIPHER_CTX_init(&enc_ctx);
    EVP_CIPHER_CTX_init(&dec_ctx);
  }

  virtual void TearDown() {
    EVP_CIPHER_CTX_cleanup(&dec_ctx);
    EVP_CIPHER_CTX_cleanup(&enc_ctx);
  }

  virtual void Encrypt() {
    ASSERT_LE(0, EVP_CipherInit(&enc_ctx, EVP_aes_128_gcm(), key, iv, 1));
    EVP_Cipher(&enc_ctx, NULL, kAad, sizeof(kAad));
    EVP_Cipher(&enc_ctx, ciphertext, plaintext, sizeof(ciphertext));
    EVP_Cipher(&enc_ctx, NULL, NULL, 0);
    ASSERT_TRUE(
        EVP_CIPHER_CTX_ctrl(&enc_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag));
    bool ciphertext_is_sane = false;
    for (int i = 0; i < sizeof(ciphertext); ++i) {
      if (ciphertext[i] != 0) {
        ciphertext_is_sane = true;
        break;
      }
    }
    EXPECT_TRUE(ciphertext_is_sane);
    bool tag_is_sane = false;
    for (int i = 0; i < sizeof(tag); ++i) {
      if (tag[i] != 0) {
        tag_is_sane = true;
        break;
      }
    }
    EXPECT_TRUE(tag_is_sane);
  }

  virtual void Decrypt(bool expect_valid_tag) {
    ASSERT_LE(0, EVP_CipherInit(&dec_ctx, EVP_aes_128_gcm(), key, iv, 0));
    ASSERT_TRUE(
        EVP_CIPHER_CTX_ctrl(&dec_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag));
    EVP_Cipher(&dec_ctx, NULL, kAad, sizeof(kAad));
    memset(plaintext, 0, sizeof(plaintext));
    EVP_Cipher(&dec_ctx, plaintext, ciphertext, sizeof(plaintext));
    if (expect_valid_tag) {
      EXPECT_LE(0, EVP_Cipher(&dec_ctx, NULL, NULL, 0))
          << "EVP_Cipher: Expected tag verify to succeed, but it failed";
    } else {
      EXPECT_GT(0, EVP_Cipher(&dec_ctx, NULL, NULL, 0))
          << "EVP_Cipher: Expected tag verify to fail, but it succeeded";
    }
    for (int i = 0; i < sizeof(plaintext); ++i) {
      ASSERT_EQ(i % 256, plaintext[i])
          << "Decrypted text mismatches original plaintext";
    }
  }

  unsigned char ciphertext[512];
  EVP_CIPHER_CTX dec_ctx;
  EVP_CIPHER_CTX enc_ctx;
  unsigned char iv[16];
  unsigned char key[16];
  unsigned char plaintext[512];
  unsigned char tag[16];
};

TEST_F(GcmTest, GcmCryptWithGoodTag) {
  Encrypt();
  Decrypt(true);
}

TEST_F(GcmTest, GcmCryptWithBadTag) {
  Encrypt();
  ++tag[0];
  Decrypt(false);
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
