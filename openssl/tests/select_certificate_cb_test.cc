// Copyright 2011 Google Inc. All Rights Reserved.
// Author: agl@google.com (Adam Langley)

// This code tests that the certificate selection callback is made for SSLv2
// compat, SSLv3 and TLSv1 handshakes, and that suspending the handshake works.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "base/basictypes.h"
#include "testing/base/public/gunit.h"

namespace {

DH *global_dh = NULL;

class SelectCertCallbackTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds_));
    CHECK_EQ(0, fcntl(fds_[0], F_SETFL, O_NONBLOCK));
    CHECK_EQ(0, fcntl(fds_[1], F_SETFL, O_NONBLOCK));
    BIO *bio = BIO_new_socket(fds_[1], 0 /* don't take ownership of fd */);
    ctx_ = SSL_CTX_new(SSLv23_server_method());
    CHECK_EQ(SSL_CTX_set_cipher_list(ctx_, "ADH-AES128-SHA"), 1);
    callback_called_ = false;

    if (!global_dh) {
      global_dh = DH_new();
      CHECK(DH_generate_parameters_ex(global_dh, 32, DH_GENERATOR_2, 0));
      CHECK(DH_generate_key(global_dh));
    }

    SSL_CTX_set_tmp_dh(ctx_, global_dh);
    server_ = SSL_new(ctx_);
    SSL_set_bio(server_, bio, bio);
  }

  virtual void TearDown() {
    SSL_free(server_);
    // SSL_free deletes the BIO
    close(fds_[0]);
    close(fds_[1]);
    SSL_CTX_free(ctx_);
  }

  void Write(const uint8 *client_hello, unsigned client_hello_len) {
    ssize_t r = write(fds_[0], client_hello, client_hello_len);
    ASSERT_LE(0, r);
    ASSERT_EQ(client_hello_len, static_cast<unsigned>(r));
  }

  void InstallCallback() {
    ctx_->select_certificate_cb = &SelectCertCallbackTest::Callback;
    SSL_set_app_data(server_, this);
    callback_return_value_ = 1;
  }

  static int Callback(SSL* s) {
    SelectCertCallbackTest* that =
        reinterpret_cast<SelectCertCallbackTest*>(SSL_get_app_data(s));
    that->callback_called_ = true;
    return that->callback_return_value_;
  }

  int fds_[2];
  SSL_CTX *ctx_;
  SSL *server_;
  bool callback_called_;
  int callback_return_value_;
};

static const uint8 kSSLv2ClientHello[] = {
  0x80, 0x2c,  // length
  1,           // ClientHello
  3, 1,        // TLSv1
  0, 3,        // 3 bytes of cipher specs
  0, 0,        // no session id
  0, 32,       // challenge length
  0, 0, 0x34,  // ADH-AES128-SHA
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
};

TEST_F(SelectCertCallbackTest, SSLv2NotCalled) {
  Write(kSSLv2ClientHello, sizeof(kSSLv2ClientHello));
  EXPECT_EQ(-1, SSL_accept(server_));
  EXPECT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_, -1));
  EXPECT_FALSE(callback_called_);
}

TEST_F(SelectCertCallbackTest, SSLv2Called) {
  InstallCallback();
  Write(kSSLv2ClientHello, sizeof(kSSLv2ClientHello));
  EXPECT_EQ(-1, SSL_accept(server_));
  EXPECT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_, -1));
  EXPECT_TRUE(callback_called_);
}

static const uint8 kSSLv3ClientHello[] = {
  0x16,      // handshake
  3, 0,      // SSLv3
  0, 45,     // record length
  1,         // ClientHello
  0, 0, 41,  // Handshake record length
  3, 0,      // SSLv3
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0,         // no session id
  0, 2,      // 2 bytes of cipher suites
  0, 0x34,   // ADH-AES128-SHA
  1,         // 1 byte of compression methods
  0,         // no compression
};

TEST_F(SelectCertCallbackTest, SSLv3NotCalled) {
  Write(kSSLv3ClientHello, sizeof(kSSLv3ClientHello));
  EXPECT_EQ(-1, SSL_accept(server_));
  EXPECT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_, -1));
  EXPECT_FALSE(callback_called_);
}

TEST_F(SelectCertCallbackTest, SSLv3Called) {
  InstallCallback();
  Write(kSSLv3ClientHello, sizeof(kSSLv3ClientHello));
  EXPECT_EQ(-1, SSL_accept(server_));
  EXPECT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_, -1));
  EXPECT_TRUE(callback_called_);
}

TEST_F(SelectCertCallbackTest, CallbackSuspend) {
  InstallCallback();
  callback_return_value_ = 0;

  Write(kSSLv3ClientHello, sizeof(kSSLv3ClientHello));
  EXPECT_LT(SSL_accept(server_), 0);
  EXPECT_EQ(SSL_ERROR_PENDING_CERTIFICATE, SSL_get_error(server_, -1));
  EXPECT_TRUE(callback_called_);
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
