// Copyright 2010 Google Inc. All Rights Reserved.
// Author: agl@google.com (Adam Langley)

// This test checks that we can renegotiate with False Start (aka cut-through
// for historical reasons.)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "thread/thread.h"
#include "testing/base/public/gunit.h"

DECLARE_string(test_srcdir);

namespace {

static const char kMagicString[] = "testing";
static const size_t kMagicStringLen = sizeof(kMagicString);

class ServerThread : public Thread {
 public:
  explicit ServerThread(SSL *server)
      : server_(server) {
  }

  void Run() {
    CHECK_EQ(SSL_accept(server_), 1);

    char buf[kMagicStringLen];
    CHECK_EQ(SSL_read(server_, buf, kMagicStringLen), kMagicStringLen);
    CHECK(memcmp(buf, kMagicString, kMagicStringLen) == 0);

    SSL_set_verify(server_, SSL_VERIFY_PEER, NULL);
    // Sends a HelloRequest
    CHECK_NE(0, SSL_renegotiate(server_));
    CHECK_NE(0, SSL_do_handshake(server_));
    // Forces the renegotiation to occur now, rather than during the course of
    // the connection.
    server_->state = SSL_ST_ACCEPT;
    CHECK_NE(0, SSL_do_handshake(server_));

    CHECK_EQ(SSL_write(server_, kMagicString, kMagicStringLen),
             kMagicStringLen);

    SSL_shutdown(server_);
  }

 private:
  SSL *const server_;
};

static long DumpCallback(BIO *bio, int cmd, const char *argp, int argi,
                         long argl, long ret) {
  BIO *out = BIO_new_socket(1, 0 /* don't take ownership */);
  if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
    BIO_printf(out, "read from %p [%p] (%d bytes => %ld (0x%lX))\n",
               (void *)bio,argp,argi,ret,ret);
    BIO_dump(out,argp,(int)ret);
  } else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN)) {
    BIO_printf(out, "write to %p [%p] (%d bytes => %ld (0x%lX))\n",
               (void *)bio,argp,argi,ret,ret);
    BIO_dump(out,argp,(int)ret);
  }
  BIO_free(out);
  return ret;
}

class FalseStartRenegotiationTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    client_bio = BIO_new_socket(fds[0], 0 /* don't take ownership of fd */);
    server_bio = BIO_new_socket(fds[1], 0 /* don't take ownership of fd */);
    client_ctx = SSL_CTX_new(TLSv1_client_method());
    server_ctx = SSL_CTX_new(TLSv1_server_method());
    CHECK_EQ(SSL_CTX_set_cipher_list(client_ctx, "NULL-SHA"), 1);
    CHECK_EQ(SSL_CTX_set_cipher_list(server_ctx, "NULL-SHA"), 1);
    SSL_CTX_set_session_cache_mode(client_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_session_cache_mode(server_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(client_ctx,
                        SSL_OP_NO_TICKET |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_TICKET);

    string prefix = FLAGS_test_srcdir + "/google3/third_party/openssl/tests/";
    string key_file = prefix + "test.key";
    string crt_file = prefix + "test.crt";

    CHECK_NE(0, SSL_CTX_use_PrivateKey_file(server_ctx, key_file.c_str(),
                                            SSL_FILETYPE_PEM));
    CHECK_NE(0, SSL_CTX_use_certificate_file(server_ctx, crt_file.c_str(),
                                             SSL_FILETYPE_PEM));

    server = SSL_new(server_ctx);
    SSL_set_bio(server, server_bio, server_bio);
    client = SSL_new(client_ctx);
    SSL_set_bio(client, client_bio, client_bio);
  }

  void Clear(bool delete_contexts) {
    SSL_free(client);
    SSL_free(server);
    // SSL_free deletes the BIO
    close(fds[0]);
    close(fds[1]);

    if (delete_contexts) {
      SSL_CTX_free(client_ctx);
      SSL_CTX_free(server_ctx);
    }
  }

  virtual void TearDown() {
    Clear(true /* also delete [server|client]_ctx */);
  }

  void DoConnectionAndRenegotiate() {
    ServerThread *const thread = new ServerThread(server);
    thread->SetJoinable(true);
    thread->Start();

    int ret = SSL_connect(client);
    if (ret != 1) {
      const int err = SSL_get_error(client, ret);
      if (err != SSL_ERROR_SSL)
        LOG(FATAL) << "Connect failed: " << ret;

      const long err2 = ERR_get_error();
      char buf[256];
      LOG(FATAL) << "Connect failed: " << ERR_error_string(err2, buf);
    }

    CHECK_EQ(SSL_write(client, kMagicString, kMagicStringLen),
             kMagicStringLen);

    char buf[kMagicStringLen];
    ret = SSL_read(client, buf, kMagicStringLen);
    if (ret < 0) {
      int err = SSL_get_error(client, ret);
      if (err == SSL_ERROR_WANT_READ) {
        ret = SSL_read(client, buf, kMagicStringLen);
      } else {
        LOG(FATAL) << "Unexpected read error: " << err;
      }
    }
    CHECK_EQ(kMagicStringLen, ret);
    CHECK(memcmp(buf, kMagicString, kMagicStringLen) == 0);

    thread->Join();
    SSL_shutdown(client);
    delete thread;
  }

  int fds[2];
  BIO *client_bio, *server_bio;
  SSL_CTX *client_ctx, *server_ctx;
  SSL *server, *client;
};


TEST_F(FalseStartRenegotiationTest, WithoutFalseStart) {
  // A normal TLS renegotiation
  BIO_set_callback(SSL_get_rbio(server), DumpCallback);
  DoConnectionAndRenegotiate();
}

TEST_F(FalseStartRenegotiationTest, WithFalseStart) {
  SSL_set_mode(client, SSL_MODE_HANDSHAKE_CUTTHROUGH);
  BIO_set_callback(SSL_get_rbio(server), DumpCallback);
  DoConnectionAndRenegotiate();
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
