// Copyright 2010 Google Inc. All Rights Reserved.
// Author: agl@google.com (Adam Langley)

// These tests cover various combinations of the Next Protocol Negotiation
// extension for OpenSSL.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "thread/thread.h"
#include "testing/base/public/gunit.h"

namespace {

DH *global_dh = NULL;

static const char kMagicString[] = "testing";
static const size_t kMagicStringLen = sizeof(kMagicString);

class ServerThread : public Thread {
 public:
  ServerThread(SSL *server)
      : server_(server) {
  }

  void Run() {
    const int ret = SSL_accept(server_);
    if (ret != 1) {
      const int err = SSL_get_error(server_, ret);
      if (err != SSL_ERROR_SSL)
        LOG(FATAL) << "Accept failed: " << ret;

      const long err2 = ERR_get_error();
      char buf[256];
      LOG(FATAL) << "Accept failed: " << ERR_error_string(err2, buf);
    }
    CHECK_EQ(SSL_write(server_, kMagicString, kMagicStringLen),
             kMagicStringLen);
    SSL_shutdown(server_);
  }

 private:
  SSL *const server_;
};

class ConnectionTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    client_bio = BIO_new_socket(fds[0], 0 /* don't take ownership of fd */);
    server_bio = BIO_new_socket(fds[1], 0 /* don't take ownership of fd */);
    client_ctx = SSL_CTX_new(TLSv1_client_method());
    server_ctx = SSL_CTX_new(TLSv1_server_method());
    CHECK_EQ(SSL_CTX_set_cipher_list(client_ctx, "ADH-AES128-SHA"), 1);
    CHECK_EQ(SSL_CTX_set_cipher_list(server_ctx, "ADH-AES128-SHA"), 1);
    SSL_CTX_set_options(client_ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(client_ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_cache_mode(server_ctx, SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_id_context(server_ctx, (const unsigned char *) "test",
                                   4);

    if (!global_dh) {
      global_dh = DH_new();
      CHECK(DH_generate_parameters_ex(global_dh, 32, DH_GENERATOR_2, 0));
      CHECK(DH_generate_key(global_dh));
    }

    SSL_CTX_set_tmp_dh(server_ctx, global_dh);

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

  void ResetForResume() {
    Clear(false /* leave [server|client]_ctx */);

    CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    client_bio = BIO_new_socket(fds[0], 0 /* don't take ownership of fd */);
    server_bio = BIO_new_socket(fds[1], 0 /* don't take ownership of fd */);
    server = SSL_new(server_ctx);
    SSL_set_bio(server, server_bio, server_bio);
    client = SSL_new(client_ctx);
    SSL_set_bio(client, client_bio, client_bio);
  }

  void DoConnection() {
    ServerThread *const thread = new ServerThread(server);
    thread->SetJoinable(true);
    thread->Start();

    const int ret = SSL_connect(client);
    if (ret != 1) {
      const int err = SSL_get_error(client, ret);
      if (err != SSL_ERROR_SSL)
        LOG(FATAL) << "Connect failed: " << ret;

      for (;;) {
        const long err2 = ERR_get_error();
        if (err2 == 0)
          break;
        char buf[256];
        LOG(ERROR) << "OpenSSL error: " << ERR_error_string(err2, buf);
      }
      LOG(FATAL) << "Connection failed";
    }
    char buf[kMagicStringLen];
    CHECK_EQ(SSL_read(client, buf, kMagicStringLen), kMagicStringLen);
    CHECK(memcmp(buf, kMagicString, kMagicStringLen) == 0);

    thread->Join();
    // It's important to call shutdown, otherwise the session is marked as
    // poisoned and won't be used for resumes.
    SSL_shutdown(client);
    delete thread;
  }

  int fds[2];
  BIO *client_bio, *server_bio;
  SSL_CTX *client_ctx, *server_ctx;
  SSL *server, *client;
};


#if 0
// Because the communication happens over a socketpair, packet sniffers can't
// help. Instead you can uncomment this function and call:
// BIO_set_callback(SSL_get_rbio(server), DumpCallback);

long DumpCallback(BIO *bio, int cmd, const char *argp, int argi, long argl,
    long ret) {
  BIO *out = BIO_new_socket(1, 0 /* don't take ownership */);
  if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
    BIO_printf(out, "read from %p [%p] (%d bytes => %ld (0x%lX))\n",
               (void *)bio,argp,argi,ret,ret);
    BIO_dump(out,argp,(int)ret);
    return(ret);
  } else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN)) {
    BIO_printf(out, "write to %p [%p] (%d bytes => %ld (0x%lX))\n",
               (void *)bio,argp,argi,ret,ret);
    BIO_dump(out,argp,(int)ret);
  }
  BIO_free(out);
  return ret;
}
#endif

// Note that this code assumes that this is only a one element list:
static const char kNextProtoString[] = "\x09testproto";
static const size_t kNextProtoStringLen = sizeof(kNextProtoString) - 1;

class NextProtoNegotiationTest : public ConnectionTest {
};

TEST_F(NextProtoNegotiationTest, Neither) {
  // A normal TLS connection
  DoConnection();
}

TEST_F(NextProtoNegotiationTest, NeitherResume) {
  // A normal TLS connection followed by a resume.
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  DoConnection();
  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  ResetForResume();
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  SSL_SESSION_free(sess);
}

static int ClientNextProtoCallback(
    SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg) {
  // The callback only returns the protocol string, rather than a length
  // prefixed set. We assume that kNextProtoString is a one element list and
  // remove the first byte to chop off the length prefix.
  *out = (unsigned char*) kNextProtoString + 1;
  *outlen = kNextProtoStringLen - 1;
  return SSL_TLSEXT_ERR_OK;
}

static int CrashingClientNextProtoCallback(
    SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg) {
  CHECK(false);
}

TEST_F(NextProtoNegotiationTest, ClientOnly) {
  // Only the client offers NPN
  SSL_CTX_set_next_proto_select_cb(client_ctx, ClientNextProtoCallback, NULL);
  DoConnection();

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK(next_proto_neg == NULL);
}

static int ServerNextProtoCallback(
    SSL *s, const unsigned char **data, unsigned int *len, void *arg) {
  *data = (const unsigned char *) kNextProtoString;
  *len = kNextProtoStringLen;
  return SSL_TLSEXT_ERR_OK;
}

static int CrashingServerNextProtoCallback(
    SSL *s, const unsigned char **data, unsigned int *len, void *arg) {
  *data = (const unsigned char *) kNextProtoString;
  CHECK(false);
}

static int ServerErrorCallback(
    SSL *s, const unsigned char **data, unsigned int *len, void *arg) {
  return SSL_TLSEXT_ERR_NOACK;
}

TEST_F(NextProtoNegotiationTest, ServerOnly) {
  // Only the server supports NPN
  SSL_CTX_set_next_protos_advertised_cb(server_ctx, ServerNextProtoCallback,
                                        NULL);
  DoConnection();

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK(next_proto_neg == NULL);
}

TEST_F(NextProtoNegotiationTest, ServerOnlyRejecting) {
  // Only the server supports NPN and the callback returns an error.
  SSL_CTX_set_next_protos_advertised_cb(server_ctx, ServerErrorCallback, NULL);
  DoConnection();

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK(next_proto_neg == NULL);
}

TEST_F(NextProtoNegotiationTest, BothMatch) {
  // Both sides support NPN and match on the protocol.
  SSL_CTX_set_next_protos_advertised_cb(server_ctx, ServerNextProtoCallback,
                                        NULL);
  SSL_CTX_set_next_proto_select_cb(client_ctx, ClientNextProtoCallback, NULL);
  DoConnection();

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK_EQ(next_proto_neg_len, kNextProtoStringLen - 1);
  CHECK(memcmp(next_proto_neg, kNextProtoString + 1,
               kNextProtoStringLen - 1) == 0);

  SSL_get0_next_proto_negotiated(client, &next_proto_neg, &next_proto_neg_len);
  CHECK_EQ(next_proto_neg_len, kNextProtoStringLen - 1);
  CHECK(memcmp(next_proto_neg, kNextProtoString + 1,
               kNextProtoStringLen - 1) == 0);
}

TEST_F(NextProtoNegotiationTest, BothServerRejecting) {
  // Both sides support NPN but the server's callback returns an error.
  SSL_CTX_set_next_protos_advertised_cb(server_ctx, ServerErrorCallback, NULL);
  SSL_CTX_set_next_proto_select_cb(client_ctx, ClientNextProtoCallback, NULL);
  DoConnection();

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK(next_proto_neg == NULL);
}

TEST_F(NextProtoNegotiationTest, BothResume) {
  // Both sides support NPN, match on the protocol and resume the session.
  SSL_CTX_set_next_protos_advertised_cb(server_ctx, ServerNextProtoCallback,
                                        NULL);
  SSL_CTX_set_next_proto_select_cb(client_ctx, ClientNextProtoCallback, NULL);
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  DoConnection();
  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK_EQ(next_proto_neg_len, kNextProtoStringLen - 1);
  CHECK(memcmp(next_proto_neg, kNextProtoString + 1,
               kNextProtoStringLen - 1) == 0);

  ResetForResume();
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  CHECK_EQ(next_proto_neg_len, kNextProtoStringLen - 1);
  CHECK(memcmp(next_proto_neg, kNextProtoString + 1,
               kNextProtoStringLen - 1) == 0);

  SSL_SESSION_free(sess);
}

// TODO(agl): remove this once the core component has been released.
#undef SSL_get_tls_channel_id
#define SSL_get_tls_channel_id(ctx, channel_id, channel_id_len) \
	SSL_ctrl(ctx,SSL_CTRL_GET_CHANNEL_ID,channel_id_len,(void*)channel_id)

class ChannelIDTest : public ConnectionTest {
 public:
  virtual void SetUp() {
    ConnectionTest::SetUp();
    NewKey();
  }

  void NewKey() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    CHECK_EQ(1, EC_KEY_generate_key(key));
    pkey_ = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey_, key);
    EC_KEY_free(key);  // EVP_PKEY takes a reference.

    // A P-256 point in uncompressed form consists of 0x04 (to denote that the
    // point is uncompressed) followed by two, 32-byte field elements.
    static const int kUncompressedP256PointBytes = 65;

    int der_len = i2d_PublicKey(pkey_, NULL);
    CHECK_EQ(kUncompressedP256PointBytes, der_len);
    unsigned char buf[kUncompressedP256PointBytes];
    unsigned char* bufp = buf;
    CHECK_EQ(kUncompressedP256PointBytes, i2d_PublicKey(pkey_, &bufp));
    memcpy(expected_client_id_, buf + 1, sizeof(expected_client_id_));
  }

  virtual void TearDown() {
    ConnectionTest::TearDown();
  }

 protected:
  EVP_PKEY* pkey_;
  unsigned char expected_client_id_[64];
};

TEST_F(ChannelIDTest, Neither) {
  // A normal TLS connection
  DoConnection();
  // We never set the pkey on the client SSL*, so calling SSL_free won't free
  // it.
  EVP_PKEY_free(pkey_);
}

TEST_F(ChannelIDTest, ClientOnly) {
  // Only the client offers Channel ID.
  CHECK_EQ(1, SSL_set1_tls_channel_id(client, pkey_));

  DoConnection();

  unsigned char channel_id[64];
  CHECK_EQ(0, SSL_get_tls_channel_id(server, channel_id, sizeof(channel_id)));
}

TEST_F(ChannelIDTest, ServerOnly) {
  // Only the server supports Channel ID.
  CHECK_EQ(1, SSL_enable_tls_channel_id(server));
  DoConnection();

  unsigned char channel_id[64];
  CHECK_EQ(0, SSL_get_tls_channel_id(server, channel_id, sizeof(channel_id)));

  // We never set the pkey on the client SSL*, so calling SSL_free won't free
  // it.
  EVP_PKEY_free(pkey_);
}

TEST_F(ChannelIDTest, Both) {
  // Both sides support Channel ID.
  CHECK_EQ(1, SSL_set1_tls_channel_id(client, pkey_));
  CHECK_EQ(1, SSL_enable_tls_channel_id(server));
  DoConnection();

  unsigned char channel_id[64];
  CHECK_EQ(sizeof(channel_id), SSL_get_tls_channel_id(server, channel_id,
                                                      sizeof(channel_id)));
  CHECK(0 == memcmp(channel_id, expected_client_id_, sizeof(channel_id)));
}

TEST_F(ChannelIDTest, BothResume) {
  // Both sides support Channel ID. Resume connection.
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  DoConnection();
  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  ResetForResume();
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  CHECK_EQ(1, SSL_set1_tls_channel_id(client, pkey_));
  CHECK_EQ(1, SSL_enable_tls_channel_id(server));
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  unsigned char channel_id[64];
  CHECK_EQ(sizeof(channel_id), SSL_get_tls_channel_id(server, channel_id,
                                                      sizeof(channel_id)));
  CHECK(0 == memcmp(channel_id, expected_client_id_, sizeof(channel_id)));

  SSL_SESSION_free(sess);
}

TEST_F(ChannelIDTest, ResumeAndChangeKey) {
  // Both sides support Channel ID. The Channel ID key is changed between the
  // first connection and the resume connection in order to ensure that the
  // server sees the changed key.
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_set1_tls_channel_id(client, pkey_));
  CHECK_EQ(1, SSL_enable_tls_channel_id(server));
  DoConnection();

  unsigned char channel_id[64];
  CHECK_EQ(sizeof(channel_id), SSL_get_tls_channel_id(server, channel_id,
                                                      sizeof(channel_id)));
  CHECK(0 == memcmp(channel_id, expected_client_id_, sizeof(channel_id)));

  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  ResetForResume();
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  NewKey();
  CHECK_EQ(1, SSL_set1_tls_channel_id(client, pkey_));
  CHECK_EQ(1, SSL_enable_tls_channel_id(server));
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  CHECK_EQ(sizeof(channel_id), SSL_get_tls_channel_id(server, channel_id,
                                                      sizeof(channel_id)));
  CHECK(0 == memcmp(channel_id, expected_client_id_, sizeof(channel_id)));

  SSL_SESSION_free(sess);
}

class ALPNTest : public ConnectionTest { };

// Note that this code assumes that this is only a one element list:
static const unsigned char kALPNProtos[] = "\x09testproto";
static const size_t kALPNProtosLen = sizeof(kALPNProtos) - 1;

TEST_F(ALPNTest, Neither) {
  // A normal TLS connection
  DoConnection();
}

TEST_F(ALPNTest, NeitherResume) {
  // A normal TLS connection followed by a resume.
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  DoConnection();
  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  ResetForResume();
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  SSL_SESSION_free(sess);
}

TEST_F(ALPNTest, ClientOnly) {
  // Only the client offers ALPN.
  ASSERT_EQ(0, SSL_CTX_set_alpn_protos(client_ctx, kALPNProtos,
                                       kALPNProtosLen));
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(server, &selected, &selected_len);
  EXPECT_EQ(0u, selected_len);
}

static int ServerALPNCallback(SSL *s,
                              const unsigned char **out,
                              unsigned char *outlen,
                              const unsigned char *in,
                              unsigned int inlen,
                              void *arg) {
  *out = const_cast<unsigned char*>(in + 1);
  *outlen = *in;
  return SSL_TLSEXT_ERR_OK;
}

static int ServerALPNErrorCallback(SSL *s,
                                   const unsigned char **out,
                                   unsigned char *outlen,
                                   const unsigned char *in,
                                   unsigned int inlen,
                                   void *arg) {
  return SSL_TLSEXT_ERR_NOACK;
}

TEST_F(ALPNTest, ServerOnly) {
  // Only the server supports ALPN.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNCallback, NULL);
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(server, &selected, &selected_len);
  EXPECT_EQ(0u, selected_len);
}

TEST_F(ALPNTest, ServerOnlyRejecting) {
  // Only the server supports ALPN and the callback returns an error.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNErrorCallback, NULL);
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(server, &selected, &selected_len);
  EXPECT_EQ(0u, selected_len);
}

TEST_F(ALPNTest, Both) {
  // Both sides support ALPN and match on the protocol.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNCallback, NULL);
  ASSERT_EQ(0, SSL_set_alpn_protos(client, kALPNProtos, kALPNProtosLen));
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(server, &selected, &selected_len);
  EXPECT_EQ(kALPNProtosLen - 1, selected_len);
  EXPECT_EQ(0, memcmp(selected, kALPNProtos + 1, selected_len));

  SSL_get0_alpn_selected(client, &selected, &selected_len);
  EXPECT_EQ(kALPNProtosLen - 1, selected_len);
  EXPECT_EQ(0, memcmp(selected, kALPNProtos + 1, selected_len));
}

TEST_F(ALPNTest, BothAndNPN) {
  // Both sides support ALPN and NPN. Only ALPN should be negotiated.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNCallback, NULL);
  ASSERT_EQ(0, SSL_set_alpn_protos(client, kALPNProtos, kALPNProtosLen));
  SSL_CTX_set_next_protos_advertised_cb(
      server_ctx, CrashingServerNextProtoCallback, NULL);
  SSL_CTX_set_next_proto_select_cb(
      client_ctx, CrashingClientNextProtoCallback, NULL);
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(client, &selected, &selected_len);
  EXPECT_EQ(kALPNProtosLen - 1, selected_len);
  EXPECT_EQ(0, memcmp(selected, kALPNProtos + 1, selected_len));

  const unsigned char *next_proto_neg;
  unsigned next_proto_neg_len;
  SSL_get0_next_proto_negotiated(server, &next_proto_neg, &next_proto_neg_len);
  EXPECT_EQ(0u, next_proto_neg_len);

  SSL_get0_next_proto_negotiated(client, &next_proto_neg, &next_proto_neg_len);
  EXPECT_EQ(0u, next_proto_neg_len);
}

TEST_F(ALPNTest, BothServerRejecting) {
  // Both sides support ALPN but the server's callback returns an error.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNErrorCallback, NULL);
  ASSERT_EQ(0, SSL_set_alpn_protos(client, kALPNProtos, kALPNProtosLen));
  DoConnection();

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(server, &selected, &selected_len);
  EXPECT_EQ(0u, selected_len);

  SSL_get0_alpn_selected(client, &selected, &selected_len);
  EXPECT_EQ(0u, selected_len);
}

TEST_F(ALPNTest, BothResume) {
  // Both sides support ALPN, match on the protocol and resume the session.
  SSL_CTX_set_alpn_select_cb(server_ctx, ServerALPNCallback, NULL);
  ASSERT_EQ(0, SSL_set_alpn_protos(client, kALPNProtos, kALPNProtosLen));
  CHECK_EQ(0, SSL_CTX_sess_accept(server_ctx));
  DoConnection();
  SSL_SESSION *sess = SSL_get1_session(client);
  CHECK_EQ(1, SSL_CTX_sess_accept(server_ctx));

  const unsigned char *selected;
  unsigned selected_len;
  SSL_get0_alpn_selected(client, &selected, &selected_len);
  EXPECT_EQ(kALPNProtosLen - 1, selected_len);
  EXPECT_EQ(0, memcmp(selected, kALPNProtos + 1, selected_len));

  ResetForResume();
  ASSERT_EQ(0, SSL_set_alpn_protos(client, kALPNProtos, kALPNProtosLen));
  CHECK_EQ(0, SSL_CTX_sess_hits(server_ctx));
  SSL_set_session(client, sess);
  DoConnection();
  CHECK_EQ(2, SSL_CTX_sess_accept(server_ctx));
  CHECK_EQ(1, SSL_CTX_sess_hits(server_ctx));
  CHECK(server->hit);

  SSL_get0_alpn_selected(client, &selected, &selected_len);
  EXPECT_EQ(kALPNProtosLen - 1, selected_len);
  EXPECT_EQ(0, memcmp(selected, kALPNProtos + 1, selected_len));

  SSL_SESSION_free(sess);
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
