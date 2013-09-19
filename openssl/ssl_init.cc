// Copyright 2008 Google Inc. All Rights Reserved.
// Author: mschilder@google.com (Marius Schilder)
//
// OpenSSL has a couple of initialization functions
// that need calling before using the library.
// Moving these calls to a module initializer gets
// these functions called by InitGoogle().

#include "base/googleinit.h"
#include "base/logging.h"
#include "third_party/openssl/ssl.h"

namespace {

void InitSSL() {
  CHECK_EQ(SSL_library_init(), 1);
  SSL_load_error_strings();
}

}  // namespace

REGISTER_MODULE_INITIALIZER(OpenSSLInit, { InitSSL(); });
