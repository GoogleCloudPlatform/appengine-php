// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@google.com (Adam Langley)

#include "base/commandlineflags.h"
#include "openssl/err.h"
#include "testing/base/public/gunit.h"
#include "thread/thread.h"

namespace {

class ErrorThread : public Thread {
 public:
  void Run() {
    ERR_put_error(0, 1, 2, "example.c", 4);
    ERR_add_error_data(1, "malloced string");
  }
};

// MallocedString tests that malloced data in an ERR_STATE isn't leaked.
TEST(ERR, MallocedString) {
  // We do the allocation in another thread to make sure that heapcheck doesn't
  // think that the allocation is still live via a global.
  ErrorThread *const thread = new ErrorThread();
  thread->SetJoinable(true);
  thread->Start();
  thread->Join();
}

}  // namespace

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
