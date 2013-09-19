// Copyright 2011 Google Inc. All Rights Reserved.
// Author: agl@google.com (Adam Langley)

#include "base/atomic_refcount.h"
#include "base/macros.h"
#include "third_party/openssl/ssl.h"

template<typename T>
struct IsAtomic32 {
  enum {
    ok = 0
  };
};

template<>
struct IsAtomic32<Atomic32> {
  enum {
    ok = 1
  };
};

extern "C" {

void GOOGLE_ref_inc(google_ref_count *ref_count) {
  COMPILE_ASSERT(IsAtomic32<typeof(ref_count->count)>::ok == 1,
                 atomic32_type_has_changed);

  base::RefCountInc(&ref_count->count);
}

int GOOGLE_ref_dec(google_ref_count *ref_count) {
  return base::RefCountDec(&ref_count->count);
}

}  // extern "C"
