// Copyright 2008 Google Inc. All Rights Reserved.
// Author: mschilder@google.com (Marius Schilder)
//
// Openssl is not thread safe by default. One needs to pass in
// a callback function providing access to an array of mutex.s.
// By moving this code to a module initializer, we make sure
// this gets done by InitGoogle().

#include <assert.h>

#include <map>
#include <string>

#include "base/commandlineflags.h"
#include "base/googleinit.h"
#include "base/logging.h"
#include "base/mutex.h"
#include "base/per_thread.h"
#include "base/port.h"
#include "third_party/openssl/crypto.h"
#include "third_party/openssl/ecdsa.h"
#include "third_party/openssl/engine.h"
#include "third_party/openssl/err.h"
#include "third_party/openssl/evp.h"
#include "third_party/openssl/rand.h"

// The OpenSSL ERR implementation can be overridden by passing in a struct of
// function pointers. (This is intended to allow ENGINEs ,which may be linked
// with their own copy of OpenSSL, to avoid duplicating the `global' OpenSSL
// state.) Therefore we have to copy and paste the following from
// crypto/err/err.c.
struct st_ERR_FNS {
  /* Works on the "error_hash" string table */
  LHASH_OF(ERR_STRING_DATA) *(*cb_err_get)(int create);
  void (*cb_err_del)(void);
  ERR_STRING_DATA *(*cb_err_get_item)(const ERR_STRING_DATA *);
  ERR_STRING_DATA *(*cb_err_set_item)(ERR_STRING_DATA *);
  ERR_STRING_DATA *(*cb_err_del_item)(ERR_STRING_DATA *);
  /* Works on the "thread_hash" error-state table */
  LHASH_OF(ERR_STATE) *(*cb_thread_get)(int create);
  void (*cb_thread_release)(LHASH_OF(ERR_STATE) **hash);
  ERR_STATE *(*cb_thread_get_item)(const ERR_STATE *);
  ERR_STATE *(*cb_thread_set_item)(ERR_STATE *);
  void (*cb_thread_del_item)(const ERR_STATE *);
  /* Returns the next available error "library" numbers */
  int (*cb_get_next_lib)(void);
};

namespace {

struct MutexLine {
  Mutex mu;
} CACHELINE_ALIGNED;

MutexLine* g_crypto_locks;
int g_n_crypto_locks;

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4))
#if defined(__SUPPORT_TS_ANNOTATION__) && (!defined(SWIG))
#define NO_THREAD_SAFETY_NOR_INLINING \
    __attribute__((no_thread_safety_analysis,noinline))
#else
// When compiling with GCC without thread-safety annotations.
#define NO_THREAD_SAFETY_NOR_INLINING \
    __attribute__((noinline))
#endif
#elif defined(__clang__) && (!defined(SWIG))
#define NO_THREAD_SAFETY_NOR_INLINING \
    __attribute__((no_thread_safety_analysis,noinline))
#else
#define NO_THREAD_SAFETY_NOR_INLINING  // no-op
#endif

// OpenSSL performs locking by making a callback and naming the lock by number.
// This means that all the lock contention appears to come from the callback
// function, no matter which OpenSSL lock is actually the problem. Thus, for
// some of the hotter locks, we do the locking in a specific function so that
// the profiling tools can identify the lock.
//
// Sadly, templates don't work for this as the profiling tools combine all
// template instantiations into one. Also, we have to disable inlining
// otherwise GCC will undo all this work!
//
// This is the locking function that is instantiated for each lock that we
// handle in this way. In cpprof, these will appear as, say
// ::CRYPTO_LOCK_ERR_see_crypto_init_cc.

#define F(lock) \
void lock##_see_crypto_init_cc(int mode, const char *file, int line) \
    NO_THREAD_SAFETY_NOR_INLINING; \
\
void lock##_see_crypto_init_cc(int mode, const char *file, int line) { \
  Mutex& mutex = g_crypto_locks[lock].mu; \
\
  switch (mode) { \
    case CRYPTO_LOCK|CRYPTO_WRITE: \
      DCHECK((mutex.AssertNotHeld(), true)); \
      mutex.WriterLock(); \
      break; \
    case CRYPTO_UNLOCK|CRYPTO_WRITE: \
      DCHECK((mutex.AssertHeld(), true)); \
      mutex.WriterUnlock(); \
      break; \
    case CRYPTO_LOCK|CRYPTO_READ: \
      DCHECK((mutex.AssertNotHeld(), true)); \
      mutex.ReaderLock(); \
      break; \
    case CRYPTO_UNLOCK|CRYPTO_READ: \
      DCHECK((mutex.AssertReaderHeld(), true)); \
      mutex.ReaderUnlock(); \
      break; \
    default: \
      LOG(FATAL) << "bad mode " << mode \
                 << " @" << file << "[" << line << "]"; \
  } \
}

// This is the list of locks that are handled in this fashion. These are the
// locks that are hit in normal GFE processing of an SSL connection:

#define FOR_EACH_SPECIFICALLY_INSTRUMENTED_LOCK \
F(CRYPTO_LOCK_BIO) \
F(CRYPTO_LOCK_ERR) \
F(CRYPTO_LOCK_EVP_PKEY) \
F(CRYPTO_LOCK_EX_DATA) \
F(CRYPTO_LOCK_RAND) \
F(CRYPTO_LOCK_RAND2) \
F(CRYPTO_LOCK_RSA_BLINDING) \
F(CRYPTO_LOCK_SSL) \
F(CRYPTO_LOCK_SSL_CERT) \
F(CRYPTO_LOCK_SSL_CTX) \
F(CRYPTO_LOCK_SSL_SESSION) \
F(CRYPTO_LOCK_X509)

// Since we defined |F|, above, to be the locking function, this will create a
// different locking function for each of those locks:

FOR_EACH_SPECIFICALLY_INSTRUMENTED_LOCK
#undef F

// This function is marked as NO_THREAD_SAFETY_ANALYSIS because it is
// overloaded as lock and unlock functions of an array of mutex locks
// and our analysis cannot sanely analyze it.
void CryptoLockingCallback(int mode, int type,
                           const char *file, int line)
    NO_THREAD_SAFETY_ANALYSIS {
  assert(type >= 0);
  assert(type < g_n_crypto_locks);

  // See the comments above about why we handle some locks in their own
  // function.
#define F(lock) \
  if (type == lock) { \
    return lock##_see_crypto_init_cc(mode, file, line); \
  }
FOR_EACH_SPECIFICALLY_INSTRUMENTED_LOCK
#undef F

  Mutex& mutex = g_crypto_locks[type].mu;
  switch (mode) {
    case CRYPTO_LOCK|CRYPTO_WRITE:
      DCHECK((mutex.AssertNotHeld(), true));
      mutex.WriterLock();
      break;
    case CRYPTO_UNLOCK|CRYPTO_WRITE:
      DCHECK((mutex.AssertHeld(), true));
      mutex.WriterUnlock();
      break;
    case CRYPTO_LOCK|CRYPTO_READ:
      DCHECK((mutex.AssertNotHeld(), true));
      mutex.ReaderLock();
      break;
    case CRYPTO_UNLOCK|CRYPTO_READ:
      DCHECK((mutex.AssertReaderHeld(), true));
      mutex.ReaderUnlock();
      break;
    default:
      LOG(FATAL) << "bad mode " << mode
                 << " @" << file << "[" << line << "]";
  }
}

// CryptoThreadID is called by OpenSSL to handle CRYPTO_thread_id calls, which
// appears to be unused.
unsigned long CryptoThreadID(void) {
  return static_cast<unsigned long>(pthread_self());
}

// CryptoNewThreadID is called by OpenSSL to handle CRYPTO_THREADID_current
// calls.
void CryptoNewThreadID(CRYPTO_THREADID* tid) {
  CRYPTO_THREADID_set_numeric(tid, CryptoThreadID());
}

// GetErrorStringTable returns the singleton error->string hash. However, this
// is only used by `openssl errstr` and, since we don't really want to use an
// LHASH, we return NULL.
LHASH_OF(ERR_STRING_DATA)* GetErrorStringTable(int create) {
  LOG(FATAL) << "Error string table not supported in google3";
  return NULL;
}

// DeleteErrorStringTable is called by ERR_free_strings to cleanup at the end
// of a process. We don't care about this so it's a no-op.
void DeleteErrorStringTable() {
}

Mutex g_error_strings_mutex(base::LINKER_INITIALIZED);
map<unsigned long, const char*>* g_error_strings;

// SetErrorString is used to store a mapping from |err->error| to
// |err->string|.
ERR_STRING_DATA* SetErrorString(ERR_STRING_DATA* err) {
  MutexLock locked(&g_error_strings_mutex);
  (*g_error_strings)[err->error] = err->string;
  return err;
}

// DeleteErrorString is only called by ERR_unload_strings in order to free up
// memory before exiting.
ERR_STRING_DATA* DeleteErrorString(ERR_STRING_DATA* err) {
  MutexLock locked(&g_error_strings_mutex);

  auto i = g_error_strings->find(err->error);
  if (i == g_error_strings->end())
    return NULL;
  g_error_strings->erase(i);
  return err;
}

// GetErrorString is used to lookup a string set by SetErrorString. On entry
// |err->error| is set.
ERR_STRING_DATA* GetErrorString(const ERR_STRING_DATA* err) {
  ReaderMutexLock locked(&g_error_strings_mutex);

  auto i = g_error_strings->find(err->error);
  if (i == g_error_strings->end())
    return NULL;

  // OpenSSL expects us to store an ERR_STRING_DATA and return it, but it only
  // grabs the |string| member from it so we can reuse the one that it gave us.
  ERR_STRING_DATA* mutable_err = const_cast<ERR_STRING_DATA*>(err);
  mutable_err->string = i->second;
  return mutable_err;
}

// GetThreadErrorTable is called by ERR_get_err_state_table which, in turn, is
// never called by anything. Because we want to implement the thread local
// error state using TLS, we just return NULL.
LHASH_OF(ERR_STATE)* GetThreadErrorTable(int create) {
  LOG(FATAL) << "Thread error table not supported in google3";
  return NULL;
}

// ReleaseThreadErrorTable is called to unlock the thread->state table returned
// by GetThreadErrorTable. Since we don't have one, this is a no-op.
void ReleaseThreadErrorTable(LHASH_OF(ERR_STATE) **hash) {
}

PerThread::Key g_error_state_key = PerThread::kInvalid;

// GetThreadErrorState is used to return the ERR_STATE object for the current
// thread. On entry |state->tid| contains the current thread's TID, which we
// ignore because we're using PerThread.
ERR_STATE* GetThreadErrorState(const ERR_STATE* state) {
  void** err_state_ptr = PerThread::Data(g_error_state_key);
  ERR_STATE* thread_err_state = reinterpret_cast<ERR_STATE*>(*err_state_ptr);
  if (thread_err_state != NULL) {
    DCHECK_EQ(state->tid.val, thread_err_state->tid.val)
        << "Accessing OpenSSL error state for different thread";
  }
  return thread_err_state;
}

// SetThreadErrorState is used to set the ERR_STATE object for the current
// thread. On entry |state->tid| contains the current thread's TID, which we
// ignore because we're using PerThread.
ERR_STATE* SetThreadErrorState(ERR_STATE* state) {
  DCHECK_EQ(state->tid.val, CryptoThreadID())
      << "Setting OpenSSL state for a different thread";
  void** err_state_ptr = PerThread::Data(g_error_state_key);
  ERR_STATE* old = reinterpret_cast<ERR_STATE*>(*err_state_ptr);
  *err_state_ptr = state;
  return old;
}

// FreeErrorState is called when a thread exits with an ERR_STATE set by
// SetThreadErrorState and also when we need to free an error state in
// DeleteThreadErrorState.
void FreeErrorState(void* ptr) {
  // Most of the strings in ERR_STATE point to shared strings. However, in some
  // error paths, custom strings can be set. This code mimics ERR_STATE_free in
  // crypto/err/err.c, but that function is static.
  ERR_STATE* const state = reinterpret_cast<ERR_STATE*>(ptr);
  for (int i = 0; i < ERR_NUM_ERRORS; i++) {
    if (state->err_data[i] != NULL &&
        (state->err_data_flags[i] & ERR_TXT_MALLOCED)) {
      OPENSSL_free(state->err_data[i]);
    }
  }
  OPENSSL_free(state);
}

// DeleteThreadErrorState is used to remove the error state for |state->tid|.
// Since PerThread takes care of cleaning up when a thread exits, we don't need
// to do this, but we free it just in case any code is relying on this to clean
// up the error state within a single thread.
void DeleteThreadErrorState(const ERR_STATE *state) {
  void** err_state_ptr = PerThread::Data(g_error_state_key);
  if (*err_state_ptr) {
    DCHECK_EQ(state->tid.val, CryptoThreadID())
        << "Deleting OpenSSL state for a different thread";
  }
  FreeErrorState(*err_state_ptr);
  *err_state_ptr = NULL;
}

// GetNextLibraryId is called, concurrently, by different parts of OpenSSL the
// first time that they are used, to allocate a library error code for
// themselves. This is rarely called and so we simply use a Mutex.
int GetNextLibraryId() {
  static Mutex next_library_id_mutex(base::LINKER_INITIALIZED);
  static int next_library_id = ERR_LIB_USER;

  next_library_id_mutex.Lock();
  const int ret = next_library_id;
  next_library_id++;
  next_library_id_mutex.Unlock();
  return ret;
}

const st_ERR_FNS g_google3_err_impl = {
  GetErrorStringTable,
  DeleteErrorStringTable,
  GetErrorString,
  SetErrorString,
  DeleteErrorString,
  GetThreadErrorTable,
  ReleaseThreadErrorTable,
  GetThreadErrorState,
  SetThreadErrorState,
  DeleteThreadErrorState,
  GetNextLibraryId,
};

void InitCrypto() {
  PerThread::Allocate(&g_error_state_key, FreeErrorState);

  g_n_crypto_locks = CRYPTO_num_locks();
  g_crypto_locks = new MutexLine[g_n_crypto_locks];

  CRYPTO_THREADID_set_callback(CryptoNewThreadID);
  CRYPTO_set_id_callback(CryptoThreadID);
  CRYPTO_set_locking_callback(CryptoLockingCallback);

  g_error_strings = new map<unsigned long, const char*>;
  ERR_set_implementation(&g_google3_err_impl);

  OpenSSL_add_all_algorithms(); // initialize OpenSSL EVP library

  ENGINE_register_all_ciphers();

  ERR_load_crypto_strings();

  // These calls set a global variable containing the default method for
  // different functions. We call them in order to avoid a race later on.

  (void) DH_get_default_method();
  (void) DSA_get_default_method();
  (void) ECDH_get_default_method();
  (void) ECDSA_get_default_method();
  (void) RAND_status();
  (void) UI_get_default_method();
}

}  // namespace

REGISTER_MODULE_INITIALIZER(OpenSSLCryptoInit, { InitCrypto(); });
