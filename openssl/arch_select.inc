/*
 * This file is prepended to all platform-specific source files and,
 * effectively, excludes from compilation files that are not needed on the
 * target platform.
 *
 * OPENSSL_$(arch)_SOURCE macros are generated in one of the BUILD genrule()
 * targets.
 */
#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER) || \
    defined(THREAD_SANITIZER)
#define OPENSSL_SANITIZER
#endif

#if (defined(OPENSSL_SANITIZER) && defined(OPENSSL_GENERIC_SOURCE)) || \
    (!defined(OPENSSL_SANITIZER) &&                                    \
     ((defined(__x86_64__) && defined(OPENSSL_X86_64_SOURCE)) ||       \
      (defined(__i386__) && defined(OPENSSL_586_SOURCE)) ||            \
      (defined(__powerpc64__) && defined(OPENSSL_POWERPC64_SOURCE)) || \
      (defined(__arm__) && defined(OPENSSL_GENERIC_SOURCE))))
