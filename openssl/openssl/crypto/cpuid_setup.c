/* This file exists in order to call OPENSSL_cpuid_setup at process startup.
 * Previously it was inserted into the .init section but this meant that it was
 * run too early for some tools. See b/5359520 */

extern void OPENSSL_cpuid_setup();

static void call_cpuid_setup() __attribute__((constructor));

static void call_cpuid_setup() {
  OPENSSL_cpuid_setup();
}
