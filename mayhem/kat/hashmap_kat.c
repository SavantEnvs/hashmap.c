// Known-answer probe for mayhem/test.sh: prints values computed by hashmap.c
// for fixed inputs, one "name value" per line. test.sh compares them to
// expected values (SipHash-2-4 reference vectors, plus map behavior).
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "hashmap.h"

static uint64_t h(const void *item, uint64_t s0, uint64_t s1) {
  return hashmap_sip(item, sizeof(int), s0, s1);
}
static int cmp(const void *a, const void *b, void *u) {
  (void)u;
  return memcmp(a, b, sizeof(int));
}
static int sum;
static bool add(const void *item, void *u) {
  (void)u;
  sum += *(const int *)item;
  return true;
}

int main(void) {
  uint8_t in[64];
  for (int i = 0; i < 64; i++) in[i] = (uint8_t)i;
  // SipHash-2-4 key 00..0f as two little-endian 64-bit halves.
  uint64_t k0 = 0x0706050403020100ULL, k1 = 0x0f0e0d0c0b0a0908ULL;
  printf("sip0 %016" PRIx64 "\n", hashmap_sip(in, 0, k0, k1));
  printf("sip15 %016" PRIx64 "\n", hashmap_sip(in, 15, k0, k1));
  printf("sip63 %016" PRIx64 "\n", hashmap_sip(in, 63, k0, k1));
  printf("murmur %016" PRIx64 "\n", hashmap_murmur("hashmap", 7, 1, 2));
  printf("xxh3_short %016" PRIx64 "\n", hashmap_xxhash3("hashmap", 7, 1, 2));
  printf("xxh3_long %016" PRIx64 "\n", hashmap_xxhash3(in, 64, 1, 2));

  struct hashmap *m = hashmap_new(sizeof(int), 0, 0, 0, h, cmp, NULL, NULL);
  for (int i = 1; i <= 1000; i++) hashmap_set(m, &i);
  for (int i = 1; i <= 1000; i += 2) hashmap_delete(m, &i);
  int k = 500, miss = 501;
  const int *got = hashmap_get(m, &k);
  printf("count %zu\n", hashmap_count(m));
  printf("get500 %d\n", got ? *got : -1);
  printf("get501 %s\n", hashmap_get(m, &miss) ? "found" : "missing");
  hashmap_scan(m, add, NULL);
  printf("sum %d\n", sum);
  hashmap_free(m);
  return 0;
}
