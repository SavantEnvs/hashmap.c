// Harness for hashmap.c's exported hash functions: hashmap_sip,
// hashmap_murmur and hashmap_xxhash3.
//
// Input: 16 bytes of seeds, one byte choosing an alignment offset (0..7), then
// the data to hash. The data is copied into an exact-size heap buffer (so ASan
// sees any read past `len`) and into a second buffer at the chosen offset from
// an 8-aligned address (unaligned loads, cf. upstream ad4dfbc; the hash API
// takes any `const void *`). Each hash must be a pure function of
// (data, len, seeds): both copies must hash equal, and hashing twice must agree.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

typedef uint64_t (*hash_fn)(const void *, size_t, uint64_t, uint64_t);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 17) return -1;
  uint64_t seed0, seed1;
  memcpy(&seed0, data, 8);
  memcpy(&seed1, data + 8, 8);
  size_t offset = data[16] & 7;
  data += 17;
  size -= 17;

  uint8_t *exact = malloc(size ? size : 1);
  uint8_t *odd_base = malloc(size + offset + 1);  // malloc: 8-aligned or more
  if (!exact || !odd_base) abort();
  uint8_t *odd = odd_base + offset;
  memcpy(exact, data, size);
  memcpy(odd, data, size);

  static const hash_fn fns[] = {hashmap_sip, hashmap_murmur, hashmap_xxhash3};
  static const char *names[] = {"sip", "murmur", "xxhash3"};
  for (int i = 0; i < 3; i++) {
    uint64_t a = fns[i](exact, size, seed0, seed1);
    uint64_t b = fns[i](odd, size, seed0, seed1);
    uint64_t c = fns[i](exact, size, seed0, seed1);
    if (a != b || a != c) {
      fprintf(stderr, "hashmap_%s is not deterministic: %016llx %016llx %016llx\n",
              names[i], (unsigned long long)a, (unsigned long long)b,
              (unsigned long long)c);
      abort();
    }
  }
  free(exact);
  free(odd_base);
  return 0;
}
