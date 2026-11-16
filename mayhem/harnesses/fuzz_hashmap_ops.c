// Stateful op-sequence harness for hashmap.c's public API.
//
// The input is a small header (map configuration) followed by an op stream.
// Every op is applied to the real hashmap AND to a trivially-correct array
// model; any disagreement (count, get/set/delete results, scan/iter contents,
// elfree calls) aborts. Memory errors inside hashmap.c are caught by ASan/UBSan.
//
// Items are `elsize` bytes. The first `keylen` bytes are the key (hash and
// compare only look at them), the rest is a value, so replacing an item is
// observable. The hash callback is a function of the key bytes only, so it is
// consistent with compare (hashmap.h contract).
//
// State kept across inputs: none. All globals below are reset at the start of
// every input, and the map uses its own per-map allocator (never the
// process-global hashmap_set_allocator).
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

#define MAX_ELSIZE 64
#define MAX_OPS 2048
#define MAX_ITEMS MAX_OPS

struct reader {
  const uint8_t *p;
  size_t n;
};

static bool take(struct reader *r, void *out, size_t len) {
  if (r->n < len) return false;
  memcpy(out, r->p, len);
  r->p += len;
  r->n -= len;
  return true;
}

static bool take8(struct reader *r, uint8_t *v) { return take(r, v, 1); }

// --- per-input configuration (reset every input) --------------------------
static size_t g_elsize, g_keylen;
static int g_hashsel;
static uint64_t g_seed0, g_seed1;
static uint32_t g_failmask;  // allocation #k fails iff bit k is set (k < 32)
static unsigned g_nallocs;
static size_t g_elfree_calls;

// --- model -----------------------------------------------------------------
static uint8_t g_model[MAX_ITEMS][MAX_ELSIZE];
static size_t g_n;

#define CHECK(c)                                                         \
  do {                                                                   \
    if (!(c)) {                                                          \
      fprintf(stderr, "model mismatch: %s (line %d)\n", #c, __LINE__);   \
      abort();                                                           \
    }                                                                    \
  } while (0)

static long model_find(const void *item) {
  for (size_t i = 0; i < g_n; i++)
    if (memcmp(g_model[i], item, g_keylen) == 0) return (long)i;
  return -1;
}

static void model_remove(size_t i) {
  memmove(g_model[i], g_model[g_n - 1], g_elsize);
  g_n--;
}

// --- callbacks -------------------------------------------------------------
static uint64_t item_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  switch (g_hashsel) {
    case 0: return hashmap_sip(item, g_keylen, seed0, seed1);
    case 1: return hashmap_murmur(item, g_keylen, seed0, seed1);
    case 2: return hashmap_xxhash3(item, g_keylen, seed0, seed1);
    default: return ((const uint8_t *)item)[0] & 3;  // heavy collisions
  }
}

static int item_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  return memcmp(a, b, g_keylen);
}

static void item_free(void *item) {
  (void)item;
  g_elfree_calls++;
}

static void *fail_malloc(size_t sz) {
  unsigned k = g_nallocs++;
  if (k < 32 && (g_failmask >> k) & 1) return NULL;
  return malloc(sz);
}

static void *pass_realloc(void *p, size_t sz) { return realloc(p, sz); }
static void pass_free(void *p) { free(p); }

// Checks that an item the map handed out is one the model holds, byte for byte.
static void check_known(const void *item) {
  long i = model_find(item);
  CHECK(i >= 0);
  CHECK(memcmp(g_model[i], item, g_elsize) == 0);
}

struct scan_ctx {
  size_t seen, stop_after;
};

static bool scan_cb(const void *item, void *udata) {
  struct scan_ctx *c = udata;
  check_known(item);
  c->seen++;
  return c->seen < c->stop_after;
}

// Build an op's item: either fresh bytes from the input, or an existing key
// from the model (so get/set/delete hit) with a fresh value part.
static bool make_item(struct reader *r, bool from_model, uint8_t *item) {
  if (from_model && g_n > 0) {
    uint8_t idx[2];
    if (!take(r, idx, 2)) return false;
    memcpy(item, g_model[((size_t)idx[0] << 8 | idx[1]) % g_n], g_elsize);
    if (g_elsize > g_keylen && !take(r, item + g_keylen, g_elsize - g_keylen))
      return false;
    return true;
  }
  return take(r, item, g_elsize);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct reader r = {data, size};
  uint8_t h[8];
  if (!take(&r, h, sizeof h)) return -1;

  g_elsize = 1 + h[0] % MAX_ELSIZE;  // includes sizes that aren't multiples of 8
  g_keylen = 1 + h[1] % g_elsize;
  g_hashsel = h[2] & 3;
  bool use_elfree = h[2] & 4;
  bool use_failing_alloc = h[2] & 8;
  bool with_hash_ops = h[2] & 16;
  size_t cap = ((size_t)h[3] << 8 | h[4]) % 1025;
  g_seed0 = h[5];
  g_seed1 = (uint64_t)h[6] << 32 | h[7];
  g_failmask = 0;
  if (use_failing_alloc && !take(&r, &g_failmask, sizeof g_failmask)) return -1;
  g_nallocs = 0;
  g_elfree_calls = 0;
  g_n = 0;

  struct hashmap *map;
  if (use_failing_alloc)
    map = hashmap_new_with_allocator(fail_malloc, pass_realloc, pass_free,
                                     g_elsize, cap, g_seed0, g_seed1, item_hash,
                                     item_compare, use_elfree ? item_free : NULL,
                                     NULL);
  else
    map = hashmap_new(g_elsize, cap, g_seed0, g_seed1, item_hash, item_compare,
                      use_elfree ? item_free : NULL, NULL);
  if (!map) {
    CHECK(use_failing_alloc);
    return 0;
  }

  uint8_t item[MAX_ELSIZE];
  for (int ops = 0; ops < MAX_OPS; ops++) {
    uint8_t op;
    if (!take8(&r, &op)) break;
    bool from_model = op & 0x80;
    bool hashed = with_hash_ops && (op & 0x40);
    switch (op & 0x0f) {
      case 0: case 1: case 2: {  // set
        if (!make_item(&r, from_model, item)) goto done;
        const void *ret = hashed ? hashmap_set_with_hash(map, item, item_hash(item, g_seed0, g_seed1))
                                 : hashmap_set(map, item);
        long i = model_find(item);
        if (ret == NULL) {
          if (hashmap_oom(map)) break;  // resize failed: map unchanged
          CHECK(i < 0);
          CHECK(g_n < MAX_ITEMS);
          memcpy(g_model[g_n++], item, g_elsize);
        } else {
          CHECK(!hashmap_oom(map));
          CHECK(i >= 0);
          CHECK(memcmp(ret, g_model[i], g_elsize) == 0);
          memcpy(g_model[i], item, g_elsize);
        }
        break;
      }
      case 3: case 4: {  // get
        if (!make_item(&r, from_model, item)) goto done;
        const void *ret = hashed ? hashmap_get_with_hash(map, item, item_hash(item, g_seed0, g_seed1))
                                 : hashmap_get(map, item);
        long i = model_find(item);
        if (i < 0) {
          CHECK(ret == NULL);
        } else {
          CHECK(ret != NULL);
          CHECK(memcmp(ret, g_model[i], g_elsize) == 0);
        }
        break;
      }
      case 5: case 6: {  // delete
        if (!make_item(&r, from_model, item)) goto done;
        const void *ret = hashed ? hashmap_delete_with_hash(map, item, item_hash(item, g_seed0, g_seed1))
                                 : hashmap_delete(map, item);
        long i = model_find(item);
        if (i < 0) {
          CHECK(ret == NULL);
        } else {
          CHECK(ret != NULL);
          CHECK(memcmp(ret, g_model[i], g_elsize) == 0);
          model_remove((size_t)i);
        }
        break;
      }
      case 7: {  // clear
        size_t before = g_elfree_calls;
        hashmap_clear(map, op & 0x10);
        if (use_elfree) CHECK(g_elfree_calls - before == g_n);
        g_n = 0;
        break;
      }
      case 8: {  // scan, optionally stopping early
        uint8_t stop;
        if (!take8(&r, &stop)) goto done;
        struct scan_ctx c = {0, stop ? stop : SIZE_MAX};
        bool completed = hashmap_scan(map, scan_cb, &c);
        if (completed) {
          CHECK(c.seen == g_n);
        } else {
          CHECK(c.seen == stop && stop <= g_n);
        }
        break;
      }
      case 9: {  // iter
        size_t i = 0, seen = 0;
        void *it;
        while (hashmap_iter(map, &i, &it)) {
          check_known(it);
          seen++;
        }
        CHECK(seen == g_n);
        break;
      }
      case 10: {  // probe
        uint64_t pos;
        if (!take(&r, &pos, sizeof pos)) goto done;
        const void *it = hashmap_probe(map, pos);
        if (it) check_known(it);
        break;
      }
      case 11: {  // direct bucket access, including out-of-range indexes
        uint16_t idx;
        if (!take(&r, &idx, sizeof idx)) goto done;
        size_t nb = hashmap_nbuckets(map);
        CHECK(nb && (nb & (nb - 1)) == 0 && nb > g_n);
        const void *it = hashmap_bucket_item(map, idx);
        if (idx >= nb) CHECK(it == NULL);
        if (it) check_known(it);
        break;
      }
      case 12: {  // load factor: raw byte / 100, NaN for 0xff (clamped upstream)
        uint8_t b;
        if (!take8(&r, &b)) goto done;
        hashmap_set_load_factor(map, b == 0xff ? __builtin_nan("") : b / 100.0);
        break;
      }
      case 13: {  // grow power; 0 clamps to 1. Kept <= 4 so a single grow
                  // stays within the fuzzer's memory budget.
        uint8_t b;
        if (!take8(&r, &b)) goto done;
        hashmap_set_grow_by_power(map, b % 5);
        break;
      }
      default: {  // count
        break;
      }
    }
    CHECK(hashmap_count(map) == g_n);
  }
done:
  {
    size_t before = g_elfree_calls;
    size_t n = g_n;
    hashmap_free(map);
    if (use_elfree) CHECK(g_elfree_calls - before == n);
  }
  return 0;
}
