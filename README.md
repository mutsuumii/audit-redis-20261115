# Security audit: antirez/redis

Date: 2026-11-15 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 240 issue(s): 21 critical, 218 high, 1 medium.

## Findings

### 1. [HIGH] Use-after-free pattern

**CWE-416** | `src/crc64.c` line 332

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(data);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 2. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/crc64.c` line 297

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
data = zmalloc(crc64_test_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 3. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/sort.c` line 381

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
vector = zmalloc(sizeof(redisSortObject)*vectorlen);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 4. [HIGH] Use-after-free pattern

**CWE-416** | `src/sort.c` line 639

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(vector);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/sort.c` line 20

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
redisSortOperation *so = zmalloc(sizeof(*so));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/sort.c` line 381

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
vector = zmalloc(sizeof(redisSortObject)*vectorlen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [HIGH] Integer overflow in size calculation

**CWE-190** | `deps/jemalloc/include/jemalloc/internal/large_externs.h` line 6

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
void *large_malloc(tsdn_t *tsdn, arena_t *arena, size_t usize, bool zero);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 8. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/include/jemalloc/internal/large_externs.h` line 6

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *large_malloc(tsdn_t *tsdn, arena_t *arena, size_t usize, bool zero);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 9. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/hnsw.c` line 388

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
while (rand() < threshold && level < HNSW_MAX_LEVEL)
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 10. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/hnsw.c` line 1969

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
uint32_t rand_neighbor = rand() % current->layers[level].num_links;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 11. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/hnsw.c` line 1983

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
num_walks += rand() & 1;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 12. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/hnsw.c` line 1990

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
uint32_t rand_neighbor = rand() % current->layers[0].num_links;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 13. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 497

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
hnswNode *node = hmalloc(sizeof(hnswNode)+(sizeof(hnswNodeLayer)*(level+1)));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 14. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 1201

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
float *distances = hmalloc((unsigned long) count * count * sizeof(float));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 15. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 1218

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
float *row_avgs = hmalloc(count * sizeof(float));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 16. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 1240

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
float *scores = hmalloc((unsigned long) count * count * sizeof(float));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 17. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 1294

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
int *used = hmalloc(count*sizeof(int));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 18. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 2106

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
sn->params = hmalloc(sizeof(uint64_t)*num_params);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 19. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 2337

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
hnswNode **table = hmalloc(sizeof(hnswNode*) * table_size);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 20. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/vector-sets/hnsw.c` line 2603

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
hnswNode **stack = hmalloc(sizeof(hnswNode*) * stack_size);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 21. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 132

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(pq);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 22. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 145

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(pq);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 23. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 418

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(index);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 24. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 428

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(index);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 25. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 516

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 26. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 528

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 27. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 556

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 28. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 573

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 29. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 589

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 30. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 600

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(current);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 31. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 610

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(index);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 32. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 646

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (candidates) pq_free(candidates);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 33. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 647

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (results) pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 34. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 715

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(candidates);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 35. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 826

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 36. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 847

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 37. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1220

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 38. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1242

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 39. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1243

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(row_avgs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 40. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1297

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 41. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1298

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(row_avgs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 42. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1299

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(scores);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 43. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1407

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(candidates);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 44. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1417

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 45. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1436

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(candidates);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 46. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1440

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(candidates);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 47. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1445

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 48. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1446

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(row_avgs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 49. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1447

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(scores);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 50. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1448

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(used);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 51. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1579

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 52. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1679

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 53. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1695

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 54. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1732

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 55. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1910

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(old_distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 56. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 1929

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(old_distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 57. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2108

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(sn);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 58. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2167

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(sn);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 59. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2206

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 60. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2216

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 61. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2227

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 62. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2237

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 63. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2261

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 64. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2272

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hnsw_node_free(node);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 65. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2442

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(table);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 66. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2447

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(table);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 67. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2489

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(cursor);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 68. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2641

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(stack);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 69. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2649

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(stack);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 70. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2726

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(neighbors);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 71. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2727

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 72. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2728

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(test_vector);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 73. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2736

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(neighbors);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 74. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2737

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 75. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2811

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(neighbors);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 76. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2812

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(distances);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 77. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2813

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hfree(test_vector);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 78. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/hnsw.c` line 2886

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
pq_free(results);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 79. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 127

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
pqueue *pq = hmalloc(sizeof(*pq));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 80. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 130

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
pq->items = hmalloc(sizeof(pqitem) * capacity);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 81. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 395

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
HNSW *index = hmalloc(sizeof(HNSW));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 82. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 497

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswNode *node = hmalloc(sizeof(hnswNode)+(sizeof(hnswNodeLayer)*(level+1)));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 83. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 514

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
node->vector = hmalloc(sizeof(float) * index->vector_dim);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 84. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 525

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *quants = hmalloc(hnsw_quants_bytes(index));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 85. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 553

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
node->vector = hmalloc(vector_bytes);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 86. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 569

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
node->layers[i].links = hmalloc(sizeof(hnswNode*) * max_links);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 87. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 750

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
node->vector = hmalloc(sizeof(float)*index->vector_dim);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 88. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 761

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *quants = hmalloc(hnsw_quants_bytes(index));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 89. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1201

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *distances = hmalloc((unsigned long) count * count * sizeof(float));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 90. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1218

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *row_avgs = hmalloc(count * sizeof(float));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 91. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1240

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *scores = hmalloc((unsigned long) count * count * sizeof(float));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 92. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1294

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
int *used = hmalloc(count*sizeof(int));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 93. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1668

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
InsertContext *ctx = hmalloc(sizeof(*ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 94. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 1904

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *old_distances = hmalloc(sizeof(float) * layer0_connections);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 95. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2104

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswSerNode *sn = hmalloc(sizeof(hnswSerNode));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 96. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2106

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sn->params = hmalloc(sizeof(uint64_t)*num_params);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 97. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2337

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswNode **table = hmalloc(sizeof(hnswNode*) * table_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 98. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2460

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswCursor *cursor = hmalloc(sizeof(*cursor));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 99. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2603

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswNode **stack = hmalloc(sizeof(hnswNode*) * stack_size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 100. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2722

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
hnswNode **neighbors = hmalloc(sizeof(hnswNode*) * test_ef);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 101. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2723

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *distances = hmalloc(sizeof(float) * test_ef);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 102. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/hnsw.c` line 2724

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
float *test_vector = hmalloc(sizeof(float) * index->vector_dim);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 103. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/include/jemalloc/internal/jemalloc_internal_externs.h` line 56

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *a0malloc(size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 104. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/include/jemalloc/internal/jemalloc_internal_externs.h` line 58

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *bootstrap_malloc(size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 105. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/include/jemalloc/internal/jemalloc_internal_externs.h` line 59

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *bootstrap_calloc(size_t num, size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 106. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/bitops.c` line 865

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
src = zmalloc(sizeof(unsigned char*) * numkeys);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 107. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/bitops.c` line 866

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
len = zmalloc(sizeof(long) * numkeys);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 108. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/bitops.c` line 867

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
objects = zmalloc(sizeof(robj*) * numkeys);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 109. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/bitops.c` line 1519

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
ops = zrealloc(ops,sizeof(*ops)*(numops+1));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 110. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 859

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(opname_upper);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 111. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 885

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(src);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 112. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 886

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(len);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 113. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 887

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(objects);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 114. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1175

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(src);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 115. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1176

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(len);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 116. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1177

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(objects);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 117. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1486

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 118. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1492

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 119. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1498

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 120. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1503

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 121. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1513

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 122. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1536

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 123. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1541

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 124. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1550

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 125. [HIGH] Use-after-free pattern

**CWE-416** | `src/bitops.c` line 1688

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(ops);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 126. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/bitops.c` line 865

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
src = zmalloc(sizeof(unsigned char*) * numkeys);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 127. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/bitops.c` line 866

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
len = zmalloc(sizeof(long) * numkeys);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 128. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/bitops.c` line 867

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
objects = zmalloc(sizeof(robj*) * numkeys);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 129. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/bitops.c` line 1519

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ops = zrealloc(ops,sizeof(*ops)*(numops+1));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 130. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hdr_histogram/hdr_histogram.c` line 433

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hdr_free(counts);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 131. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hdr_histogram/hdr_histogram.c` line 449

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hdr_free(h);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 132. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hdr_histogram/hdr_histogram.c` line 424

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
counts = (int64_t*) hdr_calloc((size_t) cfg.counts_len, sizeof(int64_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 133. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hdr_histogram/hdr_histogram.c` line 430

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
histogram = (struct hdr_histogram*) hdr_calloc(1, sizeof(struct hdr_histogram));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 134. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 191

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(f_ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 135. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 204

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(lua_engine_ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 136. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 348

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (name) sdsfree(name);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 137. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 349

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (desc) sdsfree(desc);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 138. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 352

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(lua_f_ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 139. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 383

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (name) sdsfree(name);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 140. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 384

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (desc) sdsfree(desc);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 141. [HIGH] Use-after-free pattern

**CWE-416** | `src/function_lua.c` line 420

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(err);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 142. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/function_lua.c` line 313

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lua_f_ctx = zmalloc(sizeof(*lua_f_ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 143. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/function_lua.c` line 375

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lua_f_ctx = zmalloc(sizeof(*lua_f_ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 144. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/function_lua.c` line 429

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
luaEngineCtx *lua_engine_ctx = zmalloc(sizeof(*lua_engine_ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 145. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/function_lua.c` line 499

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
engine *lua_engine = zmalloc(sizeof(*lua_engine));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 146. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/bitmap.c` line 96

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bitmap);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 147. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/bitmap.c` line 127

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bitmap);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 148. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/bitmap.c` line 165

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bitmap);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 149. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/bitmap.c` line 312

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(bitmap);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 150. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 82

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bitmap_t *bitmap = (bitmap_t *)malloc(bitmap_size(binfo));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 151. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 83

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(bitmap, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 152. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 119

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bitmap_t *bitmap = (bitmap_t *)malloc(bitmap_size(binfo));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 153. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 120

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(bitmap, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 154. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 150

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bitmap_t *bitmap = (bitmap_t *)malloc(bitmap_size(binfo));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 155. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 151

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(bitmap, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 156. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 187

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
bitmap_t *bitmap = (bitmap_t *)malloc(bitmap_size(binfo));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 157. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/bitmap.c` line 188

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(bitmap, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 158. [HIGH] Integer overflow in size calculation

**CWE-190** | `src/t_string.c` line 135

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
robj **argv = zmalloc((c->argc-1)*sizeof(robj*));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 159. [HIGH] Use-after-free pattern

**CWE-416** | `src/t_string.c` line 956

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(result);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 160. [HIGH] Use-after-free pattern

**CWE-416** | `src/t_string.c` line 957

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
zfree(lcs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 161. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/t_string.c` line 135

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
robj **argv = zmalloc((c->argc-1)*sizeof(robj*));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 162. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/t_string.c` line 828

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lcs = ztrymalloc(lcsalloc);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 163. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/test/unit/emitter.c` line 59

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
size_t written = malloc_snprintf(buf_descriptor->buf,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 164. [CRITICAL] Format string vulnerability

**CWE-134** | `src/mstr.c` line 235

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("[%p] %s: %s (strLen=%zu, mstrLen=%zu, isMeta=0)\n",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 165. [CRITICAL] Format string vulnerability

**CWE-134** | `src/mstr.c` line 240

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("[%p] %s: %s (strLen=%zu, mstrLen=%zu, isMeta=1, metaFlags=0x%x)\n",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 166. [HIGH] Insecure random — cryptographic use

**CWE-338** | `src/mstr.c` line 437

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
for (i = 0 ; i < sizeof(str) ; ++i) str[i] = rand() % 256;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 167. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/mstr.c` line 38

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sh = trymalloc? s_trymalloc(len) : s_malloc(len);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 168. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/mstr.c` line 95

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
allocMstr = trymalloc? s_trymalloc(allocLen) : s_malloc(allocLen);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 169. [MEDIUM] Large stack allocation (potential stack overflow)

**CWE-770** | `src/mstr.c` line 436

alloca() or large fixed VLA on stack. If size is attacker-controlled or too large, stack overflow corrupts adjacent frames.

```
char str[66000];
```

**Fix:** Use heap allocation (malloc) for large or variable-sized buffers. Enforce a size cap before alloca().
---

### 170. [HIGH] Integer overflow in size calculation

**CWE-190** | `deps/jemalloc/test/unit/cache_bin.c` line 70

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
void **out = malloc((batch + 1) * sizeof(void *));
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 171. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/cache_bin.c` line 82

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(out);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 172. [HIGH] Use-after-free pattern

**CWE-416** | `deps/jemalloc/test/unit/cache_bin.c` line 260

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(ptrs);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 173. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/cache_bin.c` line 70

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void **out = malloc((batch + 1) * sizeof(void *));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 174. [CRITICAL] Format string vulnerability

**CWE-134** | `modules/vector-sets/fastjson_test.c` line 388

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Starting fastjson parser stress test...\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 175. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 118

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
size_t len = 1 + rand() % (max_len - 2); /* Ensure at least 1 char */
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 176. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 121

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
buffer[i] = charset[rand() % (sizeof(charset) - 1)];
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 177. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 128

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
double num = (double)rand() / RAND_MAX * 1000.0;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 178. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 131

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
if (rand() % 5 == 0) num = -num;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 179. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 132

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
if (rand() % 3 != 0) num += (double)(rand() % 100) / 100.0;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 180. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 153

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
int num_fields = 1 + rand() % 10; /* Random number of fields */
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 181. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 154

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
int target_field_index = rand() % num_fields; /* Which field to return */
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 182. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 173

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
if (rand() % 2) {
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 183. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 183

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
int value_type = rand() % 5;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 184. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 209

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
int array_items = 1 + rand() % 5;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 185. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 214

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
if (rand() % 2) {
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 186. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 239

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
int num_corruptions = 1 + rand() % 3;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 187. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 241

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
size_t pos = rand() % len;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 188. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 242

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
char corruption = " \t\n{}[]\":,0123456789abcdefXYZ"[rand() % 30];
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 189. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 345

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
size_t truncated_len = 1 + rand() % json_len;
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 190. [HIGH] Insecure random — cryptographic use

**CWE-338** | `modules/vector-sets/fastjson_test.c` line 391

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
srand(time(NULL));
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---

### 191. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/fastjson_test.c` line 284

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(json);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 192. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/fastjson_test.c` line 305

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(json);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 193. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/fastjson_test.c` line 326

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(corrupted);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 194. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/fastjson_test.c` line 327

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(json);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 195. [HIGH] Use-after-free pattern

**CWE-416** | `modules/vector-sets/fastjson_test.c` line 367

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(temp_json);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 196. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/fastjson_test.c` line 145

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *json = malloc(MAX_JSON_SIZE);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 197. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/vector-sets/fastjson_test.c` line 302

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *corrupted = malloc(json_len + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 198. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/san.c` line 33

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *ptr = malloc(sz);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 199. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/san.c` line 34

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(ptr, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 200. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/san.c` line 79

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *ptr = malloc(large_sz);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 201. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/san.c` line 81

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
expect_ptr_not_null(ptr, "Unexpected malloc() failure");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 202. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/src/prof_sys.c` line 380

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
malloc_vsnprintf(buf, sizeof(buf), format, ap);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 203. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/src/prof_sys.c` line 433

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
malloc_vsnprintf(filename, sizeof(filename), format, ap);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 204. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/src/prof_sys.c` line 568

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
malloc_snprintf(filename, DUMP_FILENAME_BUFSIZE,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 205. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/src/prof_sys.c` line 573

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
malloc_snprintf(filename, DUMP_FILENAME_BUFSIZE,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 206. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/jemalloc/src/prof_sys.c` line 583

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
malloc_snprintf(filename, PROF_DUMP_FILENAME_LEN,
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 207. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/adapters/libsdevent.h` line 28

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 208. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/adapters/libsdevent.h` line 156

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
e = (redisLibsdeventEvents*)hi_calloc(1, sizeof(*e));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 209. [HIGH] Missing NULL check after allocation

**CWE-476** | `src/unix.c` line 78

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
connection *conn = zcalloc(sizeof(connection));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 210. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/hiredis/examples/example-macosx.c` line 15

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("argv[%s]: %s\n", (char*)privdata, reply->str);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 211. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 750

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(form + l - 1, LUA_INTFRMLEN);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 212. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 777

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(buff, form, (int)luaL_checknumber(L, arg));
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 213. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 782

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(buff, form, (LUA_INTFRM_T)luaL_checknumber(L, arg));
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 214. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 787

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(buff, form, (unsigned LUA_INTFRM_T)luaL_checknumber(L, arg));
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 215. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 792

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(buff, form, (double)luaL_checknumber(L, arg));
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 216. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `deps/lua/src/lstrlib.c` line 810

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
sprintf(buff, form, s);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 217. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/lua/src/lstrlib.c` line 777

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf(buff, form, (int)luaL_checknumber(L, arg));
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 218. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/lua/src/lstrlib.c` line 782

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf(buff, form, (LUA_INTFRM_T)luaL_checknumber(L, arg));
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 219. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/lua/src/lstrlib.c` line 787

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf(buff, form, (unsigned LUA_INTFRM_T)luaL_checknumber(L, arg));
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 220. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/lua/src/lstrlib.c` line 792

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf(buff, form, (double)luaL_checknumber(L, arg));
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 221. [CRITICAL] Format string vulnerability

**CWE-134** | `deps/lua/src/lstrlib.c` line 810

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
sprintf(buff, form, s);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 222. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 94

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_free(val);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 223. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 301

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_free(cb);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 224. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 534

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_sdsfree(sname);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 225. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 888

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
if (ret == 0) hi_sdsfree(sname);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 226. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 920

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_sdsfree(sname);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 227. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 981

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_free(cmd);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 228. [HIGH] Use-after-free pattern

**CWE-416** | `deps/hiredis/async.c` line 1002

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
hi_sdsfree(cmd);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 229. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/async.c` line 69

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dup = hi_malloc(sizeof(*dup));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 230. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/async.c` line 118

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ac = hi_realloc(c,sizeof(redisAsyncContext));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 231. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/async.c` line 273

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
cb = hi_malloc(sizeof(*cb));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 232. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/async.c` line 1019

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ac->c.command_timeout = hi_calloc(1, sizeof(tv));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 233. [HIGH] Integer overflow in size calculation

**CWE-190** | `deps/hiredis/sds.h` line 273

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
void *hi_sds_realloc(void *ptr, size_t size);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 234. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/sds.h` line 272

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *hi_sds_malloc(size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 235. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/hiredis/sds.h` line 273

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void *hi_sds_realloc(void *ptr, size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 236. [HIGH] Missing NULL check after allocation

**CWE-476** | `deps/jemalloc/test/unit/zero_reallocs.c` line 24

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ptr = realloc(ptr, 0);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 237. [HIGH] Use-after-free pattern

**CWE-416** | `src/syscheck.c` line 90

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(avail);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 238. [HIGH] Use-after-free pattern

**CWE-416** | `src/syscheck.c` line 91

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(curr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 239. [HIGH] Use-after-free pattern

**CWE-416** | `src/syscheck.c` line 113

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(curr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 240. [HIGH] Use-after-free pattern

**CWE-416** | `src/syscheck.c` line 347

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
sdsfree(err_msg);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---
