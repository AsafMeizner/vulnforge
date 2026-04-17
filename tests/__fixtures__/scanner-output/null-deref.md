# null_deref_hunter results

## Finding 1

### MEDIUM: NULL dereference after strdup

**File:** lib/parser.c:214

The return value of `strdup()` is not checked before use.

```c
char *copy = strdup(input);
strcpy(copy, other);  // NULL deref on allocation failure
```

**Impact:** Crash / DoS on allocation failure.

**Fix:** Check `copy != NULL` before using it.

CWE-476
