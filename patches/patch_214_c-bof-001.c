# Buffer overflow via unsafe string function
# CWE-120 | Severity: CRITICAL
# File: deps/lua/src/lstrlib.c line 787

**Risk:** strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
