# Scan summary

The scanner found several issues that may warrant attention:

- Uninitialized memory read in pack_header, src/pack.c:141
- Integer overflow before malloc in read_len, src/io.c:77
- Unsafe strcpy in copy_buf, src/buf.c:205
- TODO: handle EOF properly
