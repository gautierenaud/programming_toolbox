# heap consolidation

Heap consolidation is a technique where one overwrites size metadata about a memory chunk. Upon freeing that chunk the consolidation will make libc think that the whole (overwritten) size of the memory is freed, while a part of it is still under our control. Then, after some more allocation/freeing, we'll have a pointer to some part of the heap that is supposed to be free.

However, with recent libc, there seems to be a check against memory consolidation. Indeed, the libc seems to be comparing the previously allocated size with the current metadata to check if it corresponds.
```c
/* consolidate backward */
if (!prev_inuse(p)) {
    prevsize = prev_size (p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
    unlink_chunk (av, p);
}
```

In the example, we overwrite the metadata for the previous free chunk (0x590) which does not corresponds to the size of the previously allocated one (0x510).