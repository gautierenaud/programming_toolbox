This folder tries to illustrates the content of [Memory part 5: What programmers can do](https://lwn.net/Articles/255364/).

It is very similar to `cache_miss`, but we will delve more in detail for the matrix multiplication.

Unfortunatly I was not able to make the cache aligned approach work, something is wrong with some index (apparently an addition is done 8 times instead of 1). As my original aim was just to know what was possible and not to master intrinsics I will leave it at here. Maybe come back some day ?

# Take away

* for C/C++, we need some compiler parameter so it can use intrinsics
* most of the time the structure we use with intrinsics must be aligned (be it 16 ~ 64 bytes)

