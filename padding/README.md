# Padding

Info at: [Structure Packing](http://www.catb.org/esr/structure-packing/).

Padding happens on:
* C
* C++
* Go
* Rust

To avoid padding one can 'pack' by explicitely telling the compiler so.

Toy program to see the effect of padding.

To compile and execute:
```bash
g++ padding_size.cpp -o padding_size --std=c++11
./padding_size
```

```bash
g++ padding_perf.cpp -o padding_perf --std=c++11
./padding_perf <vectorSize> <assignmentTime>
```
