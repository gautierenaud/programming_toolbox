# Runtime optimization

This is a small project to illustrate myself the content of:
* [inline caching](https://bernsteinbear.com/blog/inline-caching/)
* [inline caching: quickening](https://bernsteinbear.com/blog/inline-caching-quickening/)
* [small object and pointer tagging](https://bernsteinbear.com/blog/small-objects/)

Which are a series of blog entry that ellaborate on a specific aspect of runtime optimization.

In his blog, the author illustrates his example with an implementation (C or C++), and I will try to do the same in this project. While I'm at it I'll do it in Golang.

As written in the blog, implemtation is taken from https://github.com/tekknolagi/icdemo, so all the structures are taken from there.

# Initial Behaviour

Without any optimization, the interpreter will just execute each command step by step. It has to rely on a lookup method each time it encounters a type specific method (e.g. add for integer, print for string, etc).

# Inline Caching

However, it is unlikely that we call the same method with different types each time we call it. Most of the time we'll use the same type of parameter.

Inline caching tries to optimize the lookup in the following manner:
* not cached -> look for corresponding method, and cache it with type as a key
* cached and entry corresponds -> use cached method
* cached but different type -> find right method, and replace cache content

Cache related log are displayed at info level, which we can see with:
```bash
❯ go run . -log info
INFO[0000] Could not find cached value for type: int     cached="<nil>"
INFO[0000] IntAdder cached at PC: 2                      cached="&{int IntAdder}"
84
INFO[0000] Using cached method for type: int             cached="&{int IntAdder}"
84
INFO[0000] Could not find cached value for type: string  cached="&{int IntAdder}"
INFO[0000] StrAdder cached at PC: 2                      cached="&{string StrAdder}"
4242
INFO[0000] Using cached method for type: string          cached="&{string StrAdder}"
4242
```
As we can see, it went from no cached value to having cached an adder for integer, until it was not suited for adding strings.

In real life scenario, we need to profile an actual application to see the real use of `ADD`, the memory constraints etc...

But usually inline caching is a useful trick that is used in several runtimes (JVM, Python, ...)

Note that in this example I implemented a **Monomorphic** inline cache that supports only one type at a given time. I guess Polymorphic would require a layer of Map/Dictionnary, with a limit on how many entries it can hold.


# Inline caching: Quickening

With initial inline caching approach, we need to check if we have a cached value each time. This check can be removed if the interpreter is able to modify its own bytecode.

For example, the interpreter could swap the original `ADD` with a special `ADD_CACHED` instruction that would directly retrieve the cached value and check if the types correspond. This optimization can work iff there is a cached entry in the corresponding bytecode stream.

With this optimization the logs will look like that:
```bash
❯ go run . -log info -runtime quickCached
INFO[0000] ADD: By default, there is no cache (type: int) 
INFO[0000] IntAdder cached at PC: 2                      cached="&{int IntAdder}"
INFO[0000] ADD: Bytecode have been replaced at PC: 2     instruction="{Op: add_cached, Arg: 0}"
84
INFO[0000] ADD_CACHED: Using cached value               
84
INFO[0000] ADD_CACHED: Could not find cached value for type: string  cached="&{int IntAdder}"
INFO[0000] StrAdder cached at PC: 2                      cached="&{string StrAdder}"
INFO[0000] ADD_CACHED: Using cached value               
4242
INFO[0000] ADD_CACHED: Using cached value               
4242
```
We can see that after the initial cache lookup, the instruction have been rewritten and we only call `ADD_CACHED` from there on.

We can even go further with optimization, if we can say that one type of addition is much more likely than the others (e.g. integer addition). In this case, we are able to move to another specific instruction for integer addition (aka ADD_INT).

Now the logs will look like this:
```bash
❯ go run . -log INFO -runtime quickCached
INFO[0000] ADD: By default, there is no cache (type: int) 
INFO[0000] ADD: Bytecode have been replaced at PC: 2     instruction="{Op: add_int, Arg: 0}"
84
INFO[0000] ADD_INT: Using cached value                  
84
INFO[0000] ADD_INT: type string not corresponding to int, looking for right method 
INFO[0000] ADD_INT: Bytecode have been replaced at PC: 2  instruction="{Op: add_cached, Arg: 0}"
4242
INFO[0000] ADD_CACHED: Using cached value               
4242
```
We can see the transition from ADD -> ADD_INT -> ADD_CACHED.

This will actually translate into fewer instructions and less overhead if we take the integer path.


# Small objects and pointer tagging

This optimization was not implemented with Go, since it needs to fiddle with pointer in order to cram data into the pointer itself. And I'm not sure it's a good idea with a GC-ed language such as Go. So I will just note some points from the blog.

The author of the blog notes that allocating (with `malloc` which requires quite a lot of machinery/bookkeeping -> see reverse engineering exercices I did ^^) a whole object for just an int is not that optimum. He also sees that `malloc` gives aligned pointers, i.e. the lowest bits are always 0.

His solution is to use this pointer field to store integer values. He differentiates between integers and pointers by checking the lowest bit of the field: if it is 0 then it is an integer (it is the only case it could be 0), else it must be a pointer. Thus, this lowest bit is effectively reserved for **tagging** integer, which are now encoded over 63 bits.

All he needs to do now is each time one needs to access an object he has to:
* check if it is a pointer or an integer -> check lowest bit
* if it is an integer, shift to the right so we remove that lowest bit -> 63bits integer value
* else remove set the lowest bit to 0 and just use it as a pointer

I wonder if it would have been more smart if we inversed the tagging: 1 for integer, else 0. Thus in case of an object we wouldn't even have to do bitmask operation (not that they are costly) and the logic surrounding integer would not change.

## Debug with debugger

### Random analysis gdb

For this part I felt I need to dug into the executable with gdb.

So [here](https://go.dev/doc/gdb) is some documentation that could be useful. Interesting enough, go installation provides helper script that can/should be loaded from `~/.gdbinit` by putting:
```bash
add-auto-load-safe-path <$GOROOT>/src/runtime/runtime-gdb.py
```
and be sure to replace `<$GOROOT>` with its actual value.

Because it is fun to dig into the actual data structure ^^

Some chunk of memory of my "bytecode":
```bash
0xc000014150:	0x0000000000000001	0x0000000100000001  # {0, ARG}, {1, ARG}
0xc000014160:	0x0000000000000002	0x0000000000000005  # {0, ADD}, {0, PRINT}
0xc000014170:	0x0000000000000006                      # {0, HALT}
```
Since both op and arg is encoded as uint32, each pair fit in a full 64bits word.

What seems to correspond to arguments:
```bash
0xc00007c210:	0x0000000000000001	0x00000000004ad040  # TypeInt, pointer to 0x8 ???
0xc00007c220:	0x00000000004e93d8	0x0000000000000001  # pointer to 42, TypeInt
0xc00007c230:	0x00000000004ad040	0x00000000004e93d8  # pointer to 0x8 ???, pointer to 42
gef➤  x 0x00000000004e93d8
0x4e93d8:	0x000000000000002a  # i.e. 42
```
`any` (or `interface{}`) seems to be implemented as a 64bits pointer (without surprise), which is why we see pointers to argument's value. I was surprised to see both values pointing to the same memory region, as it was optimized away. The `pointer to 0x8` is more puzzling, is it the length of the value object ?

### Delve

I also wanted to try delve, so I gave it a try (and passing parameters):
```bash
go install github.com/go-delve/delve/cmd/dlv@latest
dlv debug . -- -runtime quickCached
```

To see the content of a file I can:
```bash
(dlv) l github.com/gautierenaud/programming_toolbox/rtopt/pkg.EvalCodeCached
```

Display an object (here a variable called `frame`, not a specific command):
```bash
(dlv) p frame
```
