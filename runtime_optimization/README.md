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

