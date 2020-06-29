# Cache miss

In this folder I try to gather all my experimentation about cache misses.
It contains very simple examples, such as:
* how does the container affect it
* how the way to access data affect it (simple matrix with colRow or rowCol access)
* comparison of a search between simple vector and [Van Emde Boas tree](https://en.wikipedia.org/wiki/Van_Emde_Boas_tree) (veb is supposed to be better as [this site](https://jiahai-feng.github.io/posts/cache-oblivious-algorithms/) says, but the [veb code I found](https://github.com/dragoun/veb-tree) takes more time to run, and I see more cache misses :/).

Discoverd the [perf](https://perf.wiki.kernel.org/index.php/Main_Page) tool (along with [hotspot](https://github.com/KDAB/hotspot)), which allows me to count the cache misses.
Preferred command:
```bash
perf stat -dd <command>
```

All in all my personnal feeling (for now) is that cache misses matters a bit when doing **LOTS** of computation, but not so much compared to the time it takes to initialize the structures I was working with. It may come handy when I create a structure once and do a lot of computation on the same structure.