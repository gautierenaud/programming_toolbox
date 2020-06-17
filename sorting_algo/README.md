# Sorting algos

This is a toy directory that contains different implementations of sorting algorithms.
The performance is clearly not the focus, just so that I can get a grasp of the philosophy ^^

# Veeeery unscientific speed comparison

## Algos

* stl_sort: straight usage of std::sort. It's implementation is apparently **IntroSort**, which is a hybrid of Quicksort, Heapsort and Insertion sort. Pros: inplace sort, speed, good average complexity. Cons: not stable. Time complexity is `O(n log n)`
* lsd_radix_sort: naive implementation from (Wikipedia)[https://en.wikipedia.org/wiki/Radix_sort] with dictionaries
* lsd_radix_from_web: same as above, but using count sort as seen on the web. Time complexity is `O(n w / log n)`
* kirkpatrick_reisch_sort: kind of improvement over radix sort by using a trie in order to sort value half smaller than original (e.g. sort 34 instead of 1234). Info from [here](https://sortingsearching.com/2020/06/06/kirkpatrick-reisch.html) and [here](http://www.cs.tau.ac.il/~zwick/Adv-Alg-2015/Integer-Sorting.pdf). Time complexity supposed to be: `O(n + n log (w / log n))` with *w* the length of the word. I have the feeling that I missed something since my implementation is not that fast :/ 

## 100 Million random entries

* stl_sort: **~45s**
* lsd_radix_sort: **~140s**
* lsd_radix_from_web: **~50s**
* kirkpatrick_reisch_sort: **~90s**