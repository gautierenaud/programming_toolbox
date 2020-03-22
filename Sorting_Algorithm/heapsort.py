#!/usr/bin/env python3

import sys


"""
Toy implementation of 5.2.3's heapsort algorithm 
"""

def heapify(arr, n, i):
    """Recursively transform the array into a heap
    Corresponds to what Knuth calls siftup
    """
    largest = i
    l = 2 * i + 1
    r = 2 * i + 2

    if l < n and arr[largest] < arr[l]:
        largest = l

    if r < n and arr[largest] < arr[r]:
        largest = r

    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]

        heapify(arr, n, largest)

def heapsort(arr):
    n = len(arr)

    for i in range(n, -1, -1):
        heapify(arr, n, i)

    for i in range(n - 1, 0, -1):
        # maximum item is on top of the heap, put it at the end
        arr[0], arr[i] = arr[i], arr[0]
        heapify(arr, i, 0)

if __name__ == "__main__":
    shuffled_numbers = input().split()
    heapsort(shuffled_numbers)
    print(shuffled_numbers)
