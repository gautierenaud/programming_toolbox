# Python

https://www.codingame.com/work/python-interview-questions/
https://sadh.life/post/builtins/

# For loop

```python
a = [1, 2, 3]
for i in a:
    print(i)

for i in range(0, len(a), 1):
    print(a[i])

for index, value in enumerate(a):
    print(value)

while True:
    print('duh')
```

To create own iterable class (from [here](https://wiki.python.org/moin/ForLoop)):
```python
class Iterable(object):
    def __init__(self, values):
        self.values = values
        self.location = 0

    def __iter__(self):
        return self

    def next(self):
        if self.location == len(self.values):
            raise StopIteration
        value = self.values[self.location]
        self.location += 1
        return value
```

Also range generator:
```python
def my_range(start, end, step):
    while start <= end:
        yield start  # this one is important
        start += step

for x in my_range(1, 10, 0.5):
    print(x)
```

# List

```python
# With list comprehension
foo = [0 for _ in range(length)]

foo = [1, 2, 3]

foo = list()
```

Matrix h * w (filled with 0):
```python
foo = [[0 for _ in range(w)] for _ in range(h)]
```

## Access

```python
a = [i for i in range(5)]
b = a[:2]               # [0 1]
c = a[2:5]              # [2 3 4]
d = a[-1]               # 4
a[3] = 42               # c == [2 3 4] no change
```
List are copied, changing an element of `a` will have no consequence on `c`.

Or maybe there was something about copying the list once there is a change. Until then they share the same memory region. Or was it an optimization only with strings ?

Trying to peek the address of the string objects with `id()` (only works on CPython) show too much distance in the addresses, but I guess they might have underlying fields pointing to the same region (or not).

## Appending

```python
foo.append(1)           # one element
foo.extend([1, 2, 3])   # multiple elements
```

# String


# Specifics

## Encoding

With python2, ASCII was the default. With python3, UTF8 is the default.

## Walrus operator

The `:` looks like eyes, `=` looks like tusks ^^
```python
if (n := len(foo)) > 10:
    print('list is too big:', n)
```

## None
