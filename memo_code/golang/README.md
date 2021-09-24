# Golang

# For loop

```go
for i := 0; i < 10; i++ {
}

for ; sum < 1000; {
}

for sum < 1000 {
}

// infinite loop
for {
}

// for each
for i, s := range a {
    fmt.Println(i, s)
}
```

# List

The equivalent in go is `Slice`.
[Useful link](https://www.callicoder.com/golang-slices/)

Creation:
```go
foo := make([]int, length, capacity)
a := make([]int, 0, 5)      // [] because of len 0
b := make([]int, 5)         // [0, 0, 0, 0, 0] because of len 5

foo := []int{1, 2, 3}
```

Matrix h * w (filled with 0):
```go
foo := make([][]int, h)
for i := 0; i < h; i++ {
    foo = append(foo, make([]int, w))
}
```

## Access

```go
a := []int{0, 1, 2, 3, 4}
b := a[:2]              // [0 1]
c := b[2:5]             // [2 3 4]
d := a[len(a)-1]        // 4, i.e. last element
a[3] = 42               // c == [2 42 4]
```
A slice references an underlying array, which is why modifying `a` will change `c`. To copy the content (without the shared reference to the same memory region):
```go
copy(a, b)
```

## Appending

```go
foo = append(foo, 1, 2, 3)  // one or multiple elements
```

# String

Append char (aka rune):
```go
// strings are immutable
s := "hello";
c := 'x';
fmt.Println(s + string(c));

var s string
s = "hello";
var c = 'x';
var sb strings.Builder
sb.WriteString(s)
sb.WriteRune(c)
fmt.Println(sb.String())
```

join:
```go
import (
    "fmt"
    "strings"
)

func main() {
    // array of strings.
    str := []string{"Geeks", "For", "Geeks"}
  
    // joining the string by separator
    fmt.Println(strings.Join(str, "-"))
}
```

# Dictionary/Set

```go
m := make(map[string]int)
m["route"] = 66

m := map[string]int{
    "route": 66,
}

val, ok := m["route"]
for key, value := range m {
    fmt.Println("Key:", key, "Value:", value)
}

delete(m, "route")
```

We can create a set like structure with empty struct that does not take any memory:
```go
type void struct{}
var member void

set := make(map[string]void) // New empty set
set["key"] = member
```

# Async/Thread/Coroutine

They are called goroutines.
```go
package main

import (
    "fmt"
    "time"
)

func hello(word string) {
    fmt.Println("Hello " + word)
}

func main() {
    go hello("World")
    go func(sec time.Duration) {
        time.Sleep(sec * time.Second)
        fmt.Println("I'm back")
    }(2)
	
	time.Sleep(5 * time.Second)
}
```

```go
import "golang.org/x/sync/errgroup"

g, _ := errgroup.WithContext(context.Background())

for i := 0; i < 10; i++ {
    sleepTime := i  // sleepTime is part of closure, it is recreated each time
    g.Go(func() error {
        time.Sleep(time.Duration(sleepTime) * time.Second)
        fmt.Println("I'm on")

        return nil
    })
}

_ = g.Wait()  // wait for all goroutines to finish
```

# Semaphores

## Lock

```go
import (
    "sync"
    "fmt"
)

mu := sync.Mutex{}
mu.Lock()
fmt.Println("I'm safe")
mu.Unlock()
fmt.Println("<chuckles> I'm in danger")

// or maybe cleaner
mu := sync.Mutex{}
mu.Lock()
defer mu.Unlock()
fmt.Println("Do complicated stuff")
```

## Channels

```go
import (
    "fmt"   
)

func waitSome(c chan int) {
    <-c
    fmt.Println("I was waiting for this !")
}

c := make(chan int)

go waitSome(c)
c <- 3
time.Sleep(time.Second)
```

From playground:
```go
package main

import (
	"fmt"
	"time"
)

func main() {
	tick := time.Tick(100 * time.Millisecond)
	boom := time.After(500 * time.Millisecond)
	for {
		select {
		case <-tick:
			fmt.Println("tick.")
		case <-boom:
			fmt.Println("BOOM!")
			return
		default:
			fmt.Println("    .")
			time.Sleep(50 * time.Millisecond)
		}
	}
}
```

# Error handling

Somehow I always come back [here](https://go.dev/blog/go1.13-errors)
```go
type MyError struct {
    Err error
    SomeField string
}

func (m MyError) Error() string {
    return "got an error with" + m.SomeField + ": " + m.Err.Error() 
}

err := DoSomethingStupid()
if err != nil {
    return MyError{Err: err, SomeField: "welp"}
}

// errors.Is compares the value of the error
err := MyError{Err: nil, SomeField: "welp"}
someErrValue := MyError{Err: nil, SomeField: "wolp"}
someOtherErrValue := MyError{Err: nil, SomeField: "welp"}

if errors.Is(err, someErrValue) {
    fmt.Println("1. they have the same value")
    // well they don't. Even more true if the errors are wrapping other errors
}

if errors.Is(err, someOtherErrValue) {
    fmt.Println("2. they have the same value")
}

// errors.As compares the Type of the error
err := MyError{Err: nil, SomeField: "welp"}
someErrValue := MyError{}

if errors.As(err, &someErrValue) {
    fmt.Println("They have the same type")
}

// we can also wrap errors with %w
err := MyError{Err: nil, SomeField: "welp"}
if err != nil {
    someErrValue := fmt.Errorf("decompress %v: %w", "name", err)

    if errors.As(err, &someErrValue) {
        fmt.Println("they have the same type")
    }
}
```

# Conditional

```go
if num := 9; num < 0 {
    fmt.Println(num, "is negative")
} else if num < 10 {
    fmt.Println(num, "has 1 digit")
} else {
    fmt.Println(num, "has multiple digits")
}
```

## Ternary Operator

If + Else is the idiomatic way to do a ternary operator in go.

# Recursion

```go
func recSum(val int) int{
	if val == 0 {
		return 0
	}
	return val + recSum(val - 1)
}
```

# Regex

Simple matches:
```go
found, err := regexp.MatchString(".even", "Steven")
```

```go
re, err := regexp.Compile(".even")

if err != nil {
	log.Fatal(err)
}

doesMatch := re.MatchString("Steven")
occurences := re.FindAllString(content, -1) // -1 for all matches
```

Capture groups:
```go
re, err := regexp.Compile("(\\w+)")

if err != nil {
	log.Fatal(err)
}

parts := re.FindStringSubmatch("Hello World")  // [Hello Hello]
parts := re.FindAllStringSubmatch("Hello World", -1)  // [[Hello Hello] [World World]]
```

Replace string:
```go
re, err := regexp.Compile("Steve")

if err != nil {
	log.Fatal(err)
}

replaced := re.ReplaceAllString("Hello Steve", "Hugh")
```

# Multiple args

```go
bar := append([]int{1,2}, []int{3,4}...) // [1 2 3 4]

func foo(is ...int) {
    for i := 0; i < len(is); i++ {
        fmt.Println(is[i])
    }
}
```

# Specifics

## Nil

## Context

## defer

Defer the execution of the method at the end of the closure:
```go
defer func(){
    fmt.Println("after")
}()
fmt.Println("before")
```

## Type assertion vs conversion
