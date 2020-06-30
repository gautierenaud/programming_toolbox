# Vectorization

Useful tools:
* `objdump -d *executable*`: show the assembly code
* [Compiler Explorer](https://godbolt.org/): shows how the code would be compiled with different compilers, and displays help about generated assembly.

# simple loop

This is a toy example meant to see how to detect whenever a chunk of code was vectorized.
The interesting part is the following:
```c++
for (size_t i = 0; i < a.size(); ++i)
{
    result[i] = a[i] + b[i];
}
```

With no optimization (`-O0`) I got:
```asm
mov     rdx, QWORD PTR [rbp-24]
mov     rax, QWORD PTR [rbp-48]
mov     rsi, rdx
mov     rdi, rax
call    std::vector<int, std::allocator<int> >::operator[](unsigned long) const
mov     r12d, DWORD PTR [rax]
mov     rdx, QWORD PTR [rbp-24]
mov     rax, QWORD PTR [rbp-56]
mov     rsi, rdx
mov     rdi, rax
call    std::vector<int, std::allocator<int> >::operator[](unsigned long) const
mov     ebx, DWORD PTR [rax]
mov     rdx, QWORD PTR [rbp-24]
mov     rax, QWORD PTR [rbp-40]
mov     rsi, rdx
mov     rdi, rax
call    std::vector<int, std::allocator<int> >::operator[](unsigned long)
lea     edx, [r12+rbx]
mov     DWORD PTR [rax], edx
```
We can see that we are using plain old registers to do our arithmetics (**rdx**, **rax**, ... with **mov** instructions).


While with optimization (`-O3`) I got:
```asm
movdqu  xmm0, XMMWORD PTR [rsi+rax]
movdqu  xmm1, XMMWORD PTR [rcx+rax]
paddd   xmm0, xmm1
movups  XMMWORD PTR [rbp+0+rax], xmm0
add     rax, 16
cmp     rdi, rax
jne     .L47
mov     rax, rdx
and     rax, -4
test    dl, 3
je      .L45
mov     edi, DWORD PTR [rsi+rax*4]
add     edi, DWORD PTR [rcx+rax*4]
mov     DWORD PTR [rbp+0+rax*4], edi
lea     rdi, [rax+1]
cmp     rdx, rdi
jbe     .L45
mov     r8d, DWORD PTR [rcx+rdi*4]
add     rax, 2
add     r8d, DWORD PTR [rsi+rdi*4]
mov     DWORD PTR [rbp+0+rdi*4], r8d
cmp     rdx, rax
jbe     .L45
mov     edx, DWORD PTR [rcx+rax*4]
add     edx, DWORD PTR [rsi+rax*4]
mov     DWORD PTR [rbp+0+rax*4], edx
```
Here we can see the use of different registers/instructions (knowingly **xmm0**, **movdq**, **paddd**, ...).
**xmm** seems to be a 128-bits word used for multimedia operands.

Coming to the time difference, for 10000000 element addition:
* `make -B OPT_FLAG='-O0'`: `Elapsed time: 0.172097 s for addition`
* `make -B OPT_FLAG='-O1'`: `Elapsed time: 0.0176994 s for addition`
* `make -B OPT_FLAG='-O2'`: `Elapsed time: 0.0152085 s for addition`
* `make -B OPT_FLAG='-O3'`: `Elapsed time: 0.0137107 s for addition` -> vectorization *should* only appear starting from here,
so the enhancement due to vectorization seems to be ~0.002s faster code **at most** (there are potentially other optimizations).