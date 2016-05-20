class: center, middle

# Buffer Overflow
## Insights and comments about C. Cowan paper (lecture 08)

---

## Steps

1. Arrange for suitable code to be available in the pro-
gram's address space.
2. Get the program to jump to that code, with suitable
parameters loaded into registers & memory.

---

## Steps
### ways to arrange suitable code to be in the program's address space

* Inject it
* It is already there

---

### Ways to arrange suitable code to be in the program's address space
### Inject it

.left-column[
1. what code should be injected?
]
.right-column[
  - must be binary opcode (attackers can't compile)
	- must be
[position-independent](http://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/)
(*an additional level of indirection to all global data and function
references in the code. Code can be easily mapped into different memory addresses without
needing to change one bit.*)
]

---

### Ways to arrange suitable code to be in the program's address space
### Inject it

.left-column[
1. what code should be injected?
2. Example
]
.right-column[
What the code really does is not important, but for historical
reasons, the code spawns a shell.
For this reason it is always called *Shellcode*.
- Very simple (naive) shellcode: `execve /bin//sh`
- Something like: `31 c9 f7 e1 b0 0b 51 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 cd 80`
(*naive, static, 21B shellcode*)

**Note:** if the executable is root *set-uid*, then you got a root
shell! Does you remember SUID bit?!
]

---

### Ways to arrange suitable code to be in the program's address space
### Inject it

.left-column[
1. What code should be injected?
2. Example
3. Where code should be injected?
]
.right-column[
- In the buffer
- In another buffer
- In an environment variable (easier to be located, very high address)
- Everywhere in memory, be creative
]

---

### Ways to arrange suitable code to be in the program's address space
### It is already there
Stack smashing is hard in the presence of
[StackGuard](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)
and [StackShield](http://www.angelfire.com/sk/stackshield/)
furthermore, it is hard to inject code when stack is *non-executable*
(`NX` bit).
However, `there is already so many function pointers in memory`.
Most common techniques that leverage this idea are:
.left-column[
- Return to libc
- Return to GOT
- ROP (&co)
]
.right-column[
- **Defeat NX bit and StackGuard**
- **Defeat NX bit and StackGuard**
- **Defeat NX bit, StackGuard and ASLR**
]

---

## Steps
### Jump to that code

In order to jump to the suitable code, attackers could corrupt the
normal program flow by overwrite or mangle:

- Activation records
- Function Pointers
- Longjmp buffers

---
