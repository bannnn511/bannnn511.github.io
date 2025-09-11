---
title: Hacking xv6 page table
date: 2024-09-23
---

## What will we do in this blog?

We will explore, how page table is setup in xv6 kernel. How page directory is managed during a `fork` and `exec` system call. We will also implement guarding against NULL pointer dereference.

## Virtual memory

All memory address, pointers to memory that we are using is an abstraction called virtual memory. As an software engineer, most of us don't need to care how memory is given to our programs, or how memory is given to us; thus thanks to virtual memory, we are free from worrying about these issues and can focus on the business logic.
Virtual memory is an **abstraction** that the OS provides us with efficient, control and flexible memory. Efficient is provided with the help of hardware such as TLBs, page table hardware, etc. Control means that the OS ensures no program is allowed to access other program memory. And with flexibility, we can use our address space in the way we want, thus interacting with the system memory easier.

Page tables are the **mechanism** that the OS control what **memory address mean**. Page tables allows the OS to multiplex address of different process onto a single physical memory. With page tables, the OS can multiplex address space and protect our programs memory. OS can map the kernel memory in several address space and thus making transition from user space to kernel space possible. OS can also guard the user stack by making use of unmapped page.

## Paging hardware

### Page table

Let's  look into how x86 paging hardware works. Page tables are data structures for indexing virtual address(VA) with physical address(PA) of memory. When user access virtual address, the OS will use the paging hardware to translate those virtual address to physical address. Because we are talking about x86 architecture, our processor, memory are **32-bit units**.

An x86 page table is an array of 2^20 **page table entry**. Each PTE contains a 20-bit **physical page number** (PPN). The paging hardware will use the first the top 20-bit (31-22 bit) to index the page table to find the PTE. Then it will replace the top 20-bit with the PPN in the PTE and copy the low 12-bit unchanged from the virtual address to translate to physical address. With this setup, the OS can control a address translation of aligned chunk of 4096(2*12) bytes which we call a **page table page or page**.

> VA = PTE(20bits) + offset(12bits)
> Translate virtual address (VA) to physical address
> PA = `valueof`(PTE) + offset
> PA = PPN(20bits) + offset(12bits)

### Multi-level page table

![multi-level page table]({{ site.baseurl }}/assets/multi-level-page-table.png)

```
x86 multi-level page table
```

Each process has it own page tables which makes simple page table likes the above too big and cost too much memory. Multi-level page table is used to get rid of unused region in page table. We turn a linear page table into a tree.

X86 two-level page table has a root that contains **4096-byte page directory**. Each page directory contains 1024 entries references to **page table**. Each page is an array of 1024 entries references to a 4096 bytes **page**. The `%cr3` registers
> page directory -> 1024 page tables -> 1024 pages (each 4096 bytes).

Address translation happens in two step. The top 10 bits of our virtual address is selected by the paging hardware to select a page directory entry. If the page directory entry is present, the hardware will use the next 10 bits to select a page table entry that the PDE refers to. If either the PDE or PTE is not present, it will raise a fault.

## How xv6 creates process address space

### Layout

![address space layout]({{ site.baseurl }}/assets/address-space-layout.png)

As mentioned above, xv6 multiplexes user space and kernel space onto one address space. We focus on user part of address space for now. User process start at address 0, at the bottom we have the `text` for our user program then its `data` and its `stack`. Heap is above the stack and can be expanded when the process call `sbrk` system call. Stack overflow is used to prevent user from growing out of the stack, the xv6 places a guard page below the stack and set the permission to not allowed user.

> usually, when you type a command in to the shell such as `ls`. The current process that is running the shell will call `fork` to create a new process, then the new process will call `exec` to run `ls` .`exec` will overwrite the current process state and never return, that is why `fork` is used first.

### The fork system call

```c
// FILE: proc.c
// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void) {
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0) {
    return -1;
  }

  // Copy process state from proc.
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0) {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;

  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++)
    if (curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

```

When a `fork` system call is invoked. A child process will be created with the same attributes as the parent process. Here is how `fork` works (I will skip over codes that does not related to our page table topics)
 `allocproc` create new process by finding `UNUSED` process; creates kernel stack for the new process; setup trapframe, return point for trap and fork called.

 `copyuvm` is used to copy the parent's **page directory** to our new process. It then copies the current user memories.

```c
  // FILE: proc.c
  // Copy process state from proc.
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0) {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;
```

This is where file descriptors and open files are copied.

```c
  // FILE: proc.c
  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++)
    if (curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);
```

After this, our child process state is set to `RUNNABLE` for the scheduler to pick up. `fork` is usually checked its return value for our program to check if it is a child or parent so we will return the pid here.

```c
// FILE: proc.c
  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;

```

### The exec system call

 The `exec` system call can be found in `exec.c`. Unix and unix-like OS uses EFL header to know if the file can be executed. Xv6 will check if when we load user programs into memory if the file is indeed a EFL file.

```c
// FILE: exec.c
// Check ELF header
  if (readi(ip, (char *)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if (elf.magic != ELF_MAGIC)
    goto bad;
```

This is where it setup the kernel space in our address space.

```c
// FILE: exec.c
  if ((pgdir = setupkvm()) == 0)
    goto bad;
```

EFL header is needed for our OS to determine which section is the `text` and `data` segment in our programs. With this info, `exec` can create pages following the layout above.

```c
// FILE: exec.c
  sz = 0;
  for (i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph)) {
    if (readi(ip, (char *)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if (ph.type != ELF_PROG_LOAD)
      continue;
    if (ph.memsz < ph.filesz)
      goto bad;
    if (ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if ((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if (ph.vaddr % PGSIZE != 0)
      goto bad;
    if (loaduvm(pgdir, (char *)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
```

Each section in our address space is created at the line that called `allocuvm` which will allocate memory for each EFL segment. `loaduvm` will copy the EFL contents from kernel space to user space. Both `allocuvm`, and `loaduvm` have `pgdir` (page directory) as their first parameter.

The stacks is created with 2 pages, one for the stack and one for our guard pages. `allocuvm` is used to create page for our stack, and `clearpteu` is used to  make that page inaccessible from user space by clearing its user flag.

```c
  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  sz = PGROUNDUP(sz);
  if ((sz = allocuvm(pgdir, sz, sz + 2 * PGSIZE)) == 0)
    goto bad;

  clearpteu(pgdir, (char *)(sz - 2 * PGSIZE));
  sp = sz;
```

Below this, `exec` will initialized our user stack and will switch to our new page directory at `switchuvm`.

## Hacking xv6 page table

### Dereference NULL pointer

Remember that xv6 setup user address space start at address 0? It means that if we deference a NULL pointer address, it still be valid.

Let's test this. We will write a small program in which we will deference a null pointer.

```c
// FILE: null.c
#include "types.h"
#include "pstat.h"
#include "user.h"

// Userspace Program that writes to 0x0
int main(int argc, char *argv[]) {
  char *c = 0;
  printf(1, "%x\n", *c);
  c++;
  printf(1, "%x\n", *c);
  c++;
  printf(1, "%x\n", *c);

  exit();
}
```

> add the flags `-fno-delete-null-pointer-checks` to `CFLAGS` in `Makefile` to remove the compiler null check

If we run this program, we will get

```
$ null
FFFFFF8D
4C
24
```

Let see where `c` pointed to

```
❯ objdump -d null.o

null.o: file format elf32-i386

Disassembly of section .text.startup:

00000000 <main>:
       0: 8d 4c 24 04                   leal    0x4(%esp), %ecx
       4: 83 e4 f0                      andl    $-0x10, %esp
       7: ff 71 fc                      pushl   -0x4(%ecx)
       a: 55                            pushl   %ebp
       b: 89 e5                         movl    %esp, %ebp
       d: 51                            pushl   %ecx
       e: 83 ec 08                      subl    $0x8, %esp
      11: 0f be 05 00 00 00 00          movsbl  0x0, %eax
      18: 50                            pushl   %eax
      19: 68 00 00 00 00                pushl   $0x0
      1e: 6a 01                         pushl   $0x1
      20: e8 fc ff ff ff                calll   0x21 <main+0x21>
      25: 0f be 05 01 00 00 00          movsbl  0x1, %eax
      2c: 83 c4 0c                      addl    $0xc, %esp
      2f: 50                            pushl   %eax
      30: 68 00 00 00 00                pushl   $0x0
      35: 6a 01                         pushl   $0x1
      37: e8 fc ff ff ff                calll   0x38 <main+0x38>
      3c: e8 fc ff ff ff                calll   0x3d <main+0x3d>
```

### Guard against NULL pointer

The reason why we can read memory at NULL is because of text section is at address 0. What we could do is move the text section up a page, then we user program try to read NULL, the kernel will caught this.
Here is out new layout.

![null guard address space layout]({{ site.baseurl }}/assets/null-guard-address-space.png)

These are the steps that we will do:

1. user address space are setup during `exec` system call, the text segment like mention above is setup first at address 0. We will move this segment up a page by set `sz = PGSIZE`.

```c
  // FILE: exec.c -> exec()
  sz = PGSIZE;
  for (i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph)) {
    if (readi(ip, (char *)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if (ph.type != ELF_PROG_LOAD)
      continue;
    if (ph.memsz < ph.filesz)
      goto bad;
    if (ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if ((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if (ph.vaddr % PGSIZE != 0)
      goto bad;
    if (loaduvm(pgdir, (char *)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }

```

2. doing this will break chill process, since the `fork` system call will copy at address 0. `fork` will call `copyuvm` to copy the current page directory. We will change `copyuvm` to start copy at the next page.

```c
  // FILE: proc.c -> copyuvm()
  sz = PGSIZE;
  for (i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph)) {
    if (readi(ip, (char *)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if (ph.type != ELF_PROG_LOAD)
      continue;
    if (ph.memsz < ph.filesz)
      goto bad;
    if (ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if ((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if (ph.vaddr % PGSIZE != 0)
      goto bad;
    if (loaduvm(pgdir, (char *)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }

```

4. currently, our linker mapped the text segment at address 0, which we also need to update in our `Makefile`. Since our page is 4096 bytes, set the text section to 0x1000

``` Makefile
_%: %.o $(ULIB)
 $(LD) $(LDFLAGS) -N -e main -Ttext 0x1000 -o $@ $^
 $(OBJDUMP) -S $@ > $*.asm
 $(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $*.sym
```

Let's try run our code again:

```$ null
pid 3 null: trap 14 err 4 on cpu 0 eip 0x1011 addr 0x0--kill proc
```

Now the kernel return trap 14 which is what we want for read or write to NULL pointer.

---

## Resources, references

- [https://wiki.osdev.org/Paging](https://wiki.osdev.org/Paging)

- [https://wiki.osdev.org/Exceptions#Page_Fault](https://wiki.osdev.org/Exceptions#Page_Fault)

- [https://pages.cs.wisc.edu/~remzi/OSTEP/](https://pages.cs.wisc.edu/~remzi/OSTEP/)

- [https://github.com/palladian1/xv6-annotated](https://github.com/palladian1/xv6-annotated)

- [https://github.com/mit-pdos/xv6-public](https://github.com/mit-pdos/xv6-public)

- [https://github.com/remzi-arpacidusseau/ostep-projects/tree/master/initial-xv6](https://github.com/remzi-arpacidusseau/ostep-projects/tree/master/initial-xv6)
