---
title: "Beyond Multiprocessing... Multithreading the SunOS Kernel"
category: research-paper
date: 1992-06-08
authors: J. R. Eykholt, S. R. Kleiman, S. Barton, R. Faulkner, A. Shivalingiah, M. Smith, D. Stein, J. Voll, M. Weeks, D. Williams
summary: This paper describes the implementation of a multithreaded kernel in SunOS 5.0, including kernel architecture, scheduling, thread management, synchronization primitives, and interrupt handling as threads.
---

## Motivation

- Preemptable
- Real-time scheduling
- Multiprocessor
- User-level threading
- Highly concurrent
- Responsive operation

## Kernel Architecture

- Dispatch kernel thread onto CPU
- Context switching between kernel threads are inexpensive because they are on the same address space
- Kernel threads are fully preemptable, can be scheduled by any CPU
- Use synchronization primitives to prevent priority inversion
  - Lower-priority thread cannot block higher-priority thread
- User kernel thread to provide asynchronous kernel activity (async writes,...)
  - Increase potential concurrency activity (can be handled by other CPUs)
- Interrupts are handled by kernel thread
  - Interrupt threads will be blocked if they encounter a locked synchronization variable
- Support of threads (light weight process)
  - Bridge between user threads and kernel threads
  - Kernel supports the execution of LWP by associating a kernel thread with each LWP
  - LWPs have a kernel thread, not all kernel threads have a LWP
  - LWP M:N kernel thread
- A user-level library uses LWPs to implement user-level threads

## Data Structure

### Traditional

- `user` and `proc` contained all kernel data for process
  - `user` data is swappable
  - `proc` data is not swappable
- `processor` data held in global variables and data structure
- Kernel stack of the process (swappable) was allocated with the `user` structure in user area

### Restructured Kernel

- Data:
  - Data with each LWP, LWP's kernel thread
  - Data with each process
  - Data with each processor
- `proc`: per-process data
  - List of kernel threads
  - Pointer to process address space
  - User credentials
  - List of signal handlers
  - Vestigial `user` structure (no longer need to swap)
- `lwp`: per-lwp data
  - PCB
  - Syscall args
  - Resource usage
  - Pointer to kernel threads, process structures
  - **Kernel stack** of the thread is allocated with the LWP data structure in **swappable area**
    - Kernel stack is swappable but kernel thread is not
    - Kernel stack is used to save user-level thread states
    - Kernel stack is specific to execution of a particular LWP -> need to be saved together
- `kthread`: per-thread-data (**not swappable**)
  - Registers
  - Scheduling class
  - Dispatch queue links
  - Pointers to the **stack and the associated LWP, process and CPU structures**
  - Threads are linked on a list of threads for the process + on a list of all existing threads in the system
- `cpu`
  - Pointers to the currently executing thread
  - Idle thread
  - Current dispatching and interrupt handling information
- To speed up access to the thread, LWP, process and CPU, use `%g7` registers to point to the current thread structure

## Scheduling

- Operates on thread instead of process
- Classes: time-sharing, real-time (fixed priority)
- Dispatcher chooses threads with greatest priority
- Preemption is disabled on small portion of code
  - SunOS 5 is fully preemptable which means kernel thread can be interrupted by higher priority kernel threads
  - **BUT**: preemption is disabled to protect critical section to protect shared kernel data structure
  - Further details can be found in [Khanna 1992]

## System Threads

- Scheduled like any other threads, usually belong to the system scheduling class
- Have no need for LWP structures
- Thread structure and stack can be allocated together -> non swappable
- Segment driver:
  - Handle stack allocation
  - Handle virtual memory allocations
  - Protect against stack overflow

## Mutex

- Held for short interval
- Mutexes are not recursive
  - Owner cannot call again
- Caller must also release lock
- Mutex:
  - Adaptive mutex (default policy)
    - Spins while owner is running
    - Poll owner status in the spin-loop
    - Sleep when owner is not running (owner may be interrupted by other threads -> owner sleeps -> cannot proceed to release lock)
  - Spin mutex
    - Spin to check if lock has become available
    - **Interrupt is disabled** to prevent deadlock

## Interrupts

### Traditional

- Interrupts level must be raised before lock, lower after lock is released
  - Expensive operations
  - Subsystem are interdependent, interrupt lines and priority can be shared with other modules

### SunOS 5

- Interrupts as asynchronous, high priority threads that will be dispatched
- Enabled interrupt handlers to sleep if required

### Implementing Interrupts as Threads

#### Previous SunOS Version

- Interrupted process is held captive until interrupts returns
- Interrupts are handled on the kernel stack of the interrupted process
- Kernel sync with interrupt handler by blocking out interrupts in while in critical sections

#### SunOS 5

- Preallocate interrupt threads
- Kernel do minimal amount of works to switch to interrupt threads -> not fully kernel thread yet
- The interrupted thread is pinned and cannot be processed by CPU
- If interrupt thread is blocked -> save states -> become full-fledged thread -> can be schedule -> returns to pinned thread

### Interrupt Thread Cost

- 40 instructions
- Convert into real thread only when there is contention
- Preallocated for each active interrupt level (memory usage) -> 8KB

## Summary

- SunOS 5.0 is a multithreaded and symmetric multiprocessor version of the SVR4 kernel
- Features:
  - Fully preemptible, real-time kernel
  - High degree of concurrency on symmetric multiprocessors
  - Support for user threads
  - Interrupts handled as independent threads
  - Adaptive mutual-exclusion locks
