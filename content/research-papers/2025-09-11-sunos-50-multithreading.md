# Beyond Multiprocessing: Multithreading the SunOS Kernel

**Authors:** J. R. Eykholt, S. R. Kleiman, S. Barton, R. Faulkner, A. Shivalingiah, M. Smith, D. Stein, J. Voll, M. Weeks, D. Williams (SunSoft, Inc.)

**Published in:** Summer '92 USENIX (June 8-12, 1992, San Antonio, TX)

---

## Engineering Research Paper

### 1. What is your take-away message from this paper?

- The paper provides a novel approach that allows OS to support multi-threads by using LWP (Lightweight Processes)
- Treating signal/interrupt handlers as threads helps reduce resource contention
- Adaptive mutex implementation helps reduce wasted CPU spinning cycles
- The M:N model is not relevant in today's context. Hardware resources are more abundant, and the overhead of managing the M:N model outweighs its benefits. Most operating systems today support the 1:1 model because kernel threads can be created much more freely now.

---

### 2. What is the motivation for this work?

- What is the **people problem** and the **technical problem**?
    
    - **People problems:** SunOS 4 only supports single process; developers could not write multithreaded applications and utilize multi-processor architecture effectively. Kernel threads are not preemptive, causing high priority tasks to be blocked by low priority tasks, which results in poor real-time performance (real-time in this context means that the scheduler does not guarantee that a process will be scheduled within a reasonable upper time range).
    - **Technical problems:** Bounded dispatch and real-time threads require absolute control over scheduling, which requires threads to be preemptive. With preemptive scheduling, high priority tasks can preempt low priority tasks, allowing for better responsiveness and real-time performance. Races and deadlocks in multithread architectures are difficult to manage and can lead to unpredictable behavior. The cost of synchronization is also a concern; synchronization primitives are expensive operations.
    
- **Goal:** SunOS 5 is fully preemptible, has real-time scheduling, and supports user-level multithreading.
    

---

### 3. What is the proposed solution?

- Why is it believed this solution will work?
    
    - **Idea 1: Multi-processor thread support**
        
        - **Context:** Limited by hardware resources at the time, an M:N model is used so that thousands of user threads can exist without straining kernel resources. Multiple threads must be able to run on different processors. Kernel threads are lightweight, fully preemptible, and can be scheduled by any scheduling class.
        - **Traditional approach:** The `user` and `proc` structures contained all kernel data for a process.
        - **Proposed approach:** Uses multiple data structures to divide the process control block into swappable and non-swappable structures. Dividing the process control block into multiple data structures helps with the performance of context switching. Hard state (non-swappable) is needed in every process so that the kernel has enough information for making scheduling decisions. Light state (swappable) is only needed by the user program when it is running. `proc` contains `user` data to form a complete process control block. A process can run one or many threads, so `proc` contains a pointer to a list of kernel threads. Kernel-level threads then point to:
            - `user` structure: contains light state, is swappable
            - `proc` structure: contains hard state, is non-swappable
            - `lwp` structure: contains lightweight process information, is swappable
            - `klwp` structure: contains kernel thread information, is non-swappable
    - **Idea 2: Priority inversion prevention**
        
        - The scheduler prevents priority inversion (high priority threads cannot be blocked by lower priority threads).
        - **Design:**
            - Scheduling class converts relative priority into global priority
            - The dispatcher chooses the task with the highest global priority; if there are tasks with the same priority, round-robin will be used
    - **Idea 3: Event interrupt handling**
        
        - **Context:** Signal/interrupt handlers run in the same address space as kernel threads, which may cause deadlock in handlers if kernel threads have not released the lock.
        - **Traditional approach:** The thread holding the lock must hold interrupt priority high enough so that interrupt handlers cannot interrupt the thread that is currently holding the lock.
        - **Solution:**
            - SunOS treats interrupts as asynchronous, high-priority threads so that interrupt threads can be put to sleep to release the lock
            - Kernel synchronizes with interrupts via synchronization primitives
            - If an interrupt blocks on a synchronization variable, it saves state to transform into a full-fledged thread capable of running on any CPU. Because of this, the OS can context switch back to the pinned thread that is holding the lock
    - **Idea 4: Adaptive mutex**
        
        - *(Traditional approach section appears to be incomplete in the original)*
    

---

### 4. What is the author's evaluation of the solution?

- What **logic, argument, evidence, artifacts**, or **experiments** are presented in support of the idea?
    
    - **Achieved its primary goals:**
        - Fully preemptible, real-time kernel
        - High degree of concurrency
        - Support for user threads
        - Interrupt handlers as independent threads
        - Adaptive mutexes
    - **Downsides:**
        - Thread stacks are large
        - Context switch is still expensive
    

