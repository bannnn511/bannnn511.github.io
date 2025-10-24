****# Chip Multithreading System Need a New Operating System Scheduler

**Authors:** Alexandra Fedorova, Christopher Small, Daniel Nussbaum, and Margo Seltzer (Harvard University, Sun Microsystems)

**Published in:** USENIX 2005

---

## Question–Answer Form

### 1. What is your take-away message from this paper?

At the time the paper was written, schedulers did not take advantage of multithreading in hardware, which led to lost potential performance especially for OLTP workloads where threads have contention for CPU resources. The new metric called instruction delay latency gives useful insight for how to benchmark CPU utilization, but it does not take into account other CPU resources such as caches.

---

### 2. What is the motivation for this work?
- What is the **people problem** and the **technical problem**?
  - Modern server applications (web services, online transaction systems) had poor utilization for CPU pipeline.
- How is it distilled into a **research question**?
  - CMP (chip multiprocessing) and hardware multithreading (MT) were designed to improve processor utilization for OLTP workloads, but the scheduler policy did not take advantage of new CPU architecture.
- Why doesn't the people problem have a **trivial solution**?
  - OLTP workload requires hundreds of threads which leads to 10^27 combinations to evaluate, hence the need for different designs
  - Modeling resource contention is a hard problem; good prediction is difficult to achieve
- What are the **previous solutions**, and why are they **inadequate**?
  - Previous solutions ran on MT systems which yielded 17% improvement but were not designed for CMP.

---

### 3. What is the proposed solution (hypothesis, idea, design)?
- Why is it believed this solution will work?
  - CPI (cycles-per-instruction) is used as a heuristic to measure workload
  - From the experiments it is observed that instruction mix between long-latency instruction and short-latency instructions yield the best CPU ultilization because it can interleaves execution from threads
- How does it represent an **improvement**?
  - specialized scheduler for CMT systems has the potential for a much greater gain—it can improve application performance by as much as a **factor of two** over a naïve scheduler.
  - A naïve scheduler can severely hurt performance, potentially making a multithreaded processor perform worse than a single-threaded one. By preventing this poor performance, the new design delivers significant throughput improvements
- How is the solution **achieved**?
  - the paper was able to proved that the current design of scheduler is not good enough and provide several keys factors for future work to consider for new scheduler design
  - considerations for scheduler designs:
    - resource contention
    - metrics such as CPI that can help benchmark, evaluate the effective of the design
    - co-scheduling heuristic seems to be a good policy to take into account

---

### 4. What is the author's evaluation of the solution?
- **Logic**:
	- focus on processor pipeline because this is the source of contention
	- processor pipeline depends on the latencies of the instructions. Instructions with long delay latencies(memory loads) will leave functional unit unused
	- mix instructions of long and short delay instructions can keep the pipeline busy at all time
- **Experiments**:
	- Scenario: compare performance between conventional single-threaded core and on a traditional multiprocessor
	- CMT system simulator toolkit based on multithreading proposed by Laudon et Al
	- RISC pipeline with one set of functional unit. CPU has 4 hardware contexts per CPU core. Each core has a single shared TLC and L1 Data and instruction caches. L2 cache is shared by all CPU cores on the chip
	- Alternatives: SMT(simultaneous multithreaded) systems where each core has multiple set of function units on each CPU core
	- Workloads:
		1. CPU bound workload with 4 threads that execute only ALU instructions
		2. Memory bound workload with delay latency of 4 cycles
	- Configurations:
		1. A: singled-threaded processor
		2. B: multithreaded processor with four hardware contexts(but only 1 functional unit)
		3. C: 4-way multiprocessor
- **Results**
	- CPU-bound workload: 
		- A ~~ B
		- C = 4x A or B
	- Memory-bound workload:
		- B ~~ C
		- B and C = 4x A

---

### 5. What is your analysis of the identified problem, idea, and evaluation?

- Today schedulers have been improved to take advantage of CMP and MT architectures:
	- Linux has improved its CFS scheduler to be SMT aware but still lacking
	- Window 10, 11 and Mac OS has topology aware

---

### 6. What are the paper's contributions?
- **Author's view:**
	- Addressing performance loss
	- Demonstration current scalability failures
	- Metrics suggestions for future experiments
	- Able to prove significant performance gains
	- Heuristics strategy for scheduler design

---

### 7. What are future directions for this research?
- **Author's suggestions:**
	- Techniques for inferring single-threaded CPI, given CMT CPI
	- Determining the effects of cache contention on the throughput of co-scheduled threads. 
	- Investigating other workload characteristics, e.g., static instruction mix, to improve scheduling decisions. 
	- Studying the nature and dynamics of CPIs exhibited by real workloads to understand whether this is a viable metric to be used for scheduling real applications
	- Investigating ways to integrate these ideas with other scheduling policies
	- **Testing our scheduling ideas on real workloads.**

---

### 8. What questions are you left with?
- Q1: How do current schedulers take advantage of new hardware?
- Q2: How does Window use **processor group** with **core topology info**
- Q3: How does Apple Silicon with ARM architectures not supporting SMT but still very performant?

---

## NOTES

::: note

### Page 1, Selection 27-28

**PDF Quote:**
> frequent branches and control transfers, can result in processor pipeline utilization as low as 19%

**Personal Note:** common workload for web services result in poor CPU utilization

:::

::: note

### Page 1, Selection 54-66

**PDF Quote:**
> MT-savvy operating system scheduler could improve application performance by a factor of two

**Personal Note:** **scheduler** that utilize multithreading can improve performance

:::

::: note

### Page 1, Selection 83-85

**PDF Quote:**
> application servers, web services, and on-line transaction processing systems, are notorious for poor utilization of CPU pipeline

**Personal Note:** example for common workloads

:::

::: note

### Page 1, Selection 87-93

**PDF Quote:**
> short stretches of integer operations, with frequent dynamic branches. This negatively affects cache locality and branch prediction and causes frequent processor stalls

**Personal Note:** explanation for poor CPU performance

:::

::: note

### Page 1, Selection 121-130

**PDF Quote:**
> do little for transaction processing-like workloads.

**Personal Note:** CPU not designed for common workload (works best for scientific applications)

:::

::: note

### Page 1, Selection 151-172

**PDF Quote:**
> improve processor utilization for transaction-processing-like workloads by offering better support for thread-level parallelism (TLP

**Personal Note:** How MT improves performance

:::

::: note

### Page 1, Selection 172-175 (Note)

**PDF Quote:**
> A CMP processor includes multiple processor cores on a single chip, which allows more than one thread to be active at a time and improves utilization of chip resource

**Personal Note:** CMP processor

:::

::: note

### Page 1, Selection 175-181

**PDF Quote:**
> An MT processor has multiple sets of registers and other thread state and interleaves execution of instructions from different threads

**Personal Note:** MT processor

:::

::: note

### Page 1, Selection 213-219

**PDF Quote:**
> ardware vendors are proposing architectures that combine CMP and MT. We will refer to such systems as chip multithreading (CMT) systems

**Personal Note:** combine both MT and CMP called CMT

:::

::: note

### Page 1, Selection 236-240

**PDF Quote:**
> Our experiments have shown that the potential for performance gain from a specialized scheduler on CMT systems is even greater, and can be as large as a factor of two.

**Personal Note:** a new scheduler is needed to utilize new software

:::

::: note

### Page 2, Selection 4-11

**PDF Quote:**
> Scheduling on single-processor MT systems has been studied before [10-12]. The scheduling algorithms for single-processor MT systems discussed in the literature worked as follows: they ran all combinations of threads that could be co-scheduled, determined which combination(s) yielded the best performance,

**Personal Note:** related works solution

:::

::: note

### Page 2, Selection 16-35

**PDF Quote:**
> An OLTP workload may involve a hundred threads; on a CMT system with 16 hardware contexts, there are 1027 combinations to evaluate.

**Personal Note:** not a trivial problem

:::

::: note

### Page 1, Selection 267-268

**PDF Quote:**
> minimizes resource contention and maximizes system throughput,

**Personal Note:** ideas for new CMT scheduler

:::

::: note

### Page 1, Selection 269-283

**PDF Quote:**
> he scheduler must understand how its scheduling decisions will affect resource contention, because resource contention ultimately determines performance

**Personal Note:** design choices for the new scheduler, what the scheduler must be aware of

:::

::: note

### Page 2, Selection 45-55

**PDF Quote:**
> Our proposal involves building a scheduler that would model relative resource contention resulting from different potential schedules

**Personal Note:** design proposal for the new scheduler

:::

::: note

### Page 2, Selection 73-84

**PDF Quote:**
> Our toolkit models systems with multiple multithreaded CPU cores

**Personal Note:** experiments are designed around new hardware architecture where each CPU cores have multiple threads

:::

::: note

### Page 2, Selection 92-98

**PDF Quote:**
> An MT core has multiple hardware contexts (usually one, two, four or eight), where each context consists of a set of registers and other thread state.

**Personal Note:**

:::

::: note

### Page 2, Selection 100-104

**PDF Quote:**
> switching between contexts on each cycle. A thread may become blocked when it encounters a long latency operation, such as servicing a cache miss

**Personal Note:** Hide cache latency by switching to other threads, while the blocked threads are waiting for data from memory

:::

::: note

### Page 2, Selection 118-134 (Important)

**PDF Quote:**
> his latency-hiding property is at the heart of hardware multithreading

**Personal Note:**

:::

::: note

### Page 2, Selection 181-186

**PDF Quote:**
> SMT systems are more complex and require more chip real estate. We have instead taken the approach of leveraging a simple, classical RISC core in order to allow space for more cores on each chip. This allows for a higher degree of multithreading in the system, resulting in higher throughput for multithreaded and multiprogrammed workloads.

**Personal Note:** Alternative to RISC

:::

::: note

### Page 2, Selection 215-232

**PDF Quote:**
> When assigning threads to hardware contexts, the scheduler has to decide which threads should be run on the same processor, and which threads should be run separately

**Personal Note:** OS scheduler **policy** for CPU optimization. Optimal thread assignment results in high utilization of the CPU

:::

::: note

### Page 2, Selection 235-238 (Important)

**PDF Quote:**
> r. If we are to design a scheduler that can find good thread assignments, we must understand the causes and effects of contention among the threads that share a processor.

**Personal Note:** Contention seems to be the heart of the problem

:::

::: note

### Page 2, Selection 243-264 (Important)

**PDF Quote:**
> The key to understanding why this is the case is the concept of instruction delay latency

**Personal Note:**

:::

::: note

### Page 2, Selection 269-299

**PDF Quote:**
> When a thread performs a long-latency operation, it is blocked; subsequent instructions to be issued by that thread are delayed until the operation completes. We term the duration of this delay the instruction delay latency. ALU instructions have 0 delay latency.1 A load that hits in the L1 cache has a latency of four cycles. A branch delays the subsequent instruction by two cycles

**Personal Note:** instruction delay latency is an important unit to understand the impact of CPU instructions

:::

::: note

### Page 2, Selection 301-302

**PDF Quote:**
> Processor pipeline contention depends on the latencies of the instructions that the workload executes

**Personal Note:** memory loads -> high latency. ALU operations -> no latency

:::

::: note

### Page 3, Selection 554-556 (Important)

**PDF Quote:**
> A, a single-threaded processor; B, a multithreaded processor with four hardware contexts; and C, a four-way multiprocessor

**Personal Note:** comparison profiles

:::

::: note

### Page 3, Selection 558-562

**PDF Quote:**
> A and B will perform comparably; C will have a throughput four times greater than the other two systems, because it has four times as many functional units.

**Personal Note:** B has four hardware contexts but has only a single functional unit which leads to resource contention for CPU bound workload -> A and B performance is the same

:::

::: note

### Page 3, Selection 584-588

**PDF Quote:**
> When running the memory-bound workload, System B and System C will perform comparably, outperforming System A by a factor of four2.

**Personal Note:** B and C performance is comparable because of multi hardware contexts which hide IO latency

:::

::: note

### Page 4, Selection 0-26

**PDF Quote:**
> This simple experiment demonstrates that the instruction mix, and, more precisely, the average instruction delay latency, can be used as a heuristic for approximating the processor pipeline requirements for a workload.

**Personal Note:** the proposed metric provides useful information for the scheduler to make scheduling decisions.

:::

::: note

### Page 4, Selection 27-42

**PDF Quote:**
> A thread with an instruction mix dominated by long-latency instructions can leave functional units underutilized. Therefore, it is logical to co-schedule it with a thread that is running a lot of short-latency instructions and has high demand for functional units

**Personal Note:** scheduling strategy that optimizes instruction delay latency

:::

::: note

### Page 4, Selection 46-49

**PDF Quote:**
> this technique does not take into account effects of cache contention that surface when threads with large working sets are running on the same processor.

**Personal Note:** limitations of the proposed model

:::

::: note

### Page 5, Selection 50-52

**PDF Quote:**
> envision some limitations of this approach. CPI does not give precise information on the types of instructions that the workload is executing.

**Personal Note:** limitations

:::

::: note

### Page 5, Selection 109-125

**PDF Quote:**
> CMT systems need new schedulers: a naïve scheduler may squander up to half of available application performance, and existing SMT scheduling algorithms do not scale to dozens of threads.

**Personal Note:**

:::
