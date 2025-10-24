# Chip Multithreading System Need a New Operating System Scheduler

**Authors:**  Alexandra Fedorova*†, Christopher Small†, Daniel Nussbaum†, and Margo Seltzer* *Harvard University, †Sun Microsystems
**Published in:**

---

## Question–Answer Form

### 1. What is your take-away message from this paper?

- at the time the paper is written, scheduler did not take advantages of multithreading in hardware which leads to lost of potential performance especially for OLTP workload where threads have contention for CPU workload
- new metrics called instruction delay latency give useful insight for how to benchmark CPU ultilization but not taking account of other CPU resources such as caches

---

### 2. What is the motivation for this work?

- What is the **people problem** and the **technical problem**?

  - modern server applications: web services, online transaction system had poor ultilization for CPU pipeline
- How is it distilled into a **research question**?

  - CMP (chip multiprocessing) and hardware multithreading (MT) were designed to improve processor ultilization for OLTP workload but the scheduler policy did not take advantages of new CPU architecture
- Why doesn’t the people problem have a **trivial solution**?

  - OLTP workload requires hundred of threads which leads to 10^27 combination to evaluate. Hence, the needs of different designs
  - modeling resource contention is a hard problem, good prediction is difficult to achieve
- What are the **previous solutions**, and why are they **inadequate**?

  - previous solutions ran on MT systems which yield 17% improvement but did not design for CMP

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

### 4. What is the author’s evaluation of the solution?

- What **logic, argument, evidence, artifacts**, or **experiments** are presented in support of the idea?
  -----------------------------------------------------------------------------------------------

---

### 5. What is your analysis of the identified problem, idea, and evaluation?

- Is this a **good idea**?
- What **flaws** do you perceive in the work?
- What are the most **interesting or controversial ideas**?
- For practical work:

  - Will this **actually work**?
  - Who would **want it**?
  - What would it **take to deliver** it?
  - When might it **become a reality**?

---

### 6. What are the paper’s contributions?

- **Author’s view:**
- **Your view:**

> _(Ideas, methods, software, experimental results, techniques, etc.)_

---

### 7. What are future directions for this research?

- **Author’s suggestions:**
- **Your suggestions:**

> _(Driven by shortcomings, critiques, or opportunities.)_

---

### 8. What questions are you left with?

> List at least **three questions** that remain after reading.
> Avoid simple factual questions that can be answered via a quick search.

- Q1:
- Q2:
- Q3:

## NOTES

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=27,16,28,58|Architecture-Aware OS Kernel Paper, p.1]]
>
>> frequent branches and control transfers, can result in processor pipeline utilization as low as 19%
>>
>
> common workload for web services result in pool cpu ultilization

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=54,40,66,30|Architecture-Aware OS Kernel Paper, p.1]]
>
>> MT-savvy operating system scheduler could improve application performance by a factor of two
>>
>
> **scheduler** that ultilize multithreading can improve performance

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=83,1,85,59|Architecture-Aware OS Kernel Paper, p.1]]
>
>> application servers, web services, and on-line transaction processing systems, are notorious for poor utilization of CPU pipeline
>>
>
> example for common workloads

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=87,20,93,1|Architecture-Aware OS Kernel Paper, p.1]]
>
>> short stretches of integer operations, with frequent dynamic branches. This negatively affects cache locality and branch prediction and causes frequent processor stalls
>>
>
> explaination for pool CPU performance

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=121,0,130,10|Architecture-Aware OS Kernel Paper, p.1]]
>
>> do little for transaction processing-like workloads.
>>
>
> CPU not designed for common workload (work best for scientific applications)

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=151,48,172,16|Architecture-Aware OS Kernel Paper, p.1]]
>
>> improve processor utilization for transaction-processing-like workloads by offering better support for thread-level parallelism (TLP
>>
>
> How MT improve performance

> [!PDF|note] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=172,18,175,12&color=note|Architecture-Aware OS Kernel Paper, p.1]]
>
>> A CMP processor includes multiple processor cores on a single chip, which allows more than one thread to be active at a time and improves utilization of chip resource
>>
>
> CMP processor

>> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=175,15,181,8&color=note|Architecture-Aware OS Kernel Paper, p.1]]
>> An MT processor has multiple sets of registers and other thread state and interleaves execution of instructions from different threads
>>
>
> MT processor

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=213,42,219,13|Architecture-Aware OS Kernel Paper, p.1]]
>
>> ardware vendors are proposing architectures that combine CMP and MT. We will refer to such systems as chip multithreading (CMT) systems
>>
>
> combine both MT and CMP called CMT

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=236,0,240,1|Architecture-Aware OS Kernel Paper, p.1]]
>
>> Our experiments have shown that the potential for performance gain from a specialized scheduler on CMT systems is even greater, and can be as large as a factor of two.
>>
>
> a new scheduler is need to ultilize new software

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=4,0,11,29|Architecture-Aware OS Kernel Paper, p.2]]
>
>> Scheduling on single-processor MT systems has been studied before [10-12]. The scheduling algorithms for single-processor MT systems discussed in the literature worked as follows: they ran all combinations of threads that could be co-scheduled, determined which combination(s) yielded the best performance,
>>
>
> related works solution

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=16,55,35,26|Architecture-Aware OS Kernel Paper, p.2]]
>
>> An OLTP workload may involve a hundred threads; on a CMT system with 16 hardware contexts, there are 1027 combinations to evaluate.
>>
>
> not a trivial problem

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=267,11,268,18|Architecture-Aware OS Kernel Paper, p.1]]
>
>> minimizes resource contention and maximizes system throughput,
>>
>
> ideas for new CMT scheduler
>
>> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=269,1,283,44|Architecture-Aware OS Kernel Paper, p.1]]
>> he scheduler must understand how its scheduling decisions will affect resource contention, because resource contention ultimately determines performance
>>
>
> design choices for the new scheduler, what the scheduler must be aware of

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=45,0,55,44|Architecture-Aware OS Kernel Paper, p.2]]
>
>> Our proposal involves building a scheduler that would model relative resource contention resulting from different potential schedules
>>
>
> design proposal for the new scheduler

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=73,0,84,5|Architecture-Aware OS Kernel Paper, p.2]]
>
>> Our toolkit models systems with multiple multithreaded CPU cores
>>
>
> experiments are designed around new hardware architecture where each CPU cores have multiple threads> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=92,19,98,62|Architecture-Aware OS Kernel Paper, p.2]]
>
>> An MT core has multiple hardware contexts (usually one, two, four or eight), where each context consists of a set of registers and other thread state.
>>
>
>> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=100,13,104,49|Architecture-Aware OS Kernel Paper, p.2]]
>> switching between contexts on each cycle. A thread may become blocked when it encounters a long latency operation, such as servicing a cache miss
>>
>
> Hide cache latency by switching to other threads, while the blocked threads are waiting for data from memory

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=118,55,134,14&color=red|Architecture-Aware OS Kernel Paper, p.2]]
>
>> his latency-hiding property is at the heart of hardware multithreading
>>

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=181,0,186,27|Architecture-Aware OS Kernel Paper, p.2]]
>
>> SMT systems are more complex and require more chip real estate. We have instead taken the approach of leveraging a simple, classical RISC core in order to allow space for more cores on each chip. This allows for a higher degree of multithreading in the system, resulting in higher throughput for multithreaded and multiprogrammed workloads.
>>
>
> Alternative to RISC

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=215,0,232,10|Architecture-Aware OS Kernel Paper, p.2]]
>
>> When assigning threads to hardware contexts, the scheduler has to decide which threads should be run on the same processor, and which threads should be run separately
>>
>
> OS scheduler **policy** for CPU optimization. Optimal thread assignment results in high ultilization of the CPU

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=235,32,238,31&color=important|📖]]
>
>> r. If we are to design a scheduler that can find good thread assignments, we must understand the causes and effects of contention among the threads that share a processor.
>>
>
> Contention seems to be the heart of the problem
>
>> [!PDF|important] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=243,48,264,25&color=red|📖]]
>> The key to understanding why this is the case is the concept of instruction delay latency
>>

> [!PDF|yellow] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=269,54,299,36&color=yellow|📖]]
>
>> When a thread performs a long-latency operation, it is blocked; subsequent instructions to be issued by that thread are delayed until the operation completes. We term the duration of this delay the instruction delay latency. ALU instructions have 0 delay latency.1 A load that hits in the L1 cache has a latency of four cycles. A branch delays the subsequent instruction by two cycles
>>
>
> instruction delay latency is an important unit to understand the impact of CPU instrucions

> [!PDF|yellow] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=301,0,302,46&color=yellow|📖]]
>
>> Processor pipeline contention depends on the latencies of the instructions that the workload executes
>>
>
> memory loads -> high latency. ALU operations -> no latency

> [!PDF|important] [[Architecture-Aware OS Kernel Paper.pdf#page=3&selection=554,28,556,32&color=important|📖]]
>
>> A, a single-threaded processor; B, a multithreaded processor with four hardware contexts; and C, a four-way multiprocessor
>>
>
> comparison profiles

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=3&selection=558,36,562,1|Architecture-Aware OS Kernel Paper, p.3]]
>
>> A and B will perform comparably; C will have a throughput four times greater than the other two systems, because it has four times as many functional units.
>>
>
> B has four hardware contexts but has only a single functional unit which leads to resource contention for CPU bound workload -> A and B performance is the same

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=3&selection=584,0,588,2|Architecture-Aware OS Kernel Paper, p.3]]
>
>> When running the memory-bound workload, System B and System C will perform comparably, outperforming System A by a factor of four2.
>>
>
> B and C performance is comparable because of multi hardware contexts which hide IO latency

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=4&selection=0,0,26,9|Architecture-Aware OS Kernel Paper, p.4]]
>
>> This simple experiment demonstrates that the instruction mix, and, more precisely, the average instruction delay latency, can be used as a heuristic for approximating the processor pipeline requirements for a workload.
>>
>
> the proposed metric provides useful information for the scheduler to make scheduling decisions.

> [!PDF|yellow] [[Architecture-Aware OS Kernel Paper.pdf#page=4&selection=27,57,42,27&color=yellow|Architecture-Aware OS Kernel Paper, p.4]]
>
>> A thread with an instruction mix dominated by long-latency instructions can leave functional units underutilized. Therefore, it is logical to co-schedule it with a thread that is running a lot of short-latency instructions and has high demand for functional units
>>
>
> scheduling strategy that optimizes instruction delay latency

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=4&selection=46,34,49,15&color=red|Architecture-Aware OS Kernel Paper, p.4]]
>
>> this technique does not take into account effects of cache contention that surface when threads with large working sets are running on the same processor.
>>
>
> limitations of the proposed model

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=5&selection=50,12,52,44&color=red|Architecture-Aware OS Kernel Paper, p.5]]
>
>> envision some limitations of this approach. CPI does not give precise information on the types of instructions that the workload is executing.
>>
>
> limitations

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=5&selection=109,40,125,8&color=red|Architecture-Aware OS Kernel Paper, p.5]]
>
>> CMT systems need new schedulers: a naïve scheduler may squander up to half of available application performance, and existing SMT scheduling algorithms do not scale to dozens of threads.
>>
