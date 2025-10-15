> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=27,16,28,58|Architecture-Aware OS Kernel Paper, p.1]]
> >  frequent branches and control transfers, can result in processor pipeline utilization as low as 19%
> 
> common workload for web services result in pool cpu ultilization

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=54,40,66,30|Architecture-Aware OS Kernel Paper, p.1]]
> > MT-savvy operating system scheduler could improve application performance by a factor of two
> 
> **scheduler** that ultilize multithreading can improve performance

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=83,1,85,59|Architecture-Aware OS Kernel Paper, p.1]]
> > application servers, web services, and on-line transaction processing systems, are notorious for poor utilization of CPU pipeline
> 
> example for common workloads

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=87,20,93,1|Architecture-Aware OS Kernel Paper, p.1]]
> > short stretches of integer operations, with frequent dynamic branches. This negatively affects cache locality and branch prediction and causes frequent processor stalls
> 
> explaination for pool CPU performance

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=121,0,130,10|Architecture-Aware OS Kernel Paper, p.1]]
> > do little for transaction processing-like workloads.
> 
> CPU not designed for common workload (work best for scientific applications)

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=151,48,172,16|Architecture-Aware OS Kernel Paper, p.1]]
> > improve processor utilization for transaction-processing-like workloads by offering better support for thread-level parallelism (TLP
> 
> How MT improve performance

> [!PDF|note] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=172,18,175,12&color=note|Architecture-Aware OS Kernel Paper, p.1]]
> >  A CMP processor includes multiple processor cores on a single chip, which allows more than one thread to be active at a time and improves utilization of chip resource
> 
> CMP processor


> > [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=175,15,181,8&color=note|Architecture-Aware OS Kernel Paper, p.1]]
> >  An MT processor has multiple sets of registers and other thread state and interleaves execution of instructions from different threads,
> 
> MT processor

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=213,42,219,13|Architecture-Aware OS Kernel Paper, p.1]]
> > ardware vendors are proposing architectures that combine CMP and MT. We will refer to such systems as chip multithreading (CMT) systems
> 
> combine both MT and CMP called CMT

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=236,0,240,1|Architecture-Aware OS Kernel Paper, p.1]]
> > Our experiments have shown that the potential for performance gain from a specialized scheduler on CMT systems is even greater, and can be as large as a factor of two.
> 
> a new scheduler is need to ultilize new software

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=267,11,268,18|Architecture-Aware OS Kernel Paper, p.1]]
> > minimizes resource contention and maximizes system throughput,
> 
> ideas for new CMT scheduler
> > [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=1&selection=269,1,283,44|Architecture-Aware OS Kernel Paper, p.1]]
> > he scheduler must understand how its scheduling decisions will affect resource contention, because resource contention ultimately determines performance
> 
> design choices for the new scheduler, what the scheduler must be aware of

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=45,0,55,44|Architecture-Aware OS Kernel Paper, p.2]]
> > Our proposal involves building a scheduler that would model relative resource contention resulting from different potential schedules
> 
> design proposal for the new scheduler

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=73,0,84,5|Architecture-Aware OS Kernel Paper, p.2]]
> > Our toolkit models systems with multiple multithreaded CPU cores
> 
> experiments are designed around new hardware architecture where each CPU cores have multiple threads> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=92,19,98,62|Architecture-Aware OS Kernel Paper, p.2]]
> > An MT core has multiple hardware contexts (usually one, two, four or eight), where each context consists of a set of registers and other thread state.
> 
> > [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=100,13,104,49|Architecture-Aware OS Kernel Paper, p.2]]
> > switching between contexts on each cycle. A thread may become blocked when it encounters a long latency operation, such as servicing a cache miss
> 
> Hide cache latency by switching to other threads, while the blocked threads are waiting for data from memory

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=118,55,134,14&color=red|Architecture-Aware OS Kernel Paper, p.2]]
> > his latency-hiding property is at the heart of hardware multithreading


> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=181,0,186,27|Architecture-Aware OS Kernel Paper, p.2]]
> > SMT systems are more complex and require more chip real estate. We have instead taken the approach of leveraging a simple, classical RISC core in order to allow space for more cores on each chip. This allows for a higher degree of multithreading in the system, resulting in higher throughput for multithreaded and multiprogrammed workloads.
> 
> Alternative to RISC

> [!PDF|] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=215,0,232,10|Architecture-Aware OS Kernel Paper, p.2]]
> > When assigning threads to hardware contexts, the scheduler has to decide which threads should be run on the same processor, and which threads should be run separately
> 
> OS scheduler **policy** for CPU optimization. Optimal thread assignment results in high ultilization of the CPU

> [!PDF|red] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=235,32,238,31&color=important|📖]]
> > r. If we are to design a scheduler that can find good thread assignments, we must understand the causes and effects of contention among the threads that share a processor.
> 
> Contention seems to be the heart of the problem
> > [!PDF|important] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=243,48,264,25&color=red|📖]]
> > The key to understanding why this is the case is the concept of instruction delay latency

> [!PDF|yellow] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=269,54,299,36&color=yellow|📖]]
> > When a thread performs a long-latency operation, it is blocked; subsequent instructions to be issued by that thread are delayed until the operation completes. We term the duration of this delay the instruction delay latency. ALU instructions have 0 delay latency.1 A load that hits in the L1 cache has a latency of four cycles. A branch delays the subsequent instruction by two cycles
> 
> instruction delay latency is an important unit to understand the impact of CPU instrucions


> [!PDF|yellow] [[Architecture-Aware OS Kernel Paper.pdf#page=2&selection=301,0,302,46&color=yellow|📖]]
> > Processor pipeline contention depends on the latencies of the instructions that the workload executes
> 
> memory loads -> high latency. ALU operations -> no latency