# MapReduce: Simplified Data Processing on Large Clusters

## Abstract
- processing and generating large data sets
- `map`: process a K/V pair -> generate a set of intermediate K/V pairs
- `reduce`: merge intermediate K/V pairs
- Programs:
	- automatically parallelized
	- executed on a large cluster of machines
- Runtime:
	- partitioning input data
	- scheduling program's execution across a set of machine
	- handling machine failures
	- managing the required inter-machine communication

## Motivation
- input data is large + computations have to be distributed
### New abstraction
- express simple computation
- hides the messy details of parallelization
- fault tolerance
- data distribution + load balancing in library

## Programming model

-  computation takes a set of **input** K/V pairs -> produces a set of **output** K/V pairs
- user expresses the computation as two functions: `Map` and `Reduce`
- 
### Example
```
map(String key, String value):
	// key: document name
	// value: document contents
	for each word w in value:
		EmitIntermediate(w, "1");


reduce(String key, Iterator values):
	// key: a word
	// values: a list of counts
	int result = 0;
	for each v in values:
		result += ParseInt(v);
	Emit(AsString(result));
```

## Types
```
map(k1,v1) -> list(k2,v2)
reduce(k2, list(v2)) -> list(v2)
```

## More examples
- Distributed Grep
- Count of URL Access Frequency
- Reverse Web-Link Graph
- Term-Vector per Host
- Inverted Index
- Distributed Sort

## Implementation

- Different implementations of MapReduce interface are possible, depends on the environment
	- small shared-memory machine
	- large NUMA multi-processor
	- large collection of networked machines

### Execution Overview

- `Map`: distributed across multiple machines by automatically partitioning the input
- Input splits can be processes in parallel by **different machines**
- `Reduce` invocations are distributed by partitioning the intermediate key  into `R` pieces
	- using partitioning function `hash(key) mod R`
	- number of partitions `R` + `partition function` are specified by the user
- Sequence:
	1. MapReduce library in the user program first split the input files into M pieces
		1. starts up many copies of the program on a cluster of machines
	2. `Master`: a special copies of the program
		1. other copies are `workers`
		2. `master` assign works to the `workers`
		3. `M Map` tasks and `R Reduce`tasks to assign
		4. `master` picks idle workers and assign each one a `map` task and a `reduce` task
	3. `worker` who is assigned a `map` task
		1. reads the contents of the corresponding input split
		2. parse K/V pairs and passes each pairs to the user-defined `Map`
		3. the intermediate K/V pairs produced my the `Map` function are buffered in memory
	4. periodically, the buffered pairs are written to local disk, partitioned into R regions
			1. locations of these buffers pairs on the local disk are passed back to the `master`
			2. `master` forwards theses locations to the `reduce workers`
	5. `reduce worker` is notified by the master
		1. use `rpc` to read the buffered data from local disk of the map workers
		2. `reduce worker` sorts all intermediate data by the intermediate keys
			1. different keys map to the same reduce task
			2. if data is to large -> an external sort is used
	6. `reduce worker` iterates over the sorted intermediate data
		1. for each unique key -> passed the key and the corresponding set of intermediate values to the users\`s `Reduce` function
		2. the output the `Reduce` function is appended to the final output file for this reduce partition
	7. when all `map` tasks and `reduce` tasks have been completed -> `master` wakes up user program, the `MapReduce` returns back to user code
- Output of the execution are stored in the R output files -> pass as inputs to other MapReduce call
### Master Data structures
- `master` stores the state (`idle`, `in-progress`, `completed`) for each tasks + identity of the worker machines
- for each ***`completed`*** tasks, masters stores the location and sizes of the R intermediate **file regions** of produced by map task
	- update to these regions -> signal `map` task as `completed`
	- pushed to workers that have `in-progress` `reduce` tasks

## Fault Tolerance
### Worker Failure
- `master` pings every worker periodically
	- no response from `worker` -> marks the `worker` as failed
	- `completed map` tasks ->`woker` reset back to `idle` -> eligible for scheduling
	- `map` or `reduce` task in progress on failed worker -> reset to `idle` -> rescheduling
	- `completed map` tasks are re-executed on a failure (worker machine) because output is stored on local disks of failed machine
	- `completed reduce` do not need to be re-executed since output is stored in a global file system
	- `reduce` tasks that have not read data from failed worker will read from new worker
- resilient to large-scale worker failures

### Master Failure
- single master -> failure is unlikely -> aborts the MapReduce computation if the master fails
### Semantics in the Presence of Failures
- Deterministic functions
	- when `map` and `reduce` are deterministic functions -> produces the same output as a **non-faulting sequential execution**
		- rely on atomic commits of `map` and `reduce` task
	- Mechanism:
		- in-progress task writes its output to private temporary file
			- `map` : R files (one per reduce task)
			- `reduce`: one file
		- when task completes: `worker` sends a message to `master` and include the names of the R temp files in the message
			- if master have already received a **completion** message of already **completed** map -> ignore message
				- Potential for Duplicate Messages: It's possible that a `worker` might complete a map task and send a completion message to the `master` before the `master` detects the `worker`'s failure. Alternatively, a failed `worker` might recover and resend a completion message for a task that has already been re-executed and completed on another worker
			- otherwise, recored the names of R files in master data structure
- Non-deterministic
	- output will look like it came from a single, consistent run of your non-deterministic code
	- **However**, different reduce task may end up with different results

### Locality
- takes the location information of the input files -> map task on a machine that contains replica of the corresponding input data
## Backup Tasks
- **straggler**: machine that takes unusually long time to complete on of the last computation
- solution:
	- when MapReduce operation is close to completion -> backup executions of the remaining `in-progress` tasks
	- task is mark as `completed`: either primary or backup execution completes

## Combiner function
- significant repetition in the intermediate keys produced by each map task
	-> allow user to specify an optional `Combiner` function that does partial merging of data before send over network
- same code is used for both `Combiner` and `Reduce` function
	- `Combiner`: output written to intermediate file
	- `Reduce`: output written to final output file

## Side-effects
- rely on application writer for atomic and idempotent -> writes to a temporary file and atomically renames this file
- do not support atomic two-phase commits of multiple output files produced by a single task -> multiple output files with cross-file consistency should be **deterministic**

## Skipping Bad Records
- acceptable to ignore a few records (statistical analysis on a large data set) -> skip records in order to make forward progress
- worker installs a signal handler that caches segmentation violations and bus errors

## How does the MapReduce implementation at Google achieve scalability and performance on large clusters?

Google's implementation of MapReduce is designed to run on large clusters of commodity PCs. **Scalability** is achieved through automatic parallelization and distribution of tasks across thousands of machines.

**Performance** is enhanced by several techniques:
- **Data locality optimization**: Reading input data from local disks to minimize network overhead.
- **Combiner function** (optional): Reduces the amount of intermediate data transferred between map and reduce phases.
- **Dynamic task assignment**: Tasks are assigned to workers dynamically for better load balancing.

Additionally, the system includes:
- **Fault tolerance mechanisms** to handle machine failures gracefully.
- **Backup tasks** to mitigate the effects of slow or "straggler" machines.

These features ensure efficient processing of massive datasets with high scalability and performance.