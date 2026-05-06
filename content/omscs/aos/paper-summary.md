# 1. The Recovery Manager of a Data Management System



## Application Interface to System R

The paper describe the recovery subsystem of System R, to help developer writing fault-tolerance applications. System R is a database system that supports the relational model using SQL.

A collection of statements is required to make sure that the database is consistent after transformations. Which requires characteristics: atomic, durable and support for concurrency using locks.

## Structure of System R

- Research Data System (RDS) - external layer
	- provides a relational data model + operators
	- manipulated using SQL
- Research Storage System RSS - internal layer
	- record-at-a-time access method
	- file, record type, record instance, field within record, index(B-tree)
	- support for transaction
	- responsible for recovering data to the most consistent state

## Model of Failures

![[Pasted image 20260429140643.png]]
- transaction model is an unrealizable ideal -> need redundancy for unrecoverable failures and loss of uncommitted updates

## Transaction

- atomic: actions either happens or has no effect
- consistent: actions on shared object need to be appear to execute in some serial order
- How?
	- undoing partial effects
	- locking necessary resources during the transaction
		- RSS lock subsystem 
- Sequence of actions inside BEGIN ... COMMIT
	- ABORT to undo action
		- undo all actions of that transactions
	- COMMIT = successful completion of transaction  -> must persist
	- UNDO undoes the effects of a transaction to a save point

## Transaction Save Points

- have multiple checkpoints to undo instead of a whole transaction
- each save points is numbered and transaction begin with 1
- application creates a save point using SAVE action

## Summary

- model of recovery is a subset of recovery model by Davies and Bjork[BJOR73, DAVI73]
- System R txn have no parallelism within a transaction (only one node execute at a time)
- limited form of txn nesting using save points
- LIMITATIONS from inability to find an acceptable implementation

## Files, Versions, and Shadows

- persistent data are stored in files
- buffer manager maps all the files into a virtual memory buffer pool shared by all users
- LRU is used to evict pages from the pool
- File carries a particular recovery protocol
	- shadowed: actual transaction operations
		- shadow file: always consistent, coherent snapshot of file
			- after system restarts, restore shadowed files to their shadow version
		- current file: live working copy that transaction activities operate on
			- lives primary in buffer pool
			- does not survive restart
			- commit transaction requires flushing all log records to disk
			- logs can be use to redo committed changes starting from the shadow state
	- nonshadowed
		- no automatic recovery
		- updates directly in the buffer pool
		- for performance and simplicity: temporary files, intermediate working files

## Logs and the DO, UNDO, REDO Protocol

- old-master/new-master does not generalize enough for concurrent transactions on a shared file
- requires support for COMMIT, ABORT, UNDO + handles deadlock, system overload, unexpected user-disconnect
- need to combine **shadow mechanism + incremental log**
- RSS update actions write a log record
- records are aggregated by transaction and save to a common log file
- shadowed file: logged and not logged
	- logged files saving and restoration are controlled by RSS
	- non-logged shadowed files are responsibility of users
- LOG makes shadows redundant + shadow mechanism is expensive for large file
- RSS operation
	- DO: action + write LOG RECORD
	- UNDO: undoes action using LOG RECORD
	- REDO: redoes action using LOG RECORD

## Commit Processing

- System R ensures that uncommitted transaction can be undone and committed transaction can be redone
- transaction commits when commit records are flushed to disk
	- if system crashes prior to txn commit-> abort transaction using log record
	- if system crashed after the writing of the commit record -> transaction can be redone
    
## Transaction Save Points

- undoing all its update + releasing all locks + dropping all its cursors
- to restore a save point, the recovery manager must know the name + state of cursor + lock at save point

## System Checkpoint
- records information on disk
- saves all logged shadow files -> dont need to redone at restart
- trade-off between how frequent checkpoints are take
	- checkpoints frequent -> fast restart but overhead is high
- checkpoint implementation using **quiescing** the system is simple
	- stop the world until all in-progress transaction complete
	- long interrupts in system availability
- RSS uses transaction log to produce a transaction-consistent state
	- checkpoints = snapshots of the system at a time when no RSS actions are in progress
- Checkpoints at a periodically time or needed at system request
- Checkpoints records a list of all transactions in progress and pointers to their most recent log records

## Recovery and Locking

- required lock all updates in exclusive mode + hold locks until transaction is committed/undone
- cannot tolerate deadlock
	- mark **undo** transaction as "golden"
	- "golden" transaction has higher priority  -> other transactions will be preempted
	- only one golden transaction can be executed at a time

## Evaluation

- nontrivial to implement
- each txn commits adds two I/O to the cost of the transaction
- work incrases with larger database + high transaction rates (significant at 10 txn/s)
- disk-based log eliminates operator intervention at system restart
- transaction save points are not available to application program using SQL language
    -> unsolved language-design isue for SQL
- **major virtue** of shadow: system restart with RSS action-consistent state
- **shadows for large files was a mistake**
    -> author considers WAL(Write-ahead log)
    - adoption of shadows is historical
    - shadow mechanism is complex + expensive
    - consume large amount of disk space for directories

# 2. Clustered-Based Scalable Network Services

## Motivation

- a general layered architecture for building cluster-based scalable network services
    - using stateless workers (similar to microservices)
    - BASE rather than ACID -> trading consistency for availability + softstate for failure management
- motivation
    - network appllications: easier to maintain + evolve than desktop applications
        -> simplify software distribution, customer service, dealing with platform and versions
- lower layer: handles scalability, availability, load balancing, monitoring + visualization
- middle layer: caching, transforamtion, aggregration, personalization
- top layer: composition of transformation, aggregation
- advantages of clusters:
    - incremental scalability -> parallel
    - high availablity -> redundancy
    - cost/performance + maintainance
        - commodity building blocks > high-end, low-volume machines
- challenges of clusters
    - administration
    - commodity PC in a cluster is not powerful enough -> need well-circumscribed functional responsibilities
    - partial failures
    - shared state
- BASE
    - value to user is not consistency or durability but availability
        - statle: temporarily tolerate
        - soft state: can be regenerated
        - approximate: delievered quickly > exact answer slowly
    - eventual consistency: prioritizes performance by avoding blocking commits

## Architecture

- propose functional organization
    - front-ends: interface seen by the outside world
    - worker pool: caches + service-speciifc modules
    - cusomization database: store user profiles
    - manager: balances load across workers + spawn additional workers
    - monitor: for system management supports tracking + visualization of system behaviors
    - system-area network: low-latency, high-bandwidth interconnect

- TACC programming model
    - transformation: jpeg scaling, filtering, compresion
    - aggregation: coolecting and collating data from multiple sources
        - gathering results from database partitions
    - caching: storing original, intermediate, post transformation data
    - customization: use ACID database to store user-specific preferences

## Validation

- validated through two services: TranSend (UC Berkeley) + HotBot (Inktomi)
- TranSend: web distillation/caching proxy
    - composable TACC workers
    - dynamic load balancing via centralized Manager
    - process-peers/soft state fault tolerance
    - gdbm with read caches for user profiles
    - commodity PCs (Ultra-1 class) as scaling unit
- HotBot: large-scale search engine
    - fixed search application workers
    - static load balancing via database partitioning
    - RAID storage and fast restart for fault tolerance
    - Parallel Informix (ACID) server for user profiles
    - mix of SPARCserver nodes

## Performance Insights (TranSend)

- linear scaling: adding hardware -> linear throughput improvement (~23 req/s per distiller)
- latency reduction: real-time distillation reduces end-to-end latency by 3-5x for dialup users
- resource efficiency: single Ultra-1 serves 25,000 dialup IP users
- burst management: "overflow pool" of workstations recruited by Manager for load spikes

## Economic and Administrative Impact

- low marginal cost: ~25 cents/user/month for ISP distillation services
- operational savings: 50%+ cache hit rates eliminate need for 1-2 T1 lines -> hardware pays for itself in ~2 months
- administrative simplicity: soft state + process-peer fault tolerance -> robust with minimal intervention
    - faulty workers crash + restart by Manager without compromising service


