****
# The Recovery Manager of a Data Management System

**Authors:** Jim Gray, Paul McJones, MIKE BLASGEN, BRUCE LINDSAY, RAYMOND LORIE, TOM PRICE, FRANCO PUTZOLU, AND IRVING TRAIGER

**Published in:** Computing Surveys, Vol.13, No.2, June 1981

# Introduction

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

# Description of System R Recovery Manager
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
# Implementation of System R Recovery
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

# Evaluation
- nontrivial to implement
- each txn commits adds two I/O to the cost of the transaction


> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=1&selection=90,1,113,1&color=yellow|The Recovery Manager of a Data Management System, p.1]]
> >  The recovery manager of such a system in turn ease the task of writing fault-tolerance application programs
> 
> introduction

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=1&selection=178,22,255,11&color=yellow|The Recovery Manager of a Data Management System, p.1]]
> > A collection of s u c h s t a t e m e n t s is r e q u i r e d to m a k e a c o n s i s t e n t t r a n s f o r m a t i o n o f t h e d a t a b a s e . T o t r a n s f e r f u n d s f r o m o n e a c c o u n t to a n o t h e r , for e x a m p l e , r e q u i r e s t w o S Q L s t a t e m e n t s : o n e to d e b i t t h e first a c c o u n t a n d o n e t o c r e d i t t h e seco n d a c c o u n t . I n a d d i t i o n , t h e t r a n s a c t i o n p r o b a b l y r e c o r d s t h e t r a n s f e r in a h i s t o r y file for l a t e r r e p o r t i n g a n d for a u d i t i n g p u r poses. 
> 
> the needs of consistency

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=75,0,81,42&color=yellow|The Recovery Manager of a Data Management System, p.2]]
> > ensures its correctness by ensuring that it performs the desired transformation on both the database state and the outside world
> 
> > [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=85,2,92,22&color=yellow|The Recovery Manager of a Data Management System, p.2]]
> > atomic: either all actions are performed (the transaction has an effect) or the results of all actions are undone (the transaction has no effect);
> 
> > [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=94,3,98,7&color=yellow|The Recovery Manager of a Data Management System, p.2]]
> > urable: once the transaction completes, its effects cannot be lost due to computer failure
> 
> > [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=100,2,111,9&color=yellow|The Recovery Manager of a Data Management System, p.2]]
> > consistent: the transaction occurs as though it had executed on a system which sequentially executes only one transaction at a time
> 
> where is "isolation" property?

> [!PDF|important] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=112,34,159,1&color=important|The Recovery Manager of a Data Management System, p.2]]
> > the SQL programmer brackets the transformations with the SQL statements, BEGIN__ TRANSACTION to signal the beginning of the transaction and COMMIT__ TRANSACTION to signal its completion. If the programmer wants to return to the beginning of the transaction, the command RESTORE__TRANSACTION will undo all actions since the issuance of the BEGIN__TRANSACTION command 
> 
> semantic

> [!PDF|important] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=179,0,223,17&color=important|The Recovery Manager of a Data Management System, p.2]]
> > System R generally runs several transactions concurrently. The concurrency control mechanism of System R hides such concurrency from the programmer by a locking technique [EswA76, GRAY78, NAUM78] and gives the appearance of a consistent system
> 
> support for concurrency

> [!PDF|important] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=227,0,260,4&color=important|The Recovery Manager of a Data Management System, p.2]]
> > System R consists of an external layer called the Research Data System (RDS), and a completely internal layer called the Research Storage System (RSS) 
> 
> structure

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=262,0,281,1|The Recovery Manager of a Data Management System, p.2]]
> > The external layer provides a relational data model, and operators thereon. It also provides catalog management, a data dictionary, authorization, and alternate views of data.
> 
> User-facing relational model

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=2&selection=304,0,350,10|The Recovery Manager of a Data Management System, p.2]]
> > The RSS is a nonsymbolic record-at-atime access method. It supports the notions of file, record type, record instance, field within record, index (B-tree associative and sequential access path), parent-child set (an access path supporting the operations PARENT, FIRST__CHILD, NEXT__SIBLING, PREVIOUS__SIBLING with direct pointers),
> 
> low-level internal

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=3&selection=191,11,207,26|The Recovery Manager of a Data Management System, p.3]]
> > also responsible for recovering the data to their most recent consistent state in the event of transaction, action, system, or media failure or a user request to cancel the transaction.
> 
> transaction and recovery at RSS level


> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=4&selection=56,0,67,9|The Recovery Manager of a Data Management System, p.4]]
> > The recovery manager eases the task of writing fault-tolerant programs.
> 
> motivation

![[Pasted image 20260429101837.png]]
> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=5&selection=97,0,101,7|The Recovery Manager of a Data Management System, p.5]]
> > The transaction model is an unrealizable ideal. At best, careful use of redundancy minimizes the probability of unrecoverable failures and consequent loss of committed updates
> 
> redundant copies are needed



> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=5&selection=147,14,185,11|The Recovery Manager of a Data Management System, p.5]]
> > Each RSS action is atomic-it either happens or has no effect--and consistent--if any two actions relate to the same object, they appear to execute in some serial order. These two qualities are ensured by (1) undoing the partial effects of any actions which fail and (2) locking necessary RSS resources for the duration of the action.
> 
> atomic + consistency

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=5&selection=230,0,241,24|The Recovery Manager of a Data Management System, p.5]]
> > In a multiuser environment, transactions take on the additional attribute that any two transactions concurrently operating on common objects appear to run serially (i.e., as though there were no concurrency). This property is called consistency and is handled by the RSS lock subsystem [ESWA76, GRAY76, GRAY78, NAUM78].
> 
> concurrency enforced using lock

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=6&selection=123,0,131,44|The Recovery Manager of a Data Management System, p.6]]
> > The RSS defines the additional notion of transaction save point. A save point is a firewall which allows transaction undo to stop short of undoing the entire transaction
> 
> save point

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=7&selection=109,0,113,16|The Recovery Manager of a Data Management System, p.7]]
> > This model of recovery is a subset of the recovery model formulated by Davies and Bjork [BJOR73, DAVI73]
> 
> references

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=7&selection=113,18,169,6|The Recovery Manager of a Data Management System, p.7]]
> > Unlike their model, System R transactions have no parallelism within a transaction (i.e., if multiple nodes of a network are needed to execute a single transaction, only one node executes at a time). Further, System R allows only a limited form of transaction nesting via the use of save points (each save point may be viewed as the start of an internal transaction). These limitations stem from our inability to find an acceptable implementation for the more general model.
> no acceptable implementation


> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=7&selection=179,0,180,6|The Recovery Manager of a Data Management System, p.7]]
> > All persistent System R data are stored in files.
> 
> persistent data = file as 4096-byte pages

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=7&selection=184,26,190,19|The Recovery Manager of a Data Management System, p.7]]
> > A buffer manager maps all the files into a virtual memory buffer pool shared 
> 
> buffer pool map files to memory, volatile

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=8&selection=61,0,110,6|The Recovery Manager of a Data Management System, p.8]]
> > Nonshadowed files have no automatic recovery. T h e user is responsible for making and storing redundant copies of these files. System R simply updates nonshadowed file pages in the buffer pool. Changes to nonshadowed files are recorded on disk when the pages are r e m o v e d from the buffer pool (by the L R U algorithm) and when the file is saved or closed
> 
> temporary scratch file, intermediate files

> [!PDF|] [[The Recovery Manager of a Data Management System.pdf#page=8&selection=111,15,121,15|The Recovery Manager of a Data Management System, p.8]]
> > The RSS maintains two online versions of shadowed files, a shadow version and a current version
> > [!PDF|important] [[The Recovery Manager of a Data Management System.pdf#page=8&selection=123,0,125,30&color=important|The Recovery Manager of a Data Management System, p.8]]
> > R S S actions affect only the current version of a file and never alter the shadow version
> 
> current version = working copy, shadow version = backup copy

> [!PDF|important] [[The Recovery Manager of a Data Management System.pdf#page=8&selection=239,9,264,4&color=important|The Recovery Manager of a Data Management System, p.8]]
> >  when a shadow page is updated in the buffer pool for the first time, a new disk page frame is assigned to it. Thereafter, when that page is written from the buffer pool or read into the buffer pool, the new frame is used 
> 
> only modified page get new page frame

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=9&selection=45,0,57,5&color=yellow|The Recovery Manager of a Data Management System, p.9]]
> > The paper by Lorie [LoRI77] describes the implementation in greater detaft.
> 
> reference

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=9&selection=67,0,78,17&color=yellow|The Recovery Manager of a Data Management System, p.9]]
> > shadow-version/current-version dichotomy has strong ties to the old-master/ new-master dichotomy common to most batch EDP systems
> 
> > [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=9&selection=85,12,87,40&color=yellow|The Recovery Manager of a Data Management System, p.9]]
> > his technique does not seem to generalize to concurrent transactions on a shared file
> 
> need additional mechanism for transaction

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=9&selection=123,1,139,30&color=yellow|The Recovery Manager of a Data Management System, p.9]]
> > he shadow mechanism is combined with an incremental log of all the actions a transaction performs
> 
> incremental log for transaction

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=9&selection=244,11,245,42&color=yellow|The Recovery Manager of a Data Management System, p.9]]
> >  transaction modifies a logged file, a new record is appended to the log.
> 
> log mechanism

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=10&selection=226,4,235,2&color=yellow|The Recovery Manager of a Data Management System, p.10]]
> > The transaction log is written to disk before the shadow database is replaced by the current database state
> 
> transactions's effect is durable


> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=10&selection=238,1,258,32&color=yellow|The Recovery Manager of a Data Management System, p.10]]
> > The transaction commit action writes a commit log record in the log buffer and then forces all the transaction's log records to disk
> 
> undo uncommitted update + transaction redone from the shadow stage

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=11&selection=28,0,37,16&color=yellow|The Recovery Manager of a Data Management System, p.11]]
> > The effect of any uncommitted transaction can be undone by reading the log of that transaction backward, undoing each action in turn. 
> 
> undo mechanism


> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=11&selection=122,0,130,1&color=yellow|The Recovery Manager of a Data Management System, p.11]]
> > One can easily restore a transaction to its beginning by undoing all its updates and then releasing all its locks and dropping all its cursors 
> 
> transaction save points


> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=11&selection=136,36,166,5&color=yellow|The Recovery Manager of a Data Management System, p.11]]
> > To restore to a save point, the recovery manager must know the name and state of each active cursor and the name of each lock held at the save point
> 
> what  RSS needs for save point

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=11&selection=282,1,302,7&color=yellow|The Recovery Manager of a Data Management System, p.11]]
> >  checkpoint records information on disk which helps locate the end of the log at restart and correlates the database state with the log state. A checkpoint saves all logged shadow files so that no work prior to the checkpoint will have to be redone at restart
> 
> system checkpoints limit the amount of work at restart

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=12&selection=65,0,80,27&color=yellow|The Recovery Manager of a Data Management System, p.12]]
> > The RSS uses a lower level of consistency, augmented by a transaction log, to produce a transaction-consistent state. The RSS implements checkpoints which are snapshots of the system at a time when no RSS actions are in progress
> 
> RSS approach to system checkpoint instead of quiescing

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=12&selection=92,1,98,4&color=yellow|The Recovery Manager of a Data Management System, p.12]]
> > Checkpoints are taken after a specified amount of log activity or at system operator request. At checkpoint, a checkpoint record is written in the log. The checkpoint record contains a list of all transactions in progress and pointers to their most recent log records
> 
> how system checkpoint works

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=15&selection=31,34,41,38&color=yellow|The Recovery Manager of a Data Management System, p.15]]
> > is essential that all transactions lock all updates in exclusive mode and hold all such locks until the transaction is committed or undone. In fact System R automatically acquires b
> 
> recovery safety

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=15&selection=60,2,61,23&color=yellow|The Recovery Manager of a Data Management System, p.15]]
> > nnot tolerate deadlock (we do not want to have to undo undo's)
> 
> 2nd issue in recovery

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=15&selection=84,12,90,7&color=yellow|The Recovery Manager of a Data Management System, p.15]]
> > ks because other RSS actions are in progress and because RSS actions release some locks at the end of each RSS action (e.g., physical page locks when logical rec
> 
> lockings are required

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=15&selection=111,0,131,22&color=yellow|The Recovery Manager of a Data Management System, p.15]]
> >  deadlock victims; whenever they get into a deadlock with some other transactions, the other transactions are preempted.
> 
> golden txn has higher priority


> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=15&selection=185,0,202,6&color=yellow|The Recovery Manager of a Data Management System, p.15]]
> > Writing recoverable actions (ones which can undo and redo themselves) is quite hard. Subjectively, writing a recoverable action
> 
> implementation cost

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=16&selection=62,29,64,15&color=yellow|The Recovery Manager of a Data Management System, p.16]]
> >  Each transaction commit adds two I/Os to the cost of the transaction
> 
> IO overhead

> [!PDF|yellow] [[The Recovery Manager of a Data Management System.pdf#page=16&selection=79,1,108,3&color=yellow|The Recovery Manager of a Data Management System, p.16]]
> > n another application in which the database is all resident in central memory, the log accounts for all of the disk I/O. IMS Fast Path solves this problem by logging several transactions in one I/O so that one gets less than one log I/O per transaction. The shadow mechanism when used with large databases often implies extra I/O, both during normal operation and at check-point. 
> 
> 