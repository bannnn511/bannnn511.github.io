# 30/4

## Security

- symmetric of private key encryption, same key for encryption/decryption or different but related to encryption/decryption? -> same
- asymmetric of public key encryption, same key for encryption/decryption or different but related to encryption/decryption? -> different
- Andrew FS
  - secure link : users in campus
  - insecure link: 
  - username/password: exposes to frequently -> MIM attack
  - why use symmetric private key encryption (extent login, performance,...)?
    - for performance, because symmetric is faster then asymmetric
  - core principle: authenticate user, prevent replay attack,...
  - in order to establish rpc session, the bind call in cleartext have to send client id, and encrypt a random number with a key and send to server, ... server increment x+1, and send y random number back to client, what does the client know?
    - client knows the server is genuine + server knows the client is genuine
    - client's key might be compromised
  - why use session key?
    - to not overexposed hsk key
  - Why AFS use symmetric private key?
    - if use public key encryption -> N^2 key-pairs for each user and distribute to all workstations on campus
  - If use public key encryption, do need to send user id on clear text? -> no because public key can be used to identify user
  - 

## Quicksilver

- developed by IBM - 1985
- recovery should be backed into design
- distributed {client, server}
- QS bundles IPC with recovery management using lightweight txn
- a shadow graph structure emerges from client-server interactions
  - transaction tree root = owner + participants
  - Does transaction build-up cause overhead in communication?
    - client-server can choose to use the recovery management
  - Computational overhead and not communication overhead because communication is piggybacked going from one node to another (gonna happen anyway)
    - txn managers on different nodes communicate with no extra overhead as communication is piggybacked on IPC
  - Purpose of transaction? (db, recovery?) -> recovery management
  - One for entire DS or one for each sequence of server-client communication? -> for each server-client communication
  - transaction manager on behalf of clients do log for each client -> forcing to disk (recovery)
    - manager for all server-client interactions on its node
    - open file, talking to window manger for display ... (manger have to log )
  - Log management is common or distinct for each application? -> all applications
    - recovery management is built into OS, common for all applications
      -> careful forcing log onto disk, if fsync on a node -> all logs in memory will be pushed to disk -> can hurt performance
  - Compare QS recovery (all applications) vs LRVM recovery (all applications)
    - both are truth, if applications desire then they can have it
    - QS: applications ask QS
    - LRVM: applications can use LRVM library
  - QS vs LRVM, which is more comprehensive? -> QS is more comprehensive
    - any use system resource -> QS will do everything
      - malloc
      - open window manager
        ==> all have breadcrumbs (buggy software, system crashes, resource leak), QS try to recover everything? -> HOW?
    - LRVM only for memory
  - QS vs LRVM, which has more implementation overhead? -> depends
    - LRVM need set-range -> but might have no changes
    - LRVM use redo log might be created even if no changes are made
    - QS with help of devs, logging only log in memory, QS can do less work while LRVM have to log everything within set-range
    - QS might have to log everything from network, resource -> depends on volume
  - When is txn abort in QS?
    - not aborted at the first indication of failure# 22/4
    - allowing error reporting to continue and partial failures to be cleaned up when the coordinator initiates termination

## LRVM

- LRVM reading
- applications require persistent
  - does not stop with just running process
  - beyond power failure
  - memory is volatile
  - fault tolerance
- file system = persistent data structure
- LRVM -> provide data abstraction -> help write application that requires persistent
  - begin ... end transaction, range of VA (of data structure to be modified)
  - HOW? range of addresses, using undo record incase of rollback
  - commit point -> create a redo log -> persistent storage
  - undo record vs redo log ?
    - undo only during txn
    - redo log is persisted
  - where is undo record? -> memory, only during txn
  - updates to metadata, data structure, is it going to llvm? -> doesnt go to LRVM, go directly into memory to modify using set range
  - at the end of txn, llvm creates a redo log in memory -> flush to disk
    - LLVM synchronously flush to disk? depends (can be no flush), can be parallel (trade of for risk)
  - open a file -> inode into memory by fs -> modify inode in memory -> have to flush do disk -> use LRVM to map inode to VA -> change to VA -> create redo log (change of data structure in memory result in redo log)
    - if didnt have LRVM -> make sure inode memory = inode in disk
  - LRVM txn vs DB txn? LRVM does not support ACID
    - DB txn: multiple txn (concurrent txn) -> need isolation between processes
    - LRVM baked into file server application -> consistency for single application, does not interact with other applications that use LVRM
      - multiple processes? responsibility of developers not LRVM
      - atomicity + durability
  - BEGIN TXN -> create undo record -> END TXN -> create redo log -> log apply to database (truncation)
    - In critical path, how many copies?
      1. undo record
      2. virtual memory changes for redo log in memory
      3. take redo log and put on the disk (can delay for not using log flush)
  - Recovery:
    - LRVM read from tail -> head
    - Why start from tail and not head?
      - reduce the work
      - LRVM reads the log of modified of uncommitted txn from the tail
      - read from head will see redundant work (changes to some record happens all over again)
      - log record {range, data}: {1-10: data} -> {1-10: data2} -> {1-10: data3}

## RioVista

- provides LRVM semantic on top of RIO file cache
- software failure happens more frequent
- assume power failure is non issue
- file cache is battery-backed -> written into disk for recovery purpose
- using mmap file into memory
  - doesnt need to do fsync
- dont need synchronously write to disk + write back of file to disk can be delay
- only a portion of DRAM can have battery-backed
- an app using mmap ontop of Rio, does it need msync? -> NO, mmap ontop of file cached which is batter-packed -> doesnt need to worry about persistent
- How does delay writes from a file cache to the disk help?
  - procasinate help batch IO + reduce amount of IO
  - lots of files created only temporary and will be deleted -> no urgency to write to the disk
- OS does a lot of PROCASCINATION
- RioVista:
  - data segment map into VA
  - begin_transaction -> write change -> end_transaction -> get rid of undo log
  - What happens if there is an ABORT?
    - UNDO LOG: at start of transaction is persisted
    - ABORT: apply UNDO LOG to memory to recover old image because UNDO LOG services crashes
  - What are the implications of RioVista design? (no sync IO, no redo log, data segment directly modified)
    - all of the above
    - no redo log: write directly, only need UNDO log for abort
  - read, write during a txn, is it via file cache? -> YES, so that data is persisted
    - making changes directly on to data segment
    - which is mapped into VA
    - any change is persistent because of battery-backed
- memory pressure? conviction policy?
  - only a portion of memory is battery-backed

# 08/04

## DQ

- given a capacity, DQ is constant, can increae Q and decrease D
- as a system admin, if can increase capacity -> can increase Q or D
- replication vs partitioning
  - replication
    - all servers have copies of all dataset
    - harvest can remain unchange -> yield will decrease > Q will go down
  - parition
    - failure -> full data not avialable -> harvest will surfer, yield remains unchanged
    - give parallelism but also want replication for full harvest (gmail,...)
    - some applications can deal with partial result (search,...)
- GMAIL: SAAS, implementation may change, API remains the same -> interact the same way
- Do Google Search, what happens? -> Computation running parallel on large data center

## MapReduce

- need coordination between the parallelism happens
- resources available on the cloud -> help with developers -> painless for domain experts
- Why map-reduce?
  - steps in processing can be implementing using map-reduce
  - most usecase need a map function and a reduce function
  - heavely lifting, number of mappers + reducers + coordination done by map-reduce framework
  - page rank: map will transform url, reduce: aggregate the occurence
- In case of failure, the number of maps? -> numbers of shard, 10 shards -> 10 mappers
- In case of failure, the number of reducers? -> numbers of distinct output
- How many intermediate files that will be passed from mappers to reducers? -> M immediate files, R reducers -> M * R
- When does the reducers start reading the file? -> when the mappers is done
- reducer finishes and produces an output file (temp file as first), making the file visible to user is job of master -> use rename to make visible to user
  -> the stragger will be ignored
