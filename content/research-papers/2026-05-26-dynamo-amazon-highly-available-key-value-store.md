****
****
# Dynamo: Amazon's Highly Available Key-value Store

**Authors:**  
**Published in:**

---

## Question–Answer Form

### 1. What is your take-away message from this paper?

- trade-off of consistency and availability
- use eventual consistency to increase availability
- incremental scaling requires dynamic partition
- optimistic replication of partitions to increase availability but requires conflict resolution
- data versioning is used to handle eventual consistency and requires 

---

### 2. What is the motivation for this work?

- What is the **people problem** and the **technical problem**?
	- people problem 
		- users can access services, can perform read and write operations in case of small or large scale components failure
		- shopping cart service must allow customers to add and remove items even am
	- technical problem
		- reliability at massive scale is one of the biggest challenge at Amazon.com
		- need for storage technologies that are always available
		- synchronous replication forces tradeoff the availability of data under certain failure scenarios
		- strong consistency and high availability cannot be achieved simultaneously

- How is it distilled into a **research question**?
	- How can a system designed to be highly available across datacenters and failures even at the cost of consistency?

- Why doesn’t the people problem have a **trivial solution**?
	- because in CAP theorem, system design must chose CP or AP which means that there is a tradeoff of **consistency and availability**
	- availability can be increased by using optimistic replication but leads to **conflict resolution**
		- when to resolve: at write or read?
		- who to resolve: data store or application?

- What are the **previous solutions**, and why are they **inadequate**?
	- differs in term of Dynamo's target requirements
		- always writeable
		- all nodes can be trusted
		- dont need complex relational schema
		- latency sensitive read and write operations
	- avoid routing requests through multiple nodes
		- routing increases variability in response times
	- examples
		- P2P system (Freenet, Gnutella, Oceanstore, PAST): queries need multiple hop
		- Distributed FS + DB
			- Dynamo does not focus on data integrity and already built for trusted environment
			- Ficus + Coda: allow disconnected operations

---

### 3. What is the proposed solution (hypothesis, idea, design)?

- Why is it believed this solution will work?
	- Dynamo uses eventual consistency for data replication to achieves high availability

- How does it represent an **improvement**?

- How is the solution **achieved**?
	- **partitioning**: consistent hashing -> incremental scalability
		- variant of consistent hashing by using virtual nodes
		- one physical server is represented as multiple positions on the ring
		- number of virtual nodes of a machine is decided based on capacity
		- because ranges are scattered, **loads get spread across many different machines** and not dump into the next neighbor in case of failure
		- one new node joins, accepts equivalent amount of load from other nodes
	- **replication**: //TODO
	- **data versioning**: 
		- vector clocks + reconciliation during reads -> version size is decoupled from update rates
	- **temporary failures**: sloppy quorum and hinted handoff -> high availability + durability guarantee when some replicas not available
		- sloppy quorum: not strict quorum for availability (server failures + network partition)
		- hinted handoff so that other nodes can pick up the work of downed replicas 
			- for hinted handoff, if a node is down another node not in replica set will be chosen to maintain the desired availability
	- **recovering from permanent failure**: anti-entropy using Merkle trees -> synchronizes divergent replicas in the background
	- **membership + failure detection**: gossip protocol + failure detection -> preserve symmetry + avoid having centralized registry for storing membership + node liveness information

---

### 4. What is the author’s evaluation of the solution?

- What **logic, argument, evidence, artifacts**, or **experiments** are presented in support of the idea?

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

- Q1: What is smart partitioning schemes for load balancing?

- Q2: Why Dynamo has data versioning, but DynamoDB does not?

- Q3: If DynamoDB does not aware of multiple versions of data, then does this affect business logic?
- Q4: If the node are chosen by md5, what about the top N preference list?
	- 


> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=9,0,10,18|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Reliability at massive scale is one of the biggest challenges we face at Amazon.com
> 
> challenges
> 

>[!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=28,26,49,17|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > scale, small and large components fail continuously and the way persistent state is managed in the face of these failures drives the reliability and scalability of the software systems.
> 
> motivation

> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=55,36,58,53|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Dynamo sacrifices consistency under certain failure scenarios. It makes extensive use of object versioning and application-assisted conflict resolution in a manner that provides a novel interface for developers to use.
> 
> solution using object version and assisted conflict resolution


> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=86,49,87,34|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Reliability is one of the most important requirements
> 
> motivation

> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=103,53,105,60|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > operating Amazon’s platform is that the reliability and scalability of a system is dependent on how its application state is managed.
> 
> hypothesis

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=108,21,109,26&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > a particular need for storage technologies that are always available.
> 
> motivation, because Amazon consists of hundreds of services

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=112,23,115,29&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Therefore, the service responsible for managing shopping carts requires that it can always write to and read from its data store, and that its data needs to be available across multiple data centers.
> 
> example use case for availability

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=119,45,122,11&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Amazon’s software systems need to be constructed in a manner that treats failure handling as the normal case without impacting availability or performance
> 
> failure handling first implementation

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=129,0,133,1&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Dynamo is used to manage the state of services that have very high reliability requirements and need tight control over the tradeoffs between availability, consistency, cost-effectiveness and performance.
> 
> Solution tradeoff

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=149,50,169,57&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > A select set of applications requires a storage technology that is flexible enough to let application designers configure their data store appropriately based on these tradeoffs to achieve high availability and guaranteed performance in the most cost effective manner.
> 
> type of application that can use Dynamo

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=192,0,195,18&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > Dynamo uses a synthesis of well known techniques to achieve scalability and availability: Data is partitioned and replicated using consistent hashing [10], and consistency is facilitated by object versioning 
> 
> hypothesis of how to achieve scalability and availability


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=1&selection=195,24,213,47&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.1]]
> > The consistency among replicas during updates is maintained by a quorum-like technique and a decentralized replica synchronization protocol.
> 
> Consistency implementation

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=2,0,15,7&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > gossip based distributed failure detection and membership protocol
> 
> failure + service discovery implementation

> [!PDF|note] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=72,38,75,44&color=note|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > served tens of millions requests that resulted in well over 3 million checkouts in a single day and the service that manages session state handled hundreds of thousands of concurrently active sessions
> 
> evaluation

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=185,23,206,44&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> >  relational database is a solution that is far from ideal. Most of these services only store and retrieve data by primary key and do not require the complex querying and management functionality offered by an RDBMS
> 
> Design motivation for not choosing RDBMS

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=221,17,222,47&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > available replication technologies are limited and typically choose consistency over availability.
> 
> limited replication of RDBMS

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=223,57,225,9&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > not easy to scale-out databases or use smart partitioning schemes for load balancing
> 
> reasons for not using RDBMS

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=263,48,265,65&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > simple query model and do not need any relational schema. Dynamo targets applications that need to store objects that are relatively small
> 
> query model motivation

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=305,0,308,12&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > Dynamo targets applications that operate with weaker consistency (the “C” in ACID) if this results in high availability. Dynamo does not provide any isolation guarantees and permits only single key updates.
> 
> motivation for dropping to weak consistency and no isolation

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=338,0,339,22&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > The tradeoffs are in performance, cost efficiency, availability, and durability guarantees.
> 
> efficiency tradeoffs

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=2&selection=341,54,359,32&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.2]]
> > on-hostile and there are no security related requirements such as authentication and authorization
> 
> no need for security related 

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=62,0,64,8&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > A common approach in the industry for forming a performance oriented SLA is to describe it using average, median and expected variance
> 
> common industry metrics

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=93,53,102,18&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > o address this issue, at Amazon, SLAs are expressed and measured at the 99.9 th percentile of the distribution. The choice for 99.9% over an even higher percentile has been made based on a cost-benefit analysis which demonstrated a significant increase in cost to improve performance
> 
> industry metrics are not good enough, Amazon aims for 99.9th percentile

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=262,50,265,47&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > availability can be increased by using optimistic replication techniques, where changes are allowed to propagate to replicas in the background, and concurrent, disconnected work is tolerated.
> 
> hypothesis of using optimistic replication

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=269,6,270,57&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > Dynamo is designed to be an eventually consistent data store; that is all updates reach all replicas eventually.
> 
> important solution of how Dynamo can achieve availability

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=277,44,281,10&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > any traditional data stores execute conflict resolution during writes and keep the read complexity simple [7]. In such systems, writes may be rejected if the data store cannot reach all (or a majority of) the replicas at a given time
> 
> traditional data store solution for conflicts


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=283,23,292,1&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> > For a number of Amazon services, rejecting customer updates could result in a poor customer experience. For instance, the shopping cart service must allow customers to add and remove items from their shopping cart even amidst network and server failures.
> 
> example of why Dynamo uses read for conflict resolution

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=205,0,236,1&color=yellow|p.3]]
> > Data replication algorithms used in commercial systems traditionally perform synchronous replica coordination in order to provide a strongly consistent data access interface. To achieve this level of consistency, these algorithms are forced to tradeoff the availability of the data under certain failure scenarios.
> 
> technical problem of traditional db system


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=271,0,276,42&color=red|p.3]]
> > An important design consideration is to decide when to perform the process of resolving update conflicts,
> 
> important design consideration of WHEN to resolve conflicts

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=0,0,5,66&color=red|p.4]]
> > The next design choice is who performs the process of conflict resolution. This can be done by the data store or the application.
> 
> WHO to resolve conflicts

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=160,37,176,2&color=red|p.4]]
> > Systems like Pastry [16] and Chord [20] use routing mechanisms to ensure that queries can be answered within a bounded number of hops. 
> 
> P2P mechanism for query

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=237,34,239,47&color=red|p.4]]
> > Oceanstore resolves conflicts by processing a series of updates, choosing a total order among them, and then applying them atomically in that order
> 
> how Oceanstore resolves conflicts

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=62,22,88,19&color=yellow|p.5]]
> > avoid routing requests through multiple nodes (which is the typical design adopted by several distributed hash table systems such as Chord and Pastry). This is because multihop routing increases variability in response times, thereby increasing the latency at higher percentiles.
> 
> Dynamo motivation for avoiding P2P approach

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=294,24,295,67&color=yellow|p.4]]
> >  Systems like Ficus [15] and Coda [19] replicate files for high availability at the expense of consistency
> 
> expected tradeoff

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=309,13,311,65&color=yellow|p.4]]
> > These systems differ on their conflict resolution procedures. For instance, Coda and Ficus perform system level conflict resolution and Bayou allows application level resolution
> 
> difference in conflict resolutions

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=347,52,351,63&color=yellow|p.4]]
> > Antiquity is a wide-area distributed storage system designed to handle multiple server failures [23]. It uses a secure log to preserve data integrity, replicates each log on multiple servers for durability, and uses Byzantine fault tolerance protocols to ensure data consistency.
> 
> handle failures + data integrity + durability + consistency

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=352,23,353,67&color=important|p.4]]
> > Dynamo does not focus on the problem of data integrity and security and is built for a trusted environment.

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=4&selection=359,0,384,38&color=important|p.4]]
> > Compared to Bigtable, Dynamo targets applications that require only key/value access with primary focus on high availability where updates are not rejected even in the wake of network partitions or server failures.
> 
> Dynamo only need key/value access

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=14,45,36,17&color=important|p.5]]
> > “always writeable” data store where no updates are rejected due to failures or concurrent writes
> 
> req1

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=37,40,39,31&color=important|p.5]]
> > Dynamo is built for an infrastructure within a single administrative domain where all nodes are assumed to be trusted
> 
> req2

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=40,7,40,56&color=important|p.5]]
> > do not require support for hierarchical namespace
> 
> req3

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=59,34,61,12&color=important|p.5]]
> > t require at least 99.9% of read and write operations to be performed within a few hundred milliseconds
> 
> req4

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=102,30,132,28&color=yellow|p.5]]
> >  In addition to the actual data persistence component, the system needs to have scalable and robust solutions for load balancing, membership and failure detection, failure recovery, replica synchronization, overload handling, state transfer, concurrency and job scheduling, request marshalling, request routing, system monitoring and alarming, and configuration management
> 
> required solutions for storage system

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=181,18,189,43&color=yellow|p.5]]
> > The context encodes system metadata about the object that is opaque to the caller and includes information such as the version of the object. The context information is stored along with the object so that the system can verify the validity of the context object supplied in the put request.
> 
> system interface

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=199,0,200,20&color=yellow|p.5]]
> > One of the key design requirements for Dynamo is that it must scale incrementally.
> 
> key requirements
> 

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=5&selection=191,30,193,54&color=red|p.5]]
> > It applies a MD5 hash on the key to generate a 128-bit identifier, which is used to determine the storage nodes that are responsible for serving the key
> 
> how storage nodes is picked

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=6,8,7,48&color=yellow|p.6]]
> > the random position assignment of each node on the ring leads to non-uniform data and load distribution.
> 
> harder to rebalance

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=7,49,10,1&color=yellow|p.6]]
> > Second, the basic algorithm is oblivious to the heterogeneity in the performance of nodes. 
> 
> bigger machines will get assigned multiple nodes

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=31,33,35,13&color=red|p.6]]
> >  virtual node looks like a single node in the system, but each node can be responsible for more than one virtual node. Effectively, when a new node is added to the system, it is assigned multiple positions (henceforth, “tokens”) in the ring. 
> 
> Dynamo implementation of consistent hashing

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=46,1,59,47&color=red|p.6]]
> > oad handled by this node is evenly dispersed across the remaining available nodes.
> 
> how load is balanced

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=70,0,72,30&color=red|p.6]]
> > The number of virtual nodes that a node is responsible can decided based on its capacity, accounting for heterogeneity in the physical infrastructure
> 
> accounts for heterogeneity

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=78,0,79,21&color=yellow|p.6]]
> > To achieve high availability and durability, Dynamo replicates its data on multiple host
> 
> needs for replication

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=89,29,91,38&color=yellow|p.6]]
> > In addition to locally storing each key within its range, the coordinator replicates these keys at the N-1 clockwise successor nodes in the ring.
> 
> what this means is if the ring is B -> C -> D, then the key not only stored in B but also C and D as well

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=111,30,112,13&color=yellow|p.6]]
> > preference list contains more than N nodes.
> 
> how replicas are used with partitions

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=161,38,164,65&color=yellow|p.6]]
> > When a customer wants to add an item to (or remove from) a shopping cart and the latest version is not available, the item is added to (or removed from) the older version and the divergent versions are reconciled later
> 
> data versioning use cases

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=165,44,168,28&color=yellow|p.6]]
> > Dynamo treats the result of each modification as a new and immutable version of the data. It allows for multiple versions of an object to be present in the system at the same time.
> 
> mechanism that guarantee eventual consistency under failure


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=181,0,196,16&color=yellow|p.6]]
> > system itself can determine the authoritative version (syntactic reconciliation).
> 
> 1st method of conflict resolution


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=211,55,233,15&color=yellow|p.6]]
> > system cannot reconcile the multiple versions of the same object and the client must perform the reconciliation in order to collapse multiple branches of data evolution back into one (semantic reconciliation)
> 
> 2nd method of conflict resolution


> [!PDF|note] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=234,59,236,42&color=note|p.6]]
> >  Using this reconciliation mechanism, an “add to cart” operation is never lost. However, deleted items can resurface
> 
> unwanted behavior of reconciliation mechanism



> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=258,48,260,51&color=red|p.6]]
> > design applications that explicitly acknowledge the possibility of multiple versions of the same data (in order to never lose any updates).
> 
> applications need to be aware of multiple version for Dynamo only, not DynamoDB


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=261,0,262,46&color=red|p.6]]
> > Dynamo uses vector clocks [12] in order to capture causality between different versions of the same object.
> 
> because of branching in data versions


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=264,47,266,50&color=red|p.6]]
> > One can determine whether two versions of an object are on parallel branches or have a causal ordering, by examine their vector clocks.
> 
> check if two versions are related

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=6&selection=271,0,272,36&color=red|p.6]]
> > In Dynamo, when a client wishes to update an object, it must specify which version it is updating
> 
> internal state of `put()`

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=7&selection=0,0,21,12&color=red|p.7]]
> > Dynamo has access to multiple branches that cannot be syntactically reconciled, it will return all the objects at the leaves, with the corresponding version information in the context. An update using this context is considered to have reconciled the divergent versions and the branches are collapsed into a single new version.
> 
> conflict resolution interface

> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=7&selection=78,1,79,59|Dynamo: Amazon’s Highly Available Key-value Store, p.7]]
> >  possible issue with vector clocks is that the size of vector clocks may grow if many servers coordinate the writes to an object
> 
> vector clocks size might grow too much

> [!PDF|] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=7&selection=86,5,90,61|Dynamo: Amazon’s Highly Available Key-value Store, p.7]]
> > Dynamo employs the following clock truncation scheme: Along with each (node, counter) pair, Dynamo stores a timestamp that indicates the last time the node updated the data item. When the number of (node, counter) pairs in the vector clock reaches a threshold (say 10), the oldest pair is removed from the clock
> 
> truncation scheme for vector clock

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=7&selection=141,0,145,6&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.7]]
> > There are two strategies that a client can use to select a node: (1) route its request through a generic load balancer that will select a node based on load information, or (2) use a partition-aware client library that routes requests directly to the appropriate coordinator nodes.
> 
> 1st approach: cost steps to route request, client lighter
> 2st approach: client library decides how to route request directly to node but more dependency

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=7&selection=183,0,188,43&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.7]]
> > To maintain consistency among its replicas, Dynamo uses a consistency protocol similar to those used in quorum systems. This protocol has two key configurable values: R and W. R is the minimum number of nodes that must participate in a successful read operation. W is the minimum number of nodes that must participate in a successful write operation
> 
> not strict quorum because of sloppy quorums and eventual consistency
> read and writes may involve different set of nodes

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=52,0,55,10&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > If Dynamo used a traditional quorum approach it would be unavailable during server failures and network partitions, and would have reduced durability even under the simplest of failure conditions
> 
> reduced durability if using strict quorum


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=65,26,68,64&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> >  if node A is temporarily down or unreachable during a write operation then a replica that would normally have lived on A will now be sent to node D. This is done to maintain the desired availability and durability guarantees. 
> 
> hinted handoff to maintain desired availability and durability

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=73,0,92,13&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > Nodes that receive hinted replicas will keep them in a separate local database that is scanned periodically. Upon detecting that A has recovered, D will attempt to deliver the replica to A. Once the transfer succeeds, D may delete the object from its local store without decreasing the total number of replicas in the system
> 
> how hinted handoff works

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=93,0,100,6&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > Using hinted handoff, Dynamo ensures that the read and write operations are not failed due to temporary node or network failures. Applications that need the highest level of availability can set W to 1, which ensures that a write is accepted as long as a single node in the system has durably written the key it to its local store.
> 
> W to 1 = higher chance of accepted write

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=136,33,137,34&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > There are scenarios under which hinted replicas become unavailable
> 
> 

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=138,27,150,60&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > To handle this and other threats to durability, Dynamo implements an anti-entropy (replica synchronization) protocol to keep the replicas synchronized.
> 
> for permanent failures

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=153,0,169,11&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > detect the inconsistencies between replicas faster and to minimize the amount of transferred data, Dynamo uses Merkle trees [13].
> 
> each branch of Merkle tree can be checked independently without requiring nodes to download the entire tree

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=174,35,176,29&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > erkle trees help in reducing the amount of data that needs to be transferred while checking for inconsistencies among replica


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=186,0,189,58&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > Dynamo uses Merkle trees for anti-entropy as follows: Each node maintains a separate Merkle tree for each key range (the set of keys covered by a virtual node) it hosts. This allows nodes to compare whether the keys within a key range are up-to-date
> 
> make sure keys within a key range are up-to-date

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=212,36,214,66&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > The disadvantage with this scheme is that many key ranges change when a node joins or leaves the system thereby requiring the tree(s) to be recalculated
> 
> rebalance issues

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=238,19,240,25&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > it was deemed appropriate to use an explicit mechanism to initiate the addition and removal of nodes from a Dynamo ring.
> 
> adding nodes should be manually not automatically

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=8&selection=282,39,298,44&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.8]]
> > A gossip-based protocol propagates membership changes and maintains an eventually consistent view of membership. Each node contacts a peer chosen at random every second and the two nodes efficiently reconcile their persisted membership change histories.
> 
> gossip-based protocol for service discovery

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=0,54,3,9&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > The mappings stored at different Dynamo nodes are reconciled during the same communication exchange that reconciles the membership change histories
> 
> how membership information is exchanged

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=5,49,7,14&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > his allows each node to forward a key’s read/write operations to the right set of nodes directly
> 
> membership facilitate read/write operations

 > [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=41,0,43,19&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > Seeds can be obtained either from static configuration or from a configuration service. Typically seeds are fully functional nodes in the Dynamo ring.
> 
> seeds prevent logical partition

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=13,1,30,40&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > he mechanism described above could temporarily result in a logically partitioned Dynamo ring. For example, the administrator could contact node A to join A to the ring, then contact node B to join B to the ring. In this scenario, nodes A and B would each consider itself a member of the ring, yet neither would be immediately aware of the other.
> 
> logical partition

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=100,0,102,39&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > Decentralized failure detection protocols use a simple gossip-style protocol that enable each node in the system to learn about the arrival (or departure) of other nodes. 
> 
> deprecated mechanism for service discovery

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=136,0,140,58&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > When a new node (say X) is added into the system, it gets assigned a number of tokens that are randomly scattered on the ring. For every key range that is assigned to node X, there may be a number of nodes (less than or equal to N) that are currently in charge of handling keys that fall within its token range. 
> 
> rebalancing nodes

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=181,0,192,15&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > by adding a confirmation round between the source and the destination, it is made sure that the destination node does not receive any duplicate transfers for a given key range
> 
> deduplication

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=267,1,281,38&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > he main reason for designing a pluggable persistence component is to choose the storage engine best suited for an application’s access patterns. 
> 
> storage engine follows access pattern

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=285,0,300,25&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > The majority of Dynamo’s production instances use BDB Transactional Data Store.
> 
> 

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=198,1,229,24&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > In Dynamo, each storage node has three main software components: request coordination, membership and failure detection, and a local persistence engine. All these components are implemented in Java.
> 
> 

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=301,0,303,67&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > The request coordination component is built on top of an eventdriven messaging substrate where the message processing pipeline is split into multiple stages similar to the SEDA architecture [24]
> 
> 

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=10&selection=31,32,52,8&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.10]]
> > Although it is desirable always to have the first node among the top N to coordinate the writes thereby serializing all writes at a single location, this approach has led to uneven load distribution resulting in SLA violations. This is because the request load is not uniformly distributed across objects.



> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=10&selection=21,23,29,59&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.10]]
> > If stale versions were returned in any of the responses, the coordinator updates those nodes with the latest version. This process is called read repair because it repairs replicas that have missed a recent update at an opportunistic time and relieves the anti-entropy protocol from having to do it


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=10&selection=54,41,75,8&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.10]]
> > he coordinator for a write is chosen to be the node that replied fastest to the previous read operation which is stored in the context information of the request.
> 
> how coordinator is chosen among top N nodes

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=10&selection=223,57,224,43&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.10]]
> > the value of N determines the durability of each object.


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=10&selection=226,1,227,11&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.10]]
> > he values of W and R impact object availability, durability and consistency

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=1,9,6,7&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> > However, this is not necessarily true here. For instance, the vulnerability window for durability can be decreased by increasing W. This may increase the probability of rejecting request



> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=119,49,122,46&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> > The involvement of multiple storage nodes in read and write operations makes it even more challenging, since the performance of these operations is limited by the slowest of the R or W replicas.


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=145,33,164,1&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> > Dynamo provides the ability to trade-off durability guarantees for performance. In the optimization each storage node maintains an object buffer in its main memory. Each write operation is stored in the buffer and gets periodically written to storage by a writer thread.
> 
> not flushed yet

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=175,12,177,24&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> > his scheme trades durability for performance. In this scheme, a server crash can result in missing writes that were queued up in the buffer.


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=228,13,230,12&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> >  This section discusses the load imbalance seen in Dynamo and the impact of different partitioning strategies on load distribution

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=11&selection=232,1,237,36&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.11]]
> > he total number of requests received by each node was measured for a period of 24 hours - broken down into intervals of 30 minutes. In a given time window, a node is considered to be “inbalance”, if the node’s request load deviates from the average load by a value a less than a certain threshold (here 15%). Otherwise the node was deemed “out-of-balance”
> 
> how requests are monitored

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=11,57,15,56&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > The tokens of all nodes are ordered according to their values in the hash space. Every two consecutive tokens define a range. The last token and the first token form a range that "wraps" around from the highest value to the lowest value in the hash space.
> 
> St1 token range


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=36,21,39,70&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > when a new node joins the system, it needs to “steal” its key ranges from other nodes. However, the nodes handing the key ranges off to the new node have to scan their local persistence store to retrieve the appropriate set of data items.
> 
> ST1 - "scan" requires IO on a production node -> resource intensive

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=44,38,59,8&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > this significantly slows the bootstrapping process and during busy shopping season, when the nodes are handling millions of requests a day, the bootstrapping has taken almost a day to complete
> 
> ST1 - bootstrapping to heavy

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=63,0,70,12&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > when a node joins/leaves the system, the key ranges handled by many nodes change and the Merkle trees for the new ranges need to be recalculated
> 
> ST1 - merkle tree need to be recalculated

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=71,18,73,57&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> >  Finally, there was no easy way to take a snapshot of the entire key space due to the randomness in key ranges, and this made the process of archival complicated
> 
> ST1 - hard to snapshot?



> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=76,0,77,52&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > The fundamental issue with this strategy is that the schemes for data partitioning and data placement are intertwined
> 


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=90,30,92,64&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> >  In this strategy, the tokens are only used to build the function that maps values in the hash space to the ordered lists of nodes and not to decide the partitioning
> 
> ST2 - data partitioning

> [!PDF|note] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=92,65,95,17&color=note|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> >  A partition is placed on the first N unique nodes that are encountered while walking the consistent hashing ring clockwise from the end of the partition.
> 
> ST2 - data placement

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=97,53,100,31&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > he primary advantages of this strategy are: (i) decoupling of partitioning and partition placement, and (ii) enabling the possibility of changing the placement scheme at runtime


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=104,0,106,16&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > Similar to strategy 2, this strategy divides the hash space into Q equally sized partitions


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=108,53,124,9&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > When a node leaves the system, its tokens are randomly distributed to the remaining nodes such that these properties are preserved


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=12&selection=138,0,144,50&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.12]]
> > comparing these different strategies in a fair manner is hard as different strategies have different configurations to tune their efficiency.


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=39,35,48,26&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > The load balancing efficiency of each strategy was measured for different sizes of membership information that needs to be maintained at each node, where Load balancing efficiency is defined as the ratio of average number of requests served by each node to the maximum number of requests served by the hottest node
> 
> strategies were evaluated by T and Q

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=49,61,51,30&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > ategy 3 achieves the best load balancing efficiency and strategy 2 has the worst load balancing efficienc


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=74,57,76,58&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > he nodes gossip the membership information periodically and as such it is desirable to keep this information as compact as possible.


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=90,0,95,7&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > Faster bootstrapping/recovery: Since partition ranges are fixed, they can be stored in separate files, 
> 
> ST3 faster bosstrapping/recovery

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=98,11,104,65&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > ii) Ease of archival: Periodical archiving of the dataset is a mandatory requirement for most of Amazon storage services. Archiving the entire dataset stored by Dynamo is simpler in strategy 3 because the partition files can be archived separately

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=105,28,108,5&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > the tokens are chosen randomly and, archiving the data stored in Dynamo requires retrieving the keys from individual nodes separately and is usually inefficient and slow.
> 
> for ST1, have to go through all nodes

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=108,7,124,37&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > he disadvantage of strategy 3 is that changing the node membership requires coordination in order to preserve the properties required of the assignment
> 
> because of Q equally sized partitions

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=139,57,141,55&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> >  The first is when the system is facing failure scenarios such as node failures, data center failures, and network partitions.
> 
> infra failure

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=141,56,147,1&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > The second is when the system is handling a large number of concurrent writers to a single data item and multiple nodes end up coordinating the updates concurrently. 
> 
> congestion?

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=195,16,196,60&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > Semantic reconciliation introduces additional load on services, so it is desirable to minimize the need for it.


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=203,0,205,28&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > Experience shows that the increase in the number of divergent versions is contributed not by failures but due to the increase in number of concurrent writers


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=219,13,259,63&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> >  Write requests on the other hand will be coordinated by a node in the key’s current preference list. This restriction is due to the fact that these preferred nodes have the added responsibility of creating a new version stamp that causally subsumes the version that has been updated by the write request
> 
> picking write coordinator


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=13&selection=275,0,300,55&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.13]]
> > In this scheme client applications use a library to perform request coordination locally. A client periodically picks a random Dynamo node and downloads its current view of Dynamo membership state. 
> 
> client side load balance

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=16,1,46,5&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > An important advantage of the client-driven coordination approach is that a load balancer is no longer required to uniformly distribute client load. Fair load distribution is implicitly guaranteed by the near uniform assignment of keys to the storage nodes


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=46,8,67,17&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > bviously, the efficiency of this scheme is dependent on how fresh the membership information is at the client. Currently clients poll a random Dynamo node every 10 seconds for membership update


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=67,18,70,17&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > . A pull based approach was chosen over a push based one as the former scales better with large number of clients and requires very little state to be maintained at servers regarding clients
> 
> pull base scale better cause of less state to maintain

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=71,10,74,26&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> >  stale membership for duration of 10 seconds. In case, if the client detects its membership table is stale (for instance, when some members are unreachable), it will immediately refresh its membership information
> 
> refresh when stale is detected?

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=99,14,102,25&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > The latency improvement is because the client driven approach eliminates the overhead of the load balancer and the extra network hop that may be incurred when a request is assigned to a random node
> 
> client driven approach performs better then server driven


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=166,0,168,20&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > Each node performs different kinds of background tasks for replica synchronization and data handoff (either due to hinting or adding/removing node

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=172,7,177,9&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > necessary to ensure that background tasks ran only when the regular critical operations are not affected significantly. To this end, the background tasks were integrated with an admission control mechanism
> 
> admission control mechanism?

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=213,1,227,10&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > he admission controller constantly monitors the behavior of resource accesses while executing a "foreground" put/get operation.

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=227,0,229,38&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > operation. Monitored aspects include latencies for disk operations, failed database accesses due to lock-contention and transaction timeouts, and request queue wait times
> 
> metrics to monitor

> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=243,12,245,54&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > Subsequently, it decides on how many time slices will be available to background tasks, thereby using the feedback loop to limit the intrusiveness of the background activitie
> 
> timeslice for background task

> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=289,13,290,30&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > Dynamo exposes data consistency and reconciliation logic issues to the developers


> [!PDF|yellow] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=333,9,334,45&color=yellow|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > Dynamo adopts a full membership model where each node is aware of the data hosted by its peers
> 
> membership model ~ service discovery?

> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=14&selection=336,9,339,60&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.14]]
> > his model works well for a system that contains couple of hundreds of nodes. However, scaling such a design to run with tens of thousands of nodes is not trivial because the overhead in maintaining the routing table increases with the system size


> [!PDF|red] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=3&selection=89,7,93,51&color=red|Dynamo: Amazon’s Highly Available Key-value Store, p.3]]
> >  if extensive personalization techniques are used then customers with longer histories require more processing which impacts performance at the high-end of the distribution. An SLA stated in terms of mean or median response times will not address the performance of this important customer segment.


> [!PDF|important] [[Dynamo: Amazon’s Highly Available Key-value Store.pdf#page=9&selection=166,0,168,1&color=important|Dynamo: Amazon’s Highly Available Key-value Store, p.9]]
> > Therefore, nodes B, C, and D will offer to and upon confirmation from X transfer the appropriate set of keys. 

