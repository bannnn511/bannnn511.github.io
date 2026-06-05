
**Title:**  Dynamo: Amazon's Highly Available Key-value Store

**Authors:**  
**Published in:**

---

## Question–Answer Form

### 1. What is your take-away message from this paper?

- trade-off of consistency and availability
- use eventual consistency to increase availability
- scale incrementally requires dynamic partition
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
	- **high availability**: vector clocks + reconciliation during reads -> version size is decoupled from update rates
	- **temporary failures**: sloppy quorum and hinted handoff -> high availability + durability guarantee when some replicas not available
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

