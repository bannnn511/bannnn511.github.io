
**Title:**  Dynamo: Amazon's Highly Available Key-value Store
**Name:**

**Authors:**  
**Published in:**

---

## Question–Answer Form

### 1. What is your take-away message from this paper?

> _Write your summary insight here._

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
	- because in CAP theorem, system design must chose CP or AP which means that there is a tradeoff of consistency and availability
	- availability can be increased by using optimistic replication but leads to conflict resolution
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

---

### 3. What is the proposed solution (hypothesis, idea, design)?

- Why is it believed this solution will work?
	- Dynamo uses eventual consistency for data replication to achieves high availability

- How does it represent an **improvement**?

- How is the solution **achieved**?

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

- Q2:

- Q3:


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