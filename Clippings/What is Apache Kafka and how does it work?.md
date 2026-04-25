---
title: "What is Apache Kafka and how does it work?"
source: "https://stanislavkozlovski.medium.com/what-is-apache-kafka-and-how-does-it-work-16023aa2efee"
author:
  - "[[Stanislav Kozlovski]]"
published: 2026-04-23
created: 2026-04-24
description: "The most complete and detailed explanation of Kafka on the internet"
tags:
  - "clippings"
---
## The most complete and detailed explanation of Kafka on the internet

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*U1Pq8e_qtk06n0TfusKN0g.png)

Prague, where Franz Kafka was born.

Everyone always asks me:

> \> What’s a resource you would recommend to learn Kafka?

- I used to recommend [the books about Kafka](https://kafka.apache.org/community/books_and_papers/), but most people don’t have the time to dedicate to a whole book and frankly, they don’t need them.
- There are *some* good articles on Kafka out there but they’re incomplete;
- And, more importantly, there are a ton of badly-written AI blogs out there. Open any such one, and you will see the same words being used to describe the system:
****
> “It’s an open-source, distributed, durable, very scalable, fault-tolerant pub/sub message system with rich integration and stream processing capabilities.”

While it’s technically true, it isn’t practically helpful for a novice reader being introduced to Kafka for the first time.

Today, I present you with the single best, most-thorough single resource on the internet about Apache Kafka. We will explain Kafka by **precisely breaking down** what ***every*** word in that definition means, and *a lot more*. (watch for the **💡** emoji marking each word’s definition)

At the end, you will have **a complete** high-level understanding of Apache Kafka.

## Why Trust My Explanation?🧐

I went viral explaining Kafka way back in 2017 (9 years ago now… wow) — that article was so informative and unique that it got over 200,000 views and 13.2k claps on Medium, AND landed me a job.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*ZO8TnH8ZGCMEOBaovDgJnQ.png)

the good old times

> *It landed me a job at Confluent (a company founded by the creators of Kafka), where I worked very hard as a software engineer on Apache Kafka directly for 6 years and became* [*a committer to the project*](https://kafka.apache.org/community/committers/)*. I’ve since grown* [*a newsletter*](https://blog.2minutestreaming.com/) *about Kafka to over 7000+ subscribers and collected over 50,000 followers on* [*social*](https://x.com/kozlovski) [*media*](https://www.linkedin.com/in/stanislavkozlovski/) *from sharing useful insights about data engineering. I literally call myself* [*“The Kafka Guy”*](https://www.linkedin.com/in/stanislavkozlovski/) *(half-jokingly, half-true)*

Quite a lot of things have changed since — both in my understanding and in the underlying technology — so this warrants a completely new article. One that’s better than ever.

This is it, and it’s 100% free. Enjoy:

## Apache Kafka

Apache Kafka is one of the most popular open-source projects in the data infrastructure space. It is a standard tool in every data engineer’s catalog, used by over 70% of Fortune 500 companies and 150,000 organizations. Names like OpenAI, Twitter (X), Reddit, Datadog, Newrelic, Paypal, Cloudflare, Airbnb, LinkedIn, Riot Games, etc.

Kafka is a messaging system that was originally developed by LinkedIn in 2010. In 2011, it was open-sourced and donated to the Apache Foundation.  
*That’s why its official name is “Apache Kafka”, but we still call it Kafka for short.*

> ***💡* open-source (1/8)**

Nowadays, Kafka is more than a simple messaging system: it’s a larger ecosystem of components that form a **streaming platform**. It is frequently called the swiss army knife of data infrastructure.

> ***A Streaming Platform*** means a system that allows you to store and process a large volume of streams of data. For example, a company like Uber has millions of drivers constantly streaming their GPS coordinates to Uber’s backend systems. A streaming platform can scale this data and process it in real time as it comes. This helps Uber make use of the data (e.g, recompute the route, figure out where there is traffic, etc).

## Kafka’s Story

Why did Kafka become so widely used and known?

Because it solved a very important problem — the problem of **data integration at scale**.

LinkedIn had to connect different services to one another.

A naive way of achieving this would have beento create many custom point-to-point integrations (called **data pipelines**) between each service.

That would have resulted in an **O (N²)** mess that would break often and be impossible to maintain when N is in the hundreds:

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*b7kER5QKGQZAGf8Bi0BtpA.png)

a simple visualization of the problem

Apache Kafka flips this problem on its head. Instead of creating custom pipelines per connection, it encourages organizations to:

1. Store their data in a central location (Kafka)
2. Use a single standard API (the Kafka API)
3. Have applications subscribe and consume this data in real time

This decouples writers from readers, as writers simply publish to Kafka, and readers subscribe to Kafka.

The data gets durably persisted to disk for a limited amount of time (e.g., 7 days).

Kafka is ideal and was built with **read-fanout** use cases in mind, where the same message needs to get read by multiple systems. As such, it’s common for the system’s read throughput to be a multiple of its write throughput.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*NCSrrj-sLIyHRTmDPoF6vA.png)

> *💡* **pub-sub messaging system (2/8)** *— this is what a pub/sub event log messaging system is. A message can be read multiple times, as opposed to a queue where it’s typically read once.*

With Kafka, organizations don’t need to maintain dozens of fragile custom point-to-point pipelines that break whenever a single VM restarts. The data can be written to Kafka once and read as many times as necessary by whatever system needs it.

> *In this article, we won’t talk further about the use cases of Kafka. If you’re more interested in the reason behind Kafka, I recently covered in-depth why LinkedIn created Kafka. It made the front page of Hacker News.*
> 
> *✅ Check it out* [*here*](https://bigdatastream.substack.com/p/why-was-apache-kafka-created)*.*

## The Basic Kafka Concepts

Okay, let’s dive into Kafka now! To truly understand the system, we need to start from the basics.

Let’s examine its core data structure:

### The Log Data Structure

Kafka is built upon the [simple log data structure](https://topicpartition.io/definitions/the-log).

It is append-only; you can only add records to the end of the log (no deletes or updates allowed). Reads go from left to right, in the order the records were added.

Each record in the log has a unique monotonically increasing number called an **offset**. The offset refers to the record and denotes its order.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*FizZVgXF2gkkW3IqFsYpPw.png)

[https://topicpartition.io/definitions/the-log](https://topicpartition.io/definitions/the-log)

The API of the log data structure is very simple:

```c
public interface Log {
  // save an entry to the end of the log
  void append(byte[] r);
```
```sh
// read a sequential chunk of the log
  byte[] read(int startOffset, int endOffset);
}
```

Kafka keeps the log structure on disk. The log’s sequential operations work very well with HDDs. Hard drives offer very high throughput for sequential reads and writes. This differs from random reads and writes, where HDDs don’t perform well.

> **A sequential read** means reading bytes laid out contiguously on the physical drive. Random reads mean the opposite — you have to jump to different parts of the drive to read the bytes.

### Records

> ***{record, message, event}*** *means an entry in the log and represents a data point. I use these words interchangeably when describing data in Kafka.*

Each message is essentially a key-value pair; it consists of a \` `byte[] key` \` and a \` `byte[] value` \` (although other metadata like offset, timestamp, and custom headers exist too). The key is optional; it is valid for a message to only have a value.

```c
/* A Kafka record/message/event is the smallest
logical unit of data stored in the log */
public class Record {
  private byte[] key; // optional
  private byte[] value;
}
```

The key thing to remember is that the key/value pairs are **raw bytes**.

Kafka does not inherently support types (e.g., int64, string, etc.) nor schemas (specific message structures).

It is the client-side code’s responsibility to apply schemas:

- **When writing**: producer clients convert (serialize) the objects into bytes.
- **When reading**: consumer clients parse (deserialize) the raw bytes from the network into the object.

## Topics & Partitions

### Topics

A topic is the logical separation of data (that you store in logs).

One log is not enough. You want to separate your data into categories. Just as in a database, you would create separate tables for user accounts and customer orders; in Kafka, you would create separate topics.

It’s common for a Kafka cluster to have hundreds to thousands of topics.

### Partitions

Kafka is a distributed system designed to scale much further than what a single machine can handle. As such, it uses **sharding**.

A topic is sharded into one or more partitions.

Each partition is a separate instance of the log data structure.

While a topic can have just one partition, it’s very common for it to have dozens, since this helps with parallelization of reads (more on that later).

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*7w0RRQUgYNRlHdkmeBRHnw.png)

Kafka can have many topics. Each topic has many partitions itself. A partition is a log. The log has many records.

> One of the age-old questions in Kafka is “how many partitions should my topics have?”.  
> There is no universally good answer to this question.  
> \- Too many partitions and your cluster pays a CPU overhead for maintenance (a ballpark of what a Kafka cluster can handle is up to 100–200k partitions total).
> 
> \- Too little partitions and your topic can’t scale to handle reads.
> 
> The important thing to know is that once created, a topic’s partitions **cannot** be reduced. They can be increased, but this introduces the shard remapping problem. In Kafka, this breaks ordering guarantees of the data written prior to the increase as records with a particular key may get routed to a new partition.

## Clients & The API

Kafka doesn’t use HTTP. It uses its own [TCP](https://networklessons.com/network-fundamentals/introduction-to-tcp-and-udp) -based protocol. This means that you need more custom code to send and receive requests; you can’t just use any HTTP library.

Kafka provides its own libraries that implement the underlying protocol. The main clients you’d care about are the **Producer** and the **Consumer**.

- **Producer**: the class that’s used for writing data to Kafka
- **Consumer**: the class that’s used for reading data from Kafka

The Apache Kafka project offers a Java library that implements these:

```c
import org.apache.kafka.clients.producer.KafkaProducer;
```
```sh
import org.apache.kafka.clients.consumer.KafkaConsumer;
```

The Producer class allows you to **send messages** to a topic. You can explicitly choose the partition or allow Kafka to do it automatically for you.

```c
KafkaProducer<String, String> producerClient = new KafkaProducer<>(props);
val record = new ProducerRecord<>("my-topic", desiredPartition, "key", "value")
producerClient.send(record);
val record2 = new ProducerRecord<>("my-topic",
/* ANY PARTITION (it's implicitly chosen) */ "key", "value")
producerClient.send(record2);
```

For reading, it’s the **Consumer** class and its API:

```c
KafkaConsumer<String, String> c = new KafkaConsumer<>(props);
// subscribe to specific partitions
c.assign(List.of(new TopicPartition("my-topic", 0)));
// or subscribe to the topic in general and
// let Kafka figure out which partition it’ll assign to you
c.subscribe(List.of("my-topic"));
```
```sh
// poll for the latest records
while (true) {
  ConsumerRecords<String, String> records = c.poll(Duration.ofMillis(100));
  for (ConsumerRecord<String, String> rec : records) {
    System.out.printf("Got record with key=%s and value=%s at offset %d %n",
      rec.key(), rec.value(), rec.offset());
  }
}
```

This is simply the most important API I can show you concisely; a lot more exist. Kafka may seem simple, but it has many details to learn to be effective with it.

## Message Order

Consumers are guaranteed to read the messages in the order in which they arrived on the server.

With one caveat — this only applies **within a single partition**.  
Between partitions, no order of messages exists.

Producers can explicitly choose the partition they produce to, or they can configure a specific partitioning strategy depending on the key of the record. This can ensure, for example, that website actions from the same user ID go to the same partition.

In practice, some big tech companies tend to omit ordering at the Kafka layer and utilize the random partition strategy in order to gain the best performance from load balancing. Others rely on the ordering.

No two consumers from the same group (more on what that is later) read the same partition at once. This guarantees that a single consumer instance will read said messages in order too, allowing it to perform local stateful actions on the data (e.g analysis/aggregation). This helps with scalability, as an important principle for performant distributed systems is to do as much work locally as possible.

## Basics Summary

This is the high-level of Kafka:

1. Messages are stored in topics.
2. Topics are sharded into 1 or more partitions (log data structures).
3. Each message in a partition has a unique offset denoting its position in that log, and messages are stored in the order in which they arrived.
4. Clients can choose to explicitly order messages depending on some characteristic, or can simply order at random for better performance.

If you are a high-level user of Kafka, this is more or less all that you need to know in order to build on top of it.

That being said, the system has many more specifics that it frequently forces you to learn. Let’s dive into them!

## Kafka as a Distributed System

Kafka is a distributed system — it’s common to have clusters with dozens of nodes (called brokers) and thousands of partitions. Let’s concisely go over some of the internals there:

## Brokers

Apache Kafka is designed to be a ***distributed*** system — one meant to scale horizontally by adding more nodes. As such, any normal deployment of Kafka consists of at least ***three nodes***.

- ***Broker***: an instance of the Kafka server. This is what we call a node in the system.

Brokers serve client requests. Stuff like the Produce request (what you send to write data to Kafka) and the Consume request (what you send to read data from Kafka)

- ***Cluster***: all the brokers in the system.

> *💡* **distributed (3/8)**

## Replication

A partition in Kafka doesn’t live only on one broker — it lives across many.

Kafka is a fault-tolerant system made to handle single machine failures and offer high durability so that you don’t lose your data if you lose a single broker. It achieves this through **replication** — partitions are replicated (i.e copied) at a configurable replication factor number — defaulting to three replicas.

A configurable setting (called **replication factor**) denotes how many copies should exist. The default and most common is **three**.

In other words, we have three copies (called **replicas**) of the Log data structure. These replicas live on the disks of different brokers.

The structure is roughly:

1. topics (have many)
2. partitions (have many)
3. replicas (have many)
4. files in a folder on a disk (that together form the full log)

Replication is done for many reasons, one of which is data **durability**: when three copies of the data exist, one disk failing won’t lead to data loss.

> **Durability** refers to long-term data protection — ensuring that data never gets lost or corrupted.

In modern cloud deployments, brokers are spread across different [availability zones](https://blog.2minutestreaming.com/p/basic-aws-networking-costs#:~:text=AZ%20\(Availability%20Zone\)%20%2D%20a%20physically%20isolated%20location%20with%20one%20or%20more%20data%20centers%2C%20inside%20a%20region). This ensures very high durability and availability. Even in the unlikely event of a whole data center burning down, the Kafka cluster would still survive.

> *💡* **durable (4/8)**

Kafka supports both synchronous and asynchronous replication from the point of view of the writer. It’s up to the Kafka client to specify which replication it would like to have. It depends on a client-side config — the producer’s \` [acks](https://blog.2minutestreaming.com/p/kafka-acks-min-insync-replicas-explained) \` config.

- **acks=all** (synchronous replication) — the producer receives a response only once all followers are confirmed to have replicated the data
- **acks=1** (asynchronous replication) — the producer receives a response only once the leader is confirmed to have received the write

Reads always use synchronous replication — a consumer can only read a message once it’s confirmed to have been replicated in every replica. This is done to avoid [phantom reads](https://blog.2minutestreaming.com/p/kafka-high-watermark-offset).

## Leaders

Once you start maintaining copies of data in a distributed system, you open yourself to a lot of edge cases. Keeping new data in sync is tricky. The copies must match, and the system needs to somehow agree on the latest state.

> *There is a whole class of complex algorithms in computer science called* [*distributed consensus*](https://sre.google/sre-book/managing-critical-state/)*, which handle this.*

Kafka uses a straightforward single-leader replication model. At any time, one replica serves as the leader. The other two replicas act as followers (i.e., hot standbys).

Only the leader accepts new writes — it serves as the source of truth of the log. The followers actively replicate data from the leader. Reads can be served from both the leader and its followers.

When a broker node goes offline, the system notices it. Other brokers then take over the leadership of the partitions the dead broker led. This is how Kafka offers high availability.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*JGseZfJh6JW4URyj5zhlgw.png)

A topic with 4 partitions and a replication factor of 3, with different brokers leading different replicas of the partitions. Brokers with follower replicas send fetch requests to the brokers with leader replicas to replicate the data

> *💡* **fault-tolerant (5/8)**

## Scalability

Kafka has a ton of interesting performance optimizations (more on this in another article). Its greatest strength is its horizontal scalability.

> *💡* **scalable (6/8)**

The [Log data structure](https://topicpartition.io/definitions/the-log) is key to Kafka’s scalability — writes on it are O(1) and lock-free. This is because records are simply **appended to the end** and cannot be updated, nor individually deleted.

Messages within a partition are independent of each other. They have no higher-level guarantees like unique keys. This reduces the need for locking and allows Kafka to append to the Log structure as fast as the disk will allow.

Because each partition is a separate log, and you can add more brokers to the cluster, your scale is limited by how many brokers you can add.

Nothing theoretically stops you from having a Kafka cluster that accepts **50 GiB/s of writes** and then scaling it 2x to **100 GiB/s**.

> Theoretically, you can do this by using very good high-end hardware with ample networking capacity. An example could be 75 brokers each accepting 512 MiB/s of writes. Modern SSDs can do this without a problem. Practically speaking, it would be very hard to operate and may require custom code. Therefore most prefer to split such workloads into many clusters.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*SWuC8Aj9CSGVRI3R9hJ50Q.png)

Some of the biggest Kafka deployments that have been publicly shared

## The Metadata Log

In a distributed system, all nodes must agree on the latest state of the cluster. Brokers must coordinate on certain metadata changes, like electing a new leader. This is again a distributed consensus problem.

Because it’s too complex for the purposes of introducing Kafka, we will simply gloss over how Kafka solves it.

Kafka uses a **centralized coordination model**.

> *💡* ***Centralized coordination*** *in distributed systems means all the nodes rely on a single authority, like a coordinator or a leader. This authority makes decisions, enforces rules, and keeps the state consistent. Alternative interesting models include things like quorums, gossip, and CRDTs.*

The central coordinator is none other than… **a log**.

Kafka durably stores all metadata changes in a special ***single-partition*** topic called `__cluster_metadata`. This storage model inherits all the benefits from topics. It gets fault-tolerance, durability, and most importantly for metadata, **ordering**.

Each record in the log represents a **single cluster event** (a delta). When replayed fully in the same order, a node can deterministically rebuild the same cluster end state.

> ***💡 The Stream-table duality*** *is the simple idea that a stream of events and a table are two sides of the same coin. Any mutation to a table (update/delete/insert) is in itself an event. The table simply represents the end state of all events. If you start from scratch and replay all the events, you reach the same table.*
> 
> ***Event-sourcing****, on the other hand, is the design of a system around this log-based stream of events.*
> 
> *The ideas have their roots in* ***materialized view theory*** *in databases and in* ***change data capture****. (Some sources, if you’re extra curious:* [*stream-table duality*](https://medium.com/event-driven-utopia/the-duality-of-streams-and-tables-why-it-matters-ed9bb17e7505) *and* [*event-sourcing*](https://martinfowler.com/eaaDev/EventSourcing.html)*)*

Here is a visual example of how it works in Kafka:

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*X_A2OxADjwfbkP4DSmCF_g.png)

A representation of how cluster events represent changes in the cluster state, and how applying one after the other results in the same end-state

In other words, the cluster metadata topic partition is the source of truth for the latest metadata in Kafka.

Every broker in the cluster is subscribed to this topic. In real time, each broker pulls the latest committed updates. When a new record is fetched, the broker applies it to its in-memory metadata. This builds the broker’s idea of the latest state of the cluster.

If every broker is a follower of the partition, a natural question arises — ***who is the leader***?  
What node gets to decide what new metadata is written to this partition?

## Controllers

Controllers serve as the control plane for a Kafka cluster. They’re special kinds of brokers that don’t host regular topics — they only do specific cluster-management operations. Usually, you’d deploy three controller brokers.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*Q270XW8MqqFYmvdux5q9sw.png)

Every broker reads the \_\_cluster\_metadata log and replays the event logs to recreate the latest cluster state, regardless of whether it’s a controller broker or a regular broker.

At any one time, there is only one active controller — the leader of the log. Only the active controller can write to the log. The other controllers serve as hot standbys (followers).

The active controller is responsible for making all metadata decisions in the cluster, like electing new partition leaders (when a broker dies), creating new topics, changing configs at runtime, etc.

Most importantly, it’s responsible for determining broker liveness.

> ***💡 Liveness*** *is a tricky distributed systems term that basically means that the system will eventually make progress (i.e it won’t freeze up).  
> In the context of broker liveness, it means that a dead broker will get fenced, so partitions don’t get stuck on a dead node. This allows the cluster to move forward. Liveliness technically also means that an alive broker will eventually be unfenced.*

Every broker issues [**heartbeats**](https://martinfowler.com/articles/patterns-of-distributed-systems/heartbeat.html) to the active controller. If a broker does not send heartbeats for 6 seconds straight, it is fenced off from the cluster by the controller. The controller then assigns other brokers to act as the leaders for the partitions the fenced (dead) broker led.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*qdT0xOHdGHoxYTYiuDIkBg.png)

The careful reader will now ask:

> *If the active controller is responsible for electing partition leaders, who’s responsible for electing the* `*__cluster_metadata*` *leader?*

The `__cluster_metadata` partition is **special**. A custom distributed consensus algorithm is used to elect its leader.

## KRaft

Leader election in a distributed system is a subset of the consensus problem. Many consensus algorithms exist, like Raft, Paxos, Zab, and so on.

Kafka uses its own [Raft](https://raft.github.io/) -inspired algorithm called KRaft (Kafka Raft).

KRaft has two key roles:

**\[1\]** Elect the active controller 👑

The controller nodes comprise a Raft quorum. The quorum runs a Raft election protocol to elect a leader of the `__cluster_metadata` partition. The leader of that partition **is the active controller**.

**\[2\]** Agree on the latest state of the metadata log

Metadata updates are first appended to the Raft log on the active controller. They are marked committed only when a majority of the quorum has persisted them.

—

The active controller determines the leaders for **all the other** regular topic partitions. It writes it to the metadata log, and once committed by the controller quorum, the decision is set in stone.

In other words, the way leader election in Kafka works is:

- Leader election ***between the controllers*** (picking the active one) is done through a variant of Raft (KRaft)
- Leader election ***between regular brokers*** is done through the controller.

KRaft is a relatively recent algorithm in Apache Kafka. For many years, Kafka [used ZooKeeper](https://stanislavkozlovski.medium.com/apache-kafkas-distributed-system-firefighter-the-controller-broker-1afca1eae302). Back then, there was just one controller. It performed the same tasks as today, but critically also had the responsibilities of a regular broker. Its decisions were persisted in [ZooKeeper](https://en.wikipedia.org/wiki/Apache_ZooKeeper), which used the Zab consensus algorithm behind the scenes.

## Get Stanislav Kozlovski’s stories in your inbox

Join Medium for free to get updates from this writer.

This coordinator-based leader election model differs from other systems. For example, RedPanda (a C++ rewrite of Kafka) uses a separate Raft quorum per partition.

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*RRkQLaIDXfgiO-Vl5ZiCHQ.png)

the different consensus designs

## Other Features That Set Kafka Apart

## Data Retention

A key motivation in Kafka’s design was to add the ability to replay historical data and decouple data retention from clients. Alternative messaging systems would store messages as long as no client has consumed them, and once consumed, delete them.

Kafka flips this model — it offers a simple time-based SLA as the message retention policy. A message is automatically deleted if it has been retained in the broker longer than a certain period, typically 7 days. The fact that the Log data structure’s O(1) performance doesn’t degrade with a larger data size makes this feasible.

Through this model, Kafka offers the feature of **replayability** — the ability to reprocess old historical messages. That is extremely useful in cases where, for example, a consumer has had a dormant bug in it for a while and erroneously processed messages. When the bug is fixed, the correct logic can be rerun on the same messages.

## Tiered Storage
****
Unfortunately, at scale, it becomes extremely tricky to manage so much historical data.

A cluster with 1 GB/s of producer bandwidth would collect 1,772 TB worth of data across the cluster. Even if you tried to spread itacross 100 brokers, that’s still 17TB worth of data that each broker would have to host on its disk.

With so much state, [a lot of problems start piling up](https://blog.2minutestreaming.com/p/apache-kafka-kip-405-tiered-storage):

- ❌ The system becomes inelastic. This happens because any action or incident requires a massive amount of data to be moved. That takes a long time.
- ❌ Further, the way the cloud is priced — [durably hosting data yourself](https://aiven.io/blog/16-ways-tiered-storage-makes-kafka-better#cost) on [HDDs tends to cost](https://getkafkanated.substack.com/p/how-to-size-your-kafka-tiered-storage-cluster) **10x more** than storing it in S3.

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*07wgbl3Q5Y-PztjEtKk9aw.png)

btw if you’re interested in calculating your Kafka costs, I have a free tool — https://2minutestreaming.com/apache-kafka-calculator

The Kafka community found an ingenious way to solve [all these problems](https://aiven.io/blog/16-ways-tiered-storage-makes-kafka-better#1-simpler-operations) with one simple idea → outsource them to S3.

While it may sound overly simple or lazy, it is an **extremely elegant solution**. S3 is a [marvel of software engineering](https://bigdata.2minutestreaming.com/p/how-aws-s3-scales-with-tens-of-millions-of-hard-drives) — it is maintained by hundreds of bright Amazon engineers. It is most likely the largest scale storage system known to man.

Kafka uses a pluggable interface to store cold data in a secondary storage tier. All three cloud object stores [are supported](https://github.com/Aiven-Open/tiered-storage-for-apache-kafka) as the secondary tier, and you are free to extend it further.

In essence, the data path in modern Kafka looks like this:

1. **Hotset Tier**: Write a message to a Kafka broker, which gets replicated across the replicas in the cluster. The message is stored on disk across all three nodes. The message is asynchronously offloaded to S3 (the secondary cold tier)
2. **Cold Tier**: After a configurable amount of time (e.g., 12 hours), the message is deleted from the brokers. Its only source of truth is left in S3. It expires from S3 after a separate configurable period.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*qchY2aP3jxTSrjC8kBX9jQ.png)

You can still read the cold historical data from Kafka using the regular APIs. The only change is that the broker now fetches it from S3 instead of its own disk.

This results in slightly higher latencies when fetching historical data, but can be alleviated through caching. Latency for hot data can improve because it makes it cost-effective to deploy performant SSDs (instead of HDDs). Throughput remains the same very high number. Kafka as a system becomes much more elastic because it no longer needs to move massive amounts of data whenever new brokers are added or removed.

Storing large amounts of data in Kafka also ends up becoming more than 10x cheaper.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/0*CdU9xY-Fe9Uuikku.png)

## Consumer Groups & Read Parallelization

Recall that the log is read sequentially and in order:

- A topic is split into partitions because it’s Big Data™ — a single node shouldn’t be able to consume the whole topic. You need many consumers to handle the high volume of topic data.
- **Only one consumer** is meant to read from a partition at a time. This is done to ensure message order without needing locks.
- These consumers need to coordinate on how to split partitions between each other.
- At the same time, Kafka’s goal is to allow **parallel** consumption (multiple readers) of **the same** partition(s) for high read-fanout cases.

Kafka addresses this through **consumer** **groups**. These groups are a set of consumer client instances (typically on separate nodes) that operate as one coherent unit. They distribute the work among themselves.

Each consumer group reads topics independently at its own pace. Consumers within the same group split the partitions between each other.

Consumer Groups support dynamic membership — you can scale consumption up or down by adding or removing members at runtime.

In essence, read throughput in Kafka can be scaled in two different ways:

1. Add more **consumers** to your group
- *e.g., your topic went from 10 MB/s to 20 MB/s of throughput, and your two existing consumers can’t keep up. Add more so they take up the extra load.*

2\. Add more consumer **groups**

- *e.g., your topic is being consumed, but you’d like a new, separate application type to process the data too. For example, a nightly accounting job wants to catch up with the last day’s worth of payments.*
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*wfD_wva6nzqW5R2Q-hcP8A.png)

Two different consumer groups reading the same Kafka topic. The “fraud detection” group is expanding by adding a new consumer. A new “accounting” consumer group consisting of two consumers is starting up too.

## The Consumer Group Membership Protocol

Consumers within a group form a ***distributed processing system.*** Unsurprisingly, we hit more distributed systems’ problems — how do we coordinate the consumers? They need to:

- Establish consensus on progress (up to what offset did they read to)
- Handle liveness (did a consumer go offline, and how do we take over its work)
- Handle dynamic membership (did a new consumer come online)
- Distribute work between themselves (which consumer will take which partition)

Kafka consumers within the same group don’t talk to each other. They coordinate indirectly through a Kafka broker. The broker that leads a certain group is called the **Group Coordinator**.

Kafka again uses a **centralized coordination model** — the Group Coordinator makes the decisions. Consumers heartbeat to the coordinator and, through a pull-based model, inform themselves of what work they should do.

### The \_\_consumer\_offsets Topic

The Group Coordinator also acts as the “database” which stores the progress of each consumer.

Consumer Groups store a simple mapping of ***\`{partition, offset}*** \` in a special Kafka topic called ***\`\_\_consumer\_offsets\`***. This helps them save the progress on what record they have ***read up to.*** (key word — “up to”)

When a consumer reads messages, it commits the offset **up to** which it has processed the log via the coordinator broker. This regular checkpointing allows for smooth failovers. In the event of failure, the consumer can restart and resume from where it ended, or another consumer can come and pick the work back up.

The special offsets topic has many partitions spread throughout brokers. Each group is associated with a particular partition. The leader of the particular partition that the group is associated with acts as the Group Coordinator for that group. In that sense, every broker in the cluster can act as a coordinator for some consumer group. This prevents hot spots where one broker handles all the consumer groups in the cluster.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*-ZyPsMzn0426ITgw1vQGDg.png)

Two different consumer groups reading the same Kafka topic

The consumer group protocol is a critical part of Kafka.

It is generic enough to support other use cases beyond consumer groups. It therefore provides **a way for external distributed systems to establish leader election and durably persist state through Kafka**.

Keep this in mind: the next three systems we’ll discuss depend on the group protocol to work as distributed systems.

But first, a little about transactions:

## Transactions & Exactly Once Processing

I will try to keep this brief because it can get pretty complicated — Kafka supports **transactions**. But they aren’t quite like database transactions — it’s more about message visibility control.

A transaction in Kafka means that:

- A producer can send many messages. Those messages can go to different topics or partitions. They can also reach various brokers.
- Those messages will **atomically** either be committed or aborted across all brokers.

Technically, this happens *from the perspective* *of a consumer.* In other words, the messages are still written to the topics, but consumers can be configured to skip non-committed ones. This is client-side filtering at work.

Marking transactions as committed or aborted is achieved through a two-phase commit protocol. It again relies on a centralized coordination model. A Transaction Coordinator broker makes this work. It’s pretty complex.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*alv6tsX6G_JRZjq968wtQA.png)

A producer writing messages to multiple topics and partitions in the same transaction. It manages and commits the transaction via the broker acting as the Transaction Coordinator

The important thing with transactions is that they enable message deduplication in common cases.

- **⚡️ Network/broker blips**: if the network drops the broker response packets, or the broker restarts, the same producer client will **idempotently** write its message without creating duplicates.

> ***💡 Idempotency*** *means not repeating the same action twice. If a “Create User Bob” request is sent twice, an idempotent system would create the user only once. In Kafka, this is achieved by associating a unique monotonically increasing ID with each message. So you could send the message (“Create-User-Bob, 1”) twice, but Kafka will accept it only once because of the unique ID. This is not foolproof, though, because the unique ID comes from the Kafka Producer client. Two producers can therefore create the same message with different IDs.*

- **💥 Producer client blips**: if the producer itself restarts from a clean state, it will fetch its monotonically increasing ID and bump an epoch. This way, a potentially old zombie instance with the old epoch can’t interfere with the transaction.

This doesn’t remove all cases of duplicates. Edge cases from external systems can still exist.

> ***re: the edge cases*** *— most simply said, imagine you have an HTTP service receiving requests. The service processes the request “Create user Bob” and successfully produces the message to Kafka. Before the service responds with an HTTP response to the user, it crashes. The user then retries the same HTTP request, and the new service produces the same “Create user Bob” into Kafka. From Kafka’s PoV, this is fine because it sees both as separate messages. The HTTP service evidently does not support handling idempotent requests and exactly-once processing.*

However, when reads and writes only involve Kafka (and no other external system), exactly once processing is possible.

This is actively supported and used in Kafka Streams, as we will cover shortly 👇

## Other Kafka Components

The [Apache Kafka GitHub project](https://github.com/apache/kafka) consists of a few components, two of which we already covered:

- **Kafka Core**: the brokers, controllers, and coordinators (back-end).
- **Kafka Clients**: the Kafka client libraries (producer, consumer).

The reason Kafka is called a distributed streaming **platform** is because it consists of more components than just those two:

1. it offers first-class stream processing (**Kafka Streams**)
2. it offers first-class integration capabilities (**Kafka Connect**).

The next three systems we will go over rely on it to function as distributed systems.

## Kafka Streams

Kafka Streams is a higher-level stream processing Java library for Kafka.

> **💡 What is Stream Processing?**
> 
> ***Stream processing*** *— the easiest way to understand it is through the opposite extreme —* ***batch processing****. Imagine you are Tesla and are collecting data from your fleet of cars. At the end of each business day, you run a big report. The report joins data from multiple sources and creates a dashboard that an executive in Tesla sees. They use it to see summaries like the number of kilometers crossed, times they had to charge the Tesla, how often X feature was used. It runs once a day and calculates data after a cut-off date (e.g., end of day). Stream Processing would be the opposite — it would have the cars continuously emit data like their tire pressure (psi). It would then perform windowed aggregations on this data to understand, in real time, what’s happening to the car. If the tire pressure went from 45psi to 41psi over the course of 15 minutes, you’d know* ***the tire is losing pressure****. If the tire pressure went from 45psi to 20psi over the course of* ***10 seconds****, you’d know you* ***blew out a tire****. Tesla could implement this example by deploying a lot of Kafka Stream jobs in their back-end. (assuming the data exists in Kafka)*

A KafkaStreams stream processor is a simple program that:

1. continuously reads a stream of messages from a set of Kafka input topics
2. performs some processing on these messages (map, filter, joins, windowed aggregations, etc.)
3. continuously write the results into an output topic

Kafka Streams is a library in that you simply import it into your app — e.g:

```c
import org.apache.kafka.streams.KafkaStreams;
```

Here is a simple pseudocode example of its declarative API:

```c
builder.stream("page-views")
.filter((page, pageView) -> !isBot(pageView))
.windowedBy(Duration.ofMinutes(1))
.count()
.toStream()
 .to("page-traffic-sums");
```

This code continuously counts the sum of human page views over the last minute and produces it to a new topic. Here’s an example of what the Kafka topics would look like:

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*s_Jtp8mmzxR8DFnwSouBlQ.png)

An example of how the records in the source page view topic get processed into page traffic sums

This API is intended to be used within your own Java applications. It works like the consumer. It helps you scale by spreading the stream processing work over multiple applications (just like consumer groups do). One difference is that it also lets you spread the work through **threads**. It uses the same consumer group protocol underneath to coordinate work between instances.

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*ZLzeMij-hkwDXYWBY2kKxA.png)

An example two-node stream processing job

It is technically possible to achieve this with your own code using the simple producer/consumer libraries, but it’d be a lot of work. Kafka Streams is a higher-level abstraction above both clients with a ton of extra processing, orchestration, and stateful logic on top. 👌

Kafka Streams only works with Kafka. It takes input from a Kafka topic and sends output to another Kafka topic. This setup allows Kafka Streams to guarantee exactly once processing by using Kafka Transactions. Practically speaking, this means that it can ***atomically*** process data.

For example, it could read a set of payment messages in a Kafka topic, calculate the sum, and persist the result in another Kafka topic, with a 100% guarantee that no message was lost or double-counted in the process.

> *If interested in more, here is a quick introduction to* [*Kafka Streams*](https://bigdata.2minutestreaming.com/p/what-is-kafka-streams-api-guide)*.*

## Schema Registry

Kafka does not support types (e.g., int64) nor schemas. Messages are just raw bytes.

> **💡 What’s a Schema?**
> 
> *A* ***schema*** *basically means the expected structure of your data. A database table has a very strict schema — you know what type each field is and what fields there are (e.g id BIGINT, name VARCHAR, cost DECIMAL, is\_premium BOOLEAN). You can’t add fields or types that don’t match, like a string for an ID. A JSON object by itself is schemaless — you can modify it however you want and it’s still a valid JSON object (the only question is whether your server will accept it, and that depends on the modification). In the same way, a blob of bytes doesn’t have a strict structure — you can add any garbage in there. There is a project that adds a strict structure to JSON objects called* [*JSON Schema*](https://json-schema.github.io/json-schema/example1.html)*. Similarly, there are projects that add strict structure to blobs of bytes (*[*Protobuf*](https://protobuf.dev/)*,* [*Avro*](https://avro.apache.org/)*). It’s important to have schemas because they are critical to validating and catching bugs in your data early.*

To process a message, like summing order payment values, you need to be able to parse the message structure and the exact value field.

I believe this was a [big mistake](https://bigdata.2minutestreaming.com/i/170964904/schemaless-kafka) by the project. Every important use case, like Connect, Streams, and general processing, must understand the data’s structure.

So how is this achieved, then?

There’s no “official” way, because the open source Apache project does not support schemas. 🤦🏻♂️

There is a common convention, though. That is to use an external HTTP service with a database that stores the schemas.

In practice, a Kafka topic acts as this database. It stores a simple pair of ***{schema, topic}***. Kafka clients connect to the service, download the schema, and use it whenever they serialize/deserialize messages.

The first such registry was a [source-available project](https://github.com/confluentinc/schema-registry) by Confluent called Schema Registry. However, without official Apache support or a truly open-source license, the ecosystem has fragmented. There are many different service implementations today.

> *A few schema registry implementations are* [*Karaspace*](https://github.com/Aiven-Open/karapace) *(Apache-licensed),* [*AWS Glue*](https://docs.aws.amazon.com/glue/latest/dg/schema-registry-integrations.html) *(proprietary),* [*ApiCurio*](https://github.com/Apicurio/apicurio-registry) *(Apache-licensed),* [*Buf Schema Registry*](https://buf.build/product/bsr) *(proprietary),* [*and Redpanda*](https://github.com/redpanda-data/redpanda) *(mixed licenses).*

Many Kafka users also opt to manage schemas in their own unconventional ways.

The way the end-to-end path conventionally works with schemas:

1. Producers decide on a schema, associate it with a topic, and register it in the registry
2. Producers then serialize the message in the correct structure (including the unique schema ID in the message) and write it to Kafka
3. Consumers download the message, parse the schema ID, then fetch (and cache) the schema from the registry
4. Consumers use the schema to deserialize the message

## Kafka Connect

Kafka [was created to solve LinkedIn’s data integration problem](https://bigdatastream.substack.com/p/why-was-apache-kafka-created). It is meant to move data between different systems. This can be difficult because each system can have its own API, its own protocol (TCP, HTTP, JDBC, etc.), its own format (XML, JSON, Protobuf, Avro), and different compatibility guarantees.

Kafka Connect helps standardize this. Connect is both a framework (set of APIs) and a **runtime** for plugins that connect Kafka with external systems.

> *💡 A* ***runtime*** *here means that you deploy the Connect software, and then, via \`curl\`, schedule extra pre-defined code to run on top of it (plugins).*
> 
> *A* ***framework*** *means that you’re free to write your own plugins that use the API if you’d like.*

For the end user, it’s a no-code/low-code framework to plumb popular systems to Kafka and back (think ElasticSearch, Snowflake, PostgreSQL, BigQuery).

This ensures a single, standardized way to integrate systems together. The tricky bits of code that guarantee fault-tolerance, ordering, and exactly-once processing are written once (in the form of plugins) and battle-tested.

![](https://miro.medium.com/v2/resize:fit:2000/format:webp/1*EehCBTWM3w-v45NIwSNRjQ.png)

An example of Kafka Connect integrating data into Kafka. Source Connectors read data from MongoDB and write to Kafka. Sink Connectors read data from Kafka and write it to Snowflake.

Connect has three main terms one should know about:

- **Connect Workers**: the simple nodes that form a distributed Connect Cluster
- **Connect Herder**: a worker that acts as the manager of the cluster. It exposes a REST API with which users can check the status of tasks, start new ones, etc
- **Connectors**: the plugins (or libraries) that run on the workers. They contain the code needed to integrate with other systems
- A **Source** Connector reads data from an external system and writes it to Kafka (System->Kafka)
- A **Sink** Connector reads data from Kafka and writes it to an external system (Kafka->System)

The end user spins up a cluster with several Worker nodes. They install the particular Connector plugin jars on these nodes. Then, they start the integration with a simple HTTP POST request.

This again forms another distributed processing system. The Herder leader election, general cluster membership, and the distribution of new tasks throughout the group of Workers are all done transparently via Kafka’s Consumer Group protocol.

Essentially, Connect is a lot of plugin-specific integration logic on top of the regular KafkaProducer and KafkaConsumer APIs. [Hundreds of Connector plugins](https://www.confluent.io/hub/) exist, which give Kafka its incredibly rich integration capabilities.

> ***💡* rich integration (8/8)**

## 🎬 Conclusion

With that, we’ve gone over all the important internals of Apache Kafka. I repeat the introductory sentence, which you can now hopefully understand much better:

> *💡 Kafka is an open-source, distributed, durable, very scalable, fault-tolerant pub/sub messaging system with rich integration and stream processing capabilities.*

It achieves this through many internal details, including but not limited to:

- The Producer & Consumer libraries & APIs
- Topics, Partitions, and Replicas
- Brokers and KRaft Controller Quorums
- Idempotency, Transactions, and Exactly-Once Processing
- Tiered Storage
- Consumer Groups & the Consumer Group Protocol
- Kafka Streams
- Kafka Connect
- Schema Registry

This is why Kafka is the Swiss army knife of data engineering.

It is a very active open-source project that is constantly evolving. A few notable features that are currently being worked on are:

- [Queues](https://blog.2minutestreaming.com/p/apache-kafka-share-group-queues-kip-932): the ability to read a partition with queue-like semantics. Queues have no ordering but allow for multiple consumers to read from the same log with per-record acknowledgement. This is different from Kafka’s exclusive one-consumer-per-partition model. In that model, consumers read data in order and only know “I’ve read **up until** this message”.
- [Diskless Topics](https://blog.2minutestreaming.com/p/diskless-kafka-topics-kip-1150): the ability to host topic partitions in a leaderless way. This happens by leveraging object storage (S3) as the data layer instead of brokers’ disks. This feature can cut cloud costs by **90%** + (!), further boost scalability, and simplify managing Kafka.
- [Iceberg Topics](https://aiven.io/blog/iceberg-topics-for-apache-kafka-zero-etl-zero-copy): the ability to store your Kafka data in an [open table format](https://bigdata.2minutestreaming.com/p/meet-your-new-data-lakehouse-s3-iceberg) (Iceberg) in a zero-copy way.

## ✅ When to use Kafka

I want to preface this with a disclaimer that the answer to “when to use Kafka” is inherently vague — I don’t have a perfect decision tree for it. A critical filter that cuts to the root of the decision is — do you truly, actually need a real-time per-event streaming pipeline? I usually advise against building this unless the need is clear, because streaming is a paradigm shift that is difficult to get right. Batch is always easier and preferred, if the requirements are satisfied with it.

That being said, I would summarize the following reasons as good fits for onboarding a use case through Kafka:

1. You need high **durability**. (Kafka is usually run in at least 3 nodes in 3 different AZs. PS: keep in mind this comes at a price)
2. You need high **availability**. Kafka’s failover is pretty sturdy.
3. Your data access patterns require high read fan out — you write once, but read the same piece of data multiple times
4. You need either a specific message delivery requirement, or the flexibility to choose between all (at most once, exactly once processing, more than once)
5. If you have high-volume data that is naturally modelled after the append-only Log data structure. i.e requires ordering and doesn’t require deletes or edits. Good examples are app tracking records (e.g click events), operational metrics, application logs, database change data capture.
6. If you already have a Kafka deployment (duh)
7. You benefit from replayability of event data (reading old data in the order it came in).
8. When you rank career stability/safety highly (nobody fired anybody for using Kafka)

## ❌ When should I NOT use it

Despite loving Kafka and talking about it all the time, I love practicality more. I urge users to **not** adopt yet another complicated distributed system when there’s not a strong need for it. A lot of organizations have the tendency to over-engineering their solutions.

> ***💡* Over-Engineering**: *We generally have this “cargo cult” of scalability that wants to overdesign everything to handle imaginary circumstances. Nowadays, we are finally beginning to see the pendulum start swinging back with the growth of the* [*Small Data movement*](https://topicpartition.io/definitions/small-data) *and the* [*Just Use Postgres*](https://www.manning.com/books/just-use-postgres) *movement. As somebody who has worked on big data infrastructure and seen plenty of production workloads, I subscribe to their idea which says that most organizations don’t have anything close to “big” data and are over-engineering their solutions. Most importantly, hardware power is growing at a faster rate and many common workloads can be handled on a single modern machine. See DuckDB’s success, their* [*Big Data is Dead*](https://motherduck.com/blog/big-data-is-dead/) *blog post and* [*Small Data Manifesto*](https://motherduck.com/blog/small-data-manifesto/)*. On the same note — somebody once called Kafka the “MongoDB of sequential storage” and that quote lives rent free in my head to this day. The similarity is that it was also built for* [*webscale*](https://www.youtube.com/watch?v=b2F-DItXtZs) *and then widely adopted based in part on impressive performance numbers without much regard for how fit it for the use case.*

Teams should carefully weigh the organizational overhead of adopting a new technology versus using something simpler, like infrastructure that’s already deployed. I made this convincing argument in deeper detail in my recent piece [“Kafka is fast — I’ll use Postgres”](https://topicpartition.io/blog/postgres-pubsub-queue-benchmarks) where I compare both systems (as crazy as that sounds). That piece did extremely well on HackerNews and even prompted a response by Confluent.

In any case, here are some points on when Kafka may not be the best choice:

1. You just want to introduce some simple async background task processing. [Redis is the industry default for this](https://github.com/topics/background-jobs) with first-class library support. Although Kafka (and other systems) can do just as good of a job, many devs will prefer to use an established library than build one from scratch or use something that’s less maintained.
2. You want **queue-like** semantics — no strict ordering, granular record-level acknowledgement and retries. Kafka isn’t a queue (more on this in the next paragraph). Although it [is adding support](https://blog.2minutestreaming.com/p/apache-kafka-share-group-queues-kip-932) for queue-like workloads now, it’s still early and other systems are better established. I would definitely say [Just Use Postgres](https://topicpartition.io/blog/postgres-pubsub-queue-benchmarks) here.
3. You want queue-like semantics and more **server-side routing logic**. Things like server-side filtering, built-in dead letter queue handoff, priority queue semantics, routing based on payload, complex hierarchy or wildcard routing. [RabbitMQ](https://www.rabbitmq.com/) is more up your alley.
4. You need a **lightweight** protocol and/or an absurdly high number of clients — e.g. something like MQTT for tens/hundreds of thousands of IoT devices. Kafka does not support that protocol out of the box ([bridges exist](https://github.com/strimzi/strimzi-mqtt-bridge) though), nor is it designed to handle that many client connections. Another system would be a better fit.
5. You need extremely low latency (<15ms p99 e2e). Some Kafka vendors sell [low](https://www.redpanda.com/blog/kafka-kraft-vs-redpanda-performance-2023) [latency](https://www.confluent.io/blog/kafka-vs-kora-latency-comparison/) solutions, but open-source Kafka can find it hard to **consistently** keep such low latency. The system was simply never super optimized for such extreme low latency. Another system may be a better fit.
6. Small Scale. You’re pushing miniscule amounts of data — e.g kilobytes/s. Provisioning 3 Kafka nodes to handle KB/s can be overkill. Remember Kafka was highly marketed and adopted for its ability to scale. If your problem(s) can be solved with the infrastructure you already have now, use that. Premature optimization is the root of all evil.
7. You’re a fan of your cloud provider, prefer to keep it all in one place and aren’t afraid of being locked in. AWS has Kinesis, Google has Pub/Sub and Azure has Event Hubs. These systems aren’t necessarily better than Kafka (scalability, cost, performance, etc.), but they’re supported in a more first class way by the cloud providers. AWS has a managed Kafka service (MSK), Google has a managed Kafka service and Azure exposes a Kafka API through Event Hubs. But none of these offerings seem to be as polished as the cloud provider’s primary competitor systems.

Many alternative proprietary (and OSS) systems compete with Apache Kafka. The one common denominator is that **they all** use the same Kafka protocol and API. They just implement it differently. These include, but are not limited to, Confluent Kora, AWS MSK, RedPanda, WarpStream, StreamNative Ursa, BufStream, Aiven Inkless, AutoMQ, Tansu and more.

> *👉 My favorite up-and-coming one is* [*Tansu*](https://github.com/tansu-io/tansu)*. A Rust-based implementation of Kafka on top of Postgres (and more)  
> I recorded a 2hr30m+ podcast with the founder here:* [https://www.youtube.com/watch?v=pJQ7hcsI1Dw](https://www.youtube.com/watch?v=pJQ7hcsI1Dw) *(not sponsored)*

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*9e8I7xLUNKexOPMTIl4I0A.png)

The space is incredibly rich and rapidly evolving. I have a ton more I can talk about it. If you’re further interested in the world of event streaming and Apache Kafka, make sure to stay in touch. 🙂

## 👋 Enjoyed This?

This whole blog post was free. Others would charge you in the form of courses or books to teach you the exact same thing, whiel also taking 10x more of your time.

👉 If you’d like to “pay back”, the best way is to simply give this article some claps and share it with friends. Posting it to social forums like Reddit/HackerNews helps a lot too.

👉 If you’d like to read more extremely high-quality technical content re: Kafka and Distributed Systems, feel free to follow me on all the platforms:

> YouTube: [https://www.youtube.com/@StanKozlovski](https://www.youtube.com/@StanKozlovski/videos)  
> X (Twitter): [https://x.com/kozlovski](https://x.com/kozlovski)  
> LinkedIn: [https://www.linkedin.com/in/stanislavkozlovski/](https://www.linkedin.com/in/stanislavkozlovski/)  
> Substack: [https://bigdata.2minutestreaming.com/](https://bigdata.2minutestreaming.com/)  
> My concise 2-minute newsletter: [https://blog.2minutestreaming.com/](https://blog.2minutestreaming.com/)

*Thanks for reading. ~Stan*