---
title: "Every UPDATE Leaves a Ghost: MVCC, Bloat, and VACUUM in PostgreSQL"
source: "https://planetscale.com/blog/postgresql-mvcc"
author:
  - "[[Jan Nidzwetzki]]"
  - "[[Etienne Berube]]"
  - "[[Ahmed Darwich]]"
published: 2026-07-20
created: 2026-07-27
description: "What happens to old row versions after nobody needs them? They become dead tuples, and over time they bloat your tables. Go deeper into PostgreSQL MVCC with runnable psql examples."
tags:
  - "clippings"
---
Imagine running a big `SELECT *` on the `order` table while another process updates the same records concurrently. Your query completes displaying the original data, and the other sees successful data modification.

This is Multi-Version Concurrency Control (MVCC), a technique where the database creates new copies of rows instead of overwriting them. Using MVCC, transactions get a consistent and isolated snapshot of the data, while ongoing updates happen simultaneously. **Readers never block writers and writers never block readers** because multiple versions coexist and visibility rules determine which one each transaction can see.

There's a lot of complexity in how Postgres makes this work correctly. Here, we're gonna take a deep dive into how all this works in PostgreSQL. If database transactions are brand-new to you, you might find our [Database Transactions](https://planetscale.com/blog/database-transactions) article a helpful pre-requisite.

Let's dig in!

## Transaction basics

Transactions rely on four guarantees known as ACID: atomicity, consistency, isolation, and durability.

Those guarantees are easier to guarantee when transactions run one at a time. But how do we run thousands of transactions in parallel while safely coordinating access to the same data?

## MVCC

Early relational database management systems (RDBMS) like IBM System R solved this with read and write locks: hold a shared read lock to read, hold an exclusive write lock to modify. That kept data safe. It also meant readers blocked writers and writers blocked readers.

PostgreSQL uses Multi-Version Concurrency Control instead. This allows it to maintain more than one version of a row and let each transaction read the version its snapshot allows. Multiple tuple versions can coexist on disk. Snapshot Isolation (SI) decides which version a transaction sees when it runs a query.

PostgreSQL isn't the only database that uses MVCC, and each implements it in a different way. To understand how Postgres does, we must first understand how it stores rows in *tuples*.

## Tuples and visibility

A **tuple** is a single physical version of a row on disk. One logical row can exist as several tuples at once when PostgreSQL keeps older versions around for MVCC.

For each tuple, PostgreSQL tracks which transaction created it and which transaction deleted it. Each transaction is identified by an unsigned 32-bit integer value called the transaction id (XID). When a tuple is updated, the old version is marked as deleted and a new tuple is created.

For example:

```sql
postgres=> CREATE TABLE mytable(id SERIAL PRIMARY KEY, name VARCHAR NOT NULL);
CREATE TABLE
postgres=> INSERT INTO mytable (name) VALUES('First tuple');
INSERT 0 1

postgres=> SELECT * FROM mytable;
 id |     name
----+--------------
  1 | First tuple
(1 row)
```

We created a table and inserted one row. How does PostgreSQL know which transaction wrote it and which deleted it? Every row carries hidden system columns. `xmin` records the inserting transaction; `xmax` records the deleting one. To inspect these system columns, add them to any `SELECT`:

```sql
postgres=> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax | id |     name
-------+------+----+--------------
 22019 |    0 |  1 | First tuple
(1 row)
```

The tuple was created by the transaction with the ID `22019`. PostgreSQL implicitly creates a transaction for each insert, even when we do not start one explicitly. When using an explicit transaction with `BEGIN`, the current transaction id can be requested (and assigned, if the transaction doesn't have one yet) by calling the PostgreSQL function `pg_current_xact_id()`.

```sql
postgres=> BEGIN;
BEGIN
postgres=*> INSERT INTO mytable (name) VALUES('Second tuple');
INSERT 0 1
postgres=*> SELECT pg_current_xact_id();
 pg_current_xact_id
--------------------
              22020
(1 row)

postgres=*> COMMIT;
COMMIT

postgres=> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax | id |     name
-------+------+----+--------------
 22019 |    0 |  1 | First tuple
 22020 |    0 |  2 | Second tuple
(2 rows)
```

The transaction that inserts the second tuple has the ID 22020, which is also reflected by the `xmin` value of this tuple in the table.

This is how PostgreSQL implements MVCC. It tracks which transaction created or deleted a particular row version using these `xmin` and `xmax` columns.

## Snapshots

A single logical row can have several physical versions on disk. The question is which one your transaction sees, especially when another session commits a change mid-scan.

Snapshot isolation determines data visibility for the current transaction. SQL isolation levels define how much data modified by concurrent transactions is visible to our own.

For example, by executing `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;`, we tell PostgreSQL that subsequent reads in this transaction must always return the same data, even if another transaction modifies it in the meantime. PostgreSQL implements this by capturing a snapshot of the system's active transactions the moment the first query in our transaction runs. It uses this snapshot to filter row visibility, ensuring a static view of the data until the transaction ends.

`pg_current_snapshot()` returns current snapshot information as a string with three colon-separated values: `$xmin:$xmax:$xip_list`.

- **`xmin`:** The earliest transaction ID that is still active. All transactions before this ID have already completed, so their status is settled: committed ones are visible, aborted ones are not.
- **`xmax`:** One past the highest transaction ID that had completed when the snapshot was taken. All transaction IDs greater than or equal to `xmax` had not yet completed (or started) at snapshot time and are therefore invisible.
- **`xip_list`:** A comma-separated list of active transactions when the snapshot was taken. These transactions are considered in-progress and their effects are invisible to this snapshot, even if they commit later.

For example, the snapshot `1000:1012:1004,1005,1009` means that all transactions with an id lower than `1000` have already completed (committed or aborted). All transactions with an id equal to or greater than `1012` had not yet completed when the snapshot was taken. The transactions `1004`, `1005`, and `1009` were still in progress.

The function `pg_visible_in_snapshot()` can be used to test if a transaction ID is visible in a particular snapshot or not. For example:

```sql
-- xid is < xmin -> Visible
postgres=> SELECT pg_visible_in_snapshot('999'::xid8, '1000:1012:1004,1005,1009'::pg_snapshot);
 pg_visible_in_snapshot
------------------------
 t
(1 row)

-- xid is between xmin and xmax but in xip list -> Invisible
postgres=> SELECT pg_visible_in_snapshot('1004'::xid8, '1000:1012:1004,1005,1009'::pg_snapshot);
 pg_visible_in_snapshot
------------------------
 f
(1 row)

-- xid is between xmin and xmax but not in xip list -> Visible
postgres=> SELECT pg_visible_in_snapshot('1006'::xid8, '1000:1012:1004,1005,1009'::pg_snapshot);
 pg_visible_in_snapshot
------------------------
 t
(1 row)

-- xid >= xmax -> Invisible
postgres=> SELECT pg_visible_in_snapshot('1012'::xid8, '1000:1012:1004,1005,1009'::pg_snapshot);
 pg_visible_in_snapshot
------------------------
 f
(1 row)
```

In the following example, Session 1 starts under `REPEATABLE READ`, grabs its transaction id and snapshot, and scans `mytable`:

```sql
-- Session 1
postgres=> BEGIN ISOLATION LEVEL REPEATABLE READ;
BEGIN

postgres=*> SELECT pg_current_xact_id();
 pg_current_xact_id
--------------------
              22067
(1 row)

postgres=*> SELECT pg_current_snapshot();
 pg_current_snapshot
---------------------
 22067:22067:
(1 row)

postgres=*> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax  | id |     name
-------+-------+----+--------------
 22019 |     0 |  1 | First tuple
 22020 |     0 |  2 | Second tuple
(2 rows)
```

The output of `pg_current_snapshot()` shows that our transaction ID (`22067`) is the oldest active boundary in the system, and the active transaction list (`xip_list`) is completely empty. Transaction IDs come from a server-wide counter that advances with all activity on the server (other sessions, autovacuum, and background work).

Don't confuse snapshot `xmin` with tuple `xmin`. The snapshot fields describe which transactions were active when the snapshot was taken, the tuple columns record which transaction created or deleted that specific row version.

Next, we open a parallel connection in Session 2, perform an update on row 2, and immediately commit the change:

```sql
-- Session 2
postgres=> BEGIN;
BEGIN
postgres=*> UPDATE mytable SET name = 'Second tuple updated' WHERE id = 2;
UPDATE 1
postgres=*> SELECT pg_current_xact_id();
 pg_current_xact_id
--------------------
              22069
(1 row)

postgres=*> COMMIT;
COMMIT

postgres=> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax  | id |         name
-------+-------+----+----------------------
 22019 |     0 |  1 | First tuple
 22069 |     0 |  2 | Second tuple updated
(2 rows)
```

Back in Session 1, run the same table scan again and the changes made by transaction `22069` are not shown. Session 1 continues to see the original tuple text:

```sql
-- Session 1
postgres=*> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax  | id |     name
-------+-------+----+--------------
 22019 |     0 |  1 | First tuple
 22020 | 22069 |  2 | Second tuple
(2 rows)
```

However, the `xmax` value for row 2 has changed to `22069`. Because an update in PostgreSQL is physically a `DELETE` followed by an `INSERT`, Session 2 wrote its transaction ID into the `xmax` slot of the old row to mark it as deleted.

![An UPDATE leaves the old row version in place with its xmax set to the updating transaction, and writes a brand-new row version alongside it. The same transaction id (22069) both marks the old tuple deleted and creates the new one.](https://planetscale-images.imgix.net/assets/diagram-update-delete-insert-u7T8of0K.svg?auto=compress%2Cformat)

Session 1 reads the `xmax` value, but transaction `22069` committed after Session 1's snapshot was taken (`22067:22067:`), so the MVCC visibility rules treat the deletion as invisible and return the original row.

![Both sessions read the same heap page, which holds two versions of row 2. Session 1's snapshot lands on the old tuple while Session 2 reads the new one, so each connection gets a different answer for the same row.](https://planetscale-images.imgix.net/assets/diagram-coexisting-versions-COACd1G5.svg?auto=compress%2Cformat)

Note

A committed transaction's changes are not instantly visible to all other transactions. Visibility depends on both the transaction's status (committed or aborted) and the reader's database snapshot.

## Subtransactions

Subtransactions in PostgreSQL are transactions embedded inside an existing parent transaction. They are created using the `SAVEPOINT` command and are typically used to isolate errors within a complex workflow. If an operation fails inside a subtransaction, only the modifications made up to that last `SAVEPOINT` are rolled back, allowing the main parent transaction to continue.

### Subtransaction IDs

Just like top-level transactions, each subtransaction is assigned a unique transaction ID from the same global counter sequence. Consequently, when a row is inserted inside a subtransaction block, its `xmin` value registers the ID of the subtransaction rather than the parent transaction.

After the snapshot demo above, reset the table so the row ids and transaction ids line up cleanly. Close any still-open snapshot session first (`COMMIT` or `ROLLBACK` in Session 1), or `TRUNCATE` will sit there forever waiting for the lock.

```sql
postgres=> TRUNCATE mytable RESTART IDENTITY;
TRUNCATE TABLE
postgres=> INSERT INTO mytable (name) VALUES ('First tuple'), ('Second tuple');
INSERT 0 2
```

Now start a parent transaction, insert one row before a savepoint and one after:

```sql
postgres=> BEGIN;
BEGIN
postgres=*> SELECT pg_current_xact_id();
 pg_current_xact_id
--------------------
              22071
(1 row)

postgres=*> INSERT INTO mytable (name) VALUES ('Third tuple');
INSERT 0 1
postgres=*> SAVEPOINT s1;
SAVEPOINT
postgres=*> INSERT INTO mytable (name) VALUES ('Fourth tuple');
INSERT 0 1
postgres=*> SELECT xmin, xmax, * FROM mytable;
 xmin  | xmax | id |      name
-------+------+----+---------------
 22070 |    0 |  1 | First tuple
 22070 |    0 |  2 | Second tuple
 22071 |    0 |  3 | Third tuple
 22072 |    0 |  4 | Fourth tuple
(4 rows)
```

The two seed rows share `xmin` `22070` because they were inserted in one auto-committed statement. The third tuple was written before `SAVEPOINT s1`, so its `xmin` is the parent transaction id `22071`. The fourth tuple was written after the savepoint, so its `xmin` is `22072`, the subtransaction id. `pg_current_xact_id()` reports the parent id (`22071`) even after the savepoint; the tuple headers record which subtransaction actually wrote each row.

Rolling back to the savepoint removes only the subtransaction work:

```sql
postgres=*> ROLLBACK TO s1;
ROLLBACK
postgres=*> SELECT id, name FROM mytable;
 id |      name
----+---------------
  1 | First tuple
  2 | Second tuple
 | Third tuple
(3 rows)

postgres=*> COMMIT;
COMMIT
```

Row 4 disappears and row 3 remains. Only when the parent transaction commits do these tuples become visible to other sessions.

### Exception handling with subtransactions

Subtransactions also implement exception handling in PL/pgSQL procedures (PostgreSQL's built-in procedural language).

```sql
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(100)
);

CREATE OR REPLACE PROCEDURE insert_users() LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com');

    BEGIN
        -- This will fail because 'alice' violates the UNIQUE constraint
        INSERT INTO users (username, email) VALUES ('alice', 'duplicate_alice@example.com');

    EXCEPTION
        WHEN unique_violation THEN
            RAISE NOTICE 'Caught a unique constraint violation! Skipping this user.';
    END;

    -- This insert succeeds because the main transaction was not aborted
    INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com');

END;
$$;
```

When the `insert_users` procedure is called, the constraint violation is caught properly and only this modification is rolled back while all other modifications are applied.

```sql
postgres=> CALL insert_users();
NOTICE:  Caught a unique constraint violation! Skipping this user.
CALL

postgres=> SELECT * from users;
 user_id | username |       email
---------+----------+-------------------
 | alice    | alice@example.com
 | bob      | bob@example.com
(2 rows)
```

Note

`user_id` 2 is missing because it was consumed by the rolled-back subtransaction. Sequences in PostgreSQL operate outside of the regular transaction guarantees and do not roll back.

Since exception handling uses subtransactions automatically, many workloads rely on subtransactions without using them explicitly.

## Command IDs

XIDs tell you which *transaction* wrote a row. They cannot tell you which *statement* inside that transaction wrote it. If you run `UPDATE` on a set of rows, the statement could potentially rewrite a row, scan ahead, encounter that same rewritten row, and update it again. Without a finer-grained marker, the statement would chase its own tail forever. Database people call this the *Halloween problem*, named for the day it was discovered.

To solve this, PostgreSQL uses an incrementing Command ID inside each transaction, starting at 0 and ticking up with every data-modifying SQL statement. When a statement creates a tuple, it stamps it with the current Command ID (shown in the system column `cmin`). This counter ensures a single running query never reads its own ongoing changes. For example:

```sql
postgres=> TRUNCATE mytable RESTART IDENTITY;
TRUNCATE TABLE

postgres=> INSERT INTO mytable (name) VALUES('First tuple');
INSERT 0 1

postgres=> BEGIN;
BEGIN

postgres=*> SELECT pg_current_xact_id();
 pg_current_xact_id
--------------------
            2995013
(1 row)

postgres=*> SELECT cmin, xmin, xmax, * FROM mytable;
 cmin |  xmin   | xmax | id |    name
------+---------+------+----+-------------
    0 | 2995012 |    0 |  1 | First tuple
(1 row)

postgres=*> UPDATE mytable SET name = 'Updated first tuple' WHERE id = 1;
UPDATE 1
postgres=*> SELECT cmin, xmin, xmax, * FROM mytable;
 cmin |  xmin   | xmax | id |        name
------+---------+------+----+---------------------
    0 | 2995013 |    0 |  1 | Updated first tuple
(1 row)

postgres=*> UPDATE mytable SET name = 'Two times updated first tuple' WHERE id = 1;
UPDATE 1
postgres=*> SELECT cmin, xmin, xmax, * FROM mytable;
 cmin |  xmin   | xmax | id |             name
------+---------+------+----+-------------------------------
    1 | 2995013 |    0 |  1 | Two times updated first tuple
(1 row)

postgres=*> COMMIT;
COMMIT
```

The transaction IDs here are larger than the earlier ones because this example was run later, after many more transactions. In the example, transaction XID `2995013` runs multiple updates on a single row in `mytable`:

- **First update:** The original row's `xmax` is set to `2995013` to mark this old tuple as deleted by the current transaction and a new tuple is created. This new tuple has an `xmin` of `2995013` and a `cmin` of `0`, signaling it was created by the transaction's first data-modifying operation.
- **Second update:** The transaction updates the same tuple again. So, the last updated tuple is deleted by setting the `xmax` value and a new tuple is created. The `xmin` of the new tuple is `2995013` as well because it belongs to the same transaction. However, its `cmin` value changes to `1`. This increment indicates that the tuple was created by the transaction's second data-modifying operation, ensuring correct statement-level visibility.

## Table maintenance

As we've seen, `UPDATE` leaves an old tuple versions behind on disk. When no running transaction needs them anymore, PostgreSQL can clean them up.

You can do this manually by running `VACUUM`, and PostgreSQL performs autovacuum from time to time. When cleanup falls behind, tables and indexes get bloated (using more disk) and sequential scans slow down. High-churn tables like job queues are especially vulnerable. See [Keeping a Postgres queue healthy](https://planetscale.com/blog/keeping-a-postgres-queue-healthy) for what that looks like.

To schedule autovacuum, PostgreSQL needs to know how many dead tuples are in a table. This is tracked in the table statistics. Run:

```sql
postgres=> SELECT relname, n_live_tup, n_dead_tup
           FROM pg_stat_user_tables
           WHERE relname = 'mytable';
 relname | n_live_tup | n_dead_tup
---------+------------+------------
 mytable |          1 |          2
(1 row)
```

After two updates on one row, one live tuple remains and two dead versions sit in the statistics.

Note

`n_live_tup` and `n_dead_tup` are [estimates](https://www.postgresql.org/docs/18/monitoring-stats.html#MONITORING-PG-STAT-ALL-TABLES-VIEW), not exact counts. PostgreSQL updates them asynchronously, so a query run immediately after the updates may briefly show zeros until the cumulative statistics system catches up.

`VACUUM` removes dead tuples and marks their space as reusable within the table. Dead tuples are row versions that no active transaction or snapshot still needs.

## Page layout

PostgreSQL tables use fixed 8-kilobyte (8192 bytes) pages. Multiple tuples are stored inside each page using a specific layout:

- **Line Pointers (`lp`):** These are placed at fixed array positions starting from the beginning of the page and growing *downward*.
- **Tuple Data:** The actual row data is placed at the very end of the page and grows *upward*.
- **The Offset (`lp_off`):** Each line pointer contains a byte offset pointing directly to the exact physical byte position where its corresponding tuple data begins.

![An 8 KB heap page](https://planetscale-images.imgix.net/assets/diagram-page-layout-Do5-bp-i.svg?auto=compress%2Cformat)

## Examining the page

The `pageinspect` extension lets us inspect the details of a Postgres page. Its functions require superuser privileges, so the following runs in a superuser session (note the `#` prompt instead of `>`). `get_raw_page` plus `heap_page_items` returns line pointers, byte offsets, flags, and each tuple's `xmin` / `xmax`. Below we decode page 0 of `mytable`. Flag `1` means the line pointer is in use (`LP_NORMAL`).

```sql
postgres=# CREATE EXTENSION pageinspect;
CREATE EXTENSION

postgres=# SELECT lp, lp_off, lp_flags, t_xmin, t_xmax FROM heap_page_items(get_raw_page('mytable', 0));
 lp | lp_off | lp_flags | t_xmin  | t_xmax
----+--------+----------+---------+---------
  1 |   8152 |        1 | 2995012 | 2995013
  2 |   8104 |        1 | 2995013 | 2995013
  3 |   8040 |        1 | 2995013 |       0
(3 rows)
```

The first page of the table holds three tuples, and the `xmin` and `xmax` values match the tuple versions we produced in the update from earlier.

## Standard VACUUM

To reclaim the space, run `VACUUM`.

```sql
postgres=# VACUUM mytable;
VACUUM

postgres=# SELECT lp, lp_off, lp_flags, t_xmin, t_xmax FROM heap_page_items(get_raw_page('mytable', 0));
 lp | lp_off | lp_flags | t_xmin  | t_xmax
----+--------+----------+---------+--------
  1 |      3 |        2 |         |
  2 |      0 |        0 |         |
  3 |   8128 |        1 | 2995013 |      0
(3 rows)
```

![Before and after a standard VACUUM](https://planetscale-images.imgix.net/assets/diagram-page-vacuum-before-after-BjbvKWzL.svg?auto=compress%2Cformat)

After VACUUM is done, the two dead tuples are removed. Three things changed in the page structure:

- **LP 3 (Live Tuple):** The byte offset changed from `8040` to `8128`. Because the data for the two dead rows was wiped out, `VACUUM` defragmented the page by shifting the remaining live data down to the bottom boundary.
- **LP 2 (Unused Pointer):** The `lp_flags` value changes to 0 (`LP_UNUSED`), indicating that this line pointer is currently unused.
- **LP 1 (Redirect Pointer):** The first tuple version was also cleaned up, but something different happened here than for LP 2. The `lp_flags` value is set to 2 (`LP_REDIRECT`) and the offset points to line pointer 3. The updates in the previous section formed a *HOT (Heap-Only Tuple)* chain because they stayed on the same page and did not change indexed columns. After `VACUUM` pruned the dead versions, LP 1 became an `LP_REDIRECT` to LP 3 so the index on `id` still reaches the live tuple without being rewritten.

## VACUUM FULL

`VACUUM FULL` is for rebuilding tables and indexes completely. `VACUUM FULL` packs the data sequentially, eliminates all pointer shortcuts, and shrinks the file size. This is a resource-intensive operation that puts an `ACCESS EXCLUSIVE` lock on the table.

```sql
postgres=# VACUUM FULL mytable;
VACUUM
postgres=# SELECT lp, lp_off, lp_flags, t_xmin, t_xmax FROM heap_page_items(get_raw_page('mytable', 0));
 lp | lp_off | lp_flags | t_xmin  | t_xmax
----+--------+----------+---------+--------
  1 |   8128 |        1 | 2995013 |      0
(1 row)
```

After `VACUUM FULL` is done, the only stored tuple sits directly under line pointer 1.

## The transaction horizon

The cleanup above worked because no other session needed the dead tuples. In practice, that is not always true.

PostgreSQL tracks the oldest transaction that might still need an old row version. That cutoff is the **transaction horizon**. VACUUM can only remove tuples that became dead before the horizon.

The demo below uses a throwaway `horizon_demo` table so it does not disturb the `mytable` state from the walkthrough above. Session 1 starts under `REPEATABLE READ`, reads the rows, and stays idle:

```sql
-- Session 1
postgres=> CREATE TABLE horizon_demo (id SERIAL PRIMARY KEY, name VARCHAR NOT NULL);
CREATE TABLE
postgres=> INSERT INTO horizon_demo (name) VALUES ('alpha'), ('beta'), ('gamma');
INSERT 0 3
postgres=> BEGIN ISOLATION LEVEL REPEATABLE READ;
BEGIN
postgres=*> SELECT id, name FROM horizon_demo ORDER BY id;
 id | name  
----+-------
 | alpha
 | beta
 | gamma
(3 rows)
```

Next, open a parallel connection in Session 2. Update every row, refresh the table statistics, and run `VACUUM`:

```sql
-- Session 2
postgres=> UPDATE horizon_demo SET name = name || '-updated';
UPDATE 3
postgres=> ANALYZE horizon_demo;
ANALYZE
postgres=> SELECT relname, n_live_tup, n_dead_tup
           FROM pg_stat_user_tables
           WHERE relname = 'horizon_demo';
    relname    | n_live_tup | n_dead_tup 
---------------+------------+------------
 horizon_demo  |          3 |          3
(1 row)

postgres=> VACUUM horizon_demo;
VACUUM
postgres=> SELECT relname, n_live_tup, n_dead_tup
           FROM pg_stat_user_tables
           WHERE relname = 'horizon_demo';
    relname    | n_live_tup | n_dead_tup 
---------------+------------+------------
 horizon_demo  |          3 |          3
(1 row)
```

`VACUUM` ran, but `n_dead_tup` did not drop. Session 1's open snapshot still needs the pre-update row versions.

If we return to Session 1 and commit:

```sql
-- Session 1
postgres=*> COMMIT;
COMMIT
```

Session 2 can finish cleanup:

```sql
-- Session 2
postgres=> VACUUM ANALYZE horizon_demo;
VACUUM
postgres=> SELECT relname, n_live_tup, n_dead_tup
           FROM pg_stat_user_tables
           WHERE relname = 'horizon_demo';
    relname    | n_live_tup | n_dead_tup 
---------------+------------+------------
 horizon_demo  |          3 |          0
(1 row)
```

When `n_dead_tup` climbs but autovacuum looks healthy, find the session holding the horizon open.

```sql
SELECT pid, usename, backend_xid, backend_xmin,
       age(backend_xid)  AS xid_age,
       age(backend_xmin) AS xmin_age,
       xact_start,
       age(clock_timestamp(), xact_start) AS transaction_duration,
       state, query
FROM pg_stat_activity
WHERE backend_xmin IS NOT NULL OR backend_xid IS NOT NULL
ORDER BY GREATEST(age(backend_xid), age(backend_xmin)) DESC
LIMIT 5;
```

The culprit is whoever holds the oldest `backend_xmin` (a taken snapshot) or `backend_xid` (an assigned transaction ID). This is not always the transaction that has been open the longest.

## Wrapup

MVCC is why PostgreSQL can serve heavy read traffic and write traffic simultaneously. This gains us great performance in the short term, but means we now have deferred maintenance to manage (dead tuples and `vacuum`). Now you have an in-depth look at how all this works.