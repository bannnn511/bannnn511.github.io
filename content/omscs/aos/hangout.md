

# 22/4
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
	-  undo record vs redo log ? 
		- undo only during txn
		- redo log is persisted
	- where is undo record? -> memory, only during txn
	- updates to metadata, data structure, is it going to llvm? -> doesnt go to LRVM, go directly into memory to modify using set range
	- at the end of txn, llvm creates a redo log in memory -> flush to disk
		- LLVM synchronously flush to disk? depends (can be no flush), can be parallel (trade of for risk)
	- open a file -> inode into memory by fs -> modify inode in memory -> have to flush do disk -> use LRVM to map inode to VA -> change to VA -> create redo log (change of data structure in memory result in redo log)
		- if didnt have lrvm -> make sure inode memory = inode in disk
	- LRVM txn vs DB txn? LRVM does not support ACID
		- DB txn: multiple txn (concurrent txn) -> need isolation between processes
		- LRVM baked into file server application -> consistency for single application, does not interact with other applications that use LVRM
			- multiple processes? responsibility of developers not LRVM
			- atomicity + durability
