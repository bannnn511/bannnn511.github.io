
## Unix file system has poor performance
	- treat disk like random access memory
	- data block far away from inode
	- fragmented
	- block size small -> bad for file transfer

## Solution: disk aware (FFS - fast file system)
- FFS / disk = cylinder groups
- cylinder = set of tracks on different surface
- disk export logical address space of blocks
- FFS placing files into the same group
- FFS data structure:
	- super block: hold metadata
	- inode bitmap, data bitmap
	- inode
	- data
### Policies: How to allocate files and directories
- keep related stuff together
- 