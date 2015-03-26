To run the web server in basic mode, one enters "./webserv xxxx" where "xxxx" is the port number for the socket to reside.
If the port number is invalid, a message will be printed out to inform the user of this and the program will exit.

To run the server in threaded mode, include the "-t" flag; ie "./webserv xxxx -t" a message should be printed out informing the user the threads have been enabled.

To run the server with a cache, include the "-c" flag and the number of kilobytes for the cache to be sized, valid sizes are between 4 and 2048 (2 MB)
any other input will cause the program to print out an error message and exit.
for example: "./webserv xxxx -c 2048" will cause the server to run with a cache of 2048 kilobytes or 2 megabytes.
If the cache has been enabled, a message will be displayed informing the user that the cache has been enabled, and its size.

The cache operates though a binary tree, with each entry in the cache corresponding to one in the tree, in this manner, cache replacement is a modified form
of first-in-first-out, when the cache needs to remove a file, the root of the tree is removed from the cache, and then either the right or left side of the
tree is moved up to the root, alternating each time. If a file is larger than the total cache size, nothing will be removed, the file will simply not be cached.

The server can be run in both threaded and cache modes, one just needs to run it with both the -t and the -c flags, ie "./webserv xxxx -t -c 2048"

Proxy Support:

The server supports proxy requests, in a browser the request for a proxy looks like "csa2.bu.edu:xxxx/http://request.com:reqport/file"
after csa2.bu.edu:xxxx/, "http://" is required to inform the server that the request is for a proxy, then just include the domain, port, and file
as if they were being requested from the actual source.

In http format this corresponds to 
GET /http://request.com:reqport/file HTTP/1.1

Proxy Caching:

When a proxy file is requested while caching, if the request returns a status of 303, the file will not be cached. Otherwise, the file will be cached.
Since the binary tree is sorted via the inode of the file, an inode for the proxy file is generated randomly, this is satisfactory as there is only a
1 / INT_MAX chance that there will be a collision with any given inode. The information is then stored in the binary tree under this inode, and an 
entry in a linked list is created linking the inode with the file so subsequent requests for this proxy can be handled via the cache.

When removing an proxy entry, the linked list entry for the inode is removed, disassociating the inode with the proxy file.

If a file does happen to come in with the same inode as a proxy file, the binary tree entry for that inode will be overwritten, effectively disassociating the proxy
file with the inode as the linked list entry will be removed.
