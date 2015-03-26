#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <netdb.h>

// Starting Portable Multi-threading code
// but but but but but but but but
typedef struct mctx_st {
    jmp_buf jb;
} mctx_t;

/*
save machine context
*/
#define mctx_save(mctx) setjmp((mctx)->jb)
/*
restore machine context
*/
#define mctx_restore(mctx) longjmp((mctx)->jb, 1)
/*
switch machine context
*/
#define mctx_switch(mctx_old,mctx_new)\
    if (setjmp((mctx_old)->jb) == 0) \
        longjmp((mctx_new)->jb, 1)

void mctx_create_trampoline(int sig);
void mctx_create_boot(void);

static mctx_t mctx_caller;
static sig_atomic_t mctx_called;
static mctx_t *mctx_creat;
static void (*mctx_creat_func)(int);
static int mctx_creat_arg;
static sigset_t mctx_creat_sigs;

void mctx_create(mctx_t *mctx, void (*sf_addr)(int), int sf_arg, void *sk_addr, size_t sk_size){
    struct sigaction sa;
    struct sigaction osa;
    struct sigaltstack ss;
    struct sigaltstack oss;
    sigset_t osigs;
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGUSR1);
    sigprocmask(SIG_BLOCK, &sigs, &osigs);

    memset((void *)&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = mctx_create_trampoline;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, &osa);

    ss.ss_sp = sk_addr;
    ss.ss_size = sk_size;
    ss.ss_flags = 0;
    sigaltstack(&ss, &oss);

    mctx_creat = mctx;
    mctx_creat_func = sf_addr;
    mctx_creat_arg = sf_arg;
    mctx_creat_sigs = osigs;
    mctx_called = 0;
    kill(getpid(), SIGUSR1);
    sigfillset(&sigs);
    sigdelset(&sigs, SIGUSR1);
    while (!mctx_called)
        sigsuspend(&sigs);

    sigaltstack(NULL, &ss);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    if (!(oss.ss_flags & SS_DISABLE))
        sigaltstack(&oss, NULL);
    sigaction(SIGUSR1, &osa, NULL);
    sigprocmask(SIG_SETMASK, &osigs, NULL);

    mctx_switch(&mctx_caller, mctx);

    return;
}

void mctx_create_trampoline(int sig){

    if (mctx_save(mctx_creat) == 0){
        mctx_called = 1;
        return;
    }
    mctx_create_boot();
}

void mctx_create_boot(void){
    void (*mctx_start_func)(int);
    int mctx_start_arg;

    sigprocmask(SIG_SETMASK, &mctx_creat_sigs, NULL);

    mctx_start_func = mctx_creat_func;
    mctx_start_arg = mctx_creat_arg;

    mctx_switch(mctx_creat, &mctx_caller);

    mctx_start_func(mctx_start_arg);

    abort();
}

// end of code from Portable Multi-threading code

#define mythr_swap(i1, i2) mctx_switch(&(contexts[i1]), &(contexts[i2]))

mctx_t contexts[2];
char *args[] = {"my-histogram", "webserv.c" /*the file to read*/,/*the expressions to check*/ "and", "so", "but", "he.*lo", NULL};
int tflag = 0;
int cflag = 0;

struct cachentry{ // an entry in the cache
    unsigned int inode;
    time_t t;
    size_t s;
    char *file;
};

struct bintree { // a node in the binary tree
    struct bintree *left;
    struct bintree *right;
    struct cachentry c;
};

typedef struct bintree bintree;
typedef struct chachentry cachentry;
bintree *root = NULL; // root of the cache tree
size_t treesize = 0; // maximum size of the cache tree
size_t treemax = 0; // current size of the cache tree
int r = 0; // whether the right or left node should be moved up in the cache

struct proxyinode{ // a proxy inode linked list entry
	unsigned int inode;
	char *path;
	struct proxyinode *next;
};

typedef struct proxyinode prox;

prox *list = NULL; // pointer to the beginning of the linked list

unsigned int proxcreate(char *path){ // creates an entry in the linked list with the inode generated randomly
	unsigned int r = rand();
	prox *p = (prox *) malloc(sizeof(prox));
	p->inode = r;
	p->path = path;
	p->next = list;
	list = p;
	return r;
}

unsigned int listhelper(char *path, prox *p){ // searches for the proxy file in the list
	if (p == NULL) // returns 0 if not found
		return 0;
	if (!strcmp(path, p->path))
		return p->inode;
	return listhelper(path, p->next);
}

unsigned int creathelper(char *path, prox *p){ // a helper function to create an inode if it is not found or return it if it is found
	if (p == NULL)
		return proxcreate(path);
	if (!strcmp(path, p->path))
		return p->inode;
	return listhelper(path, p->next);
}

unsigned int listlookup(char *path){ // looks for the proxy file, returning its inode if it exists, 0 if it does not
	if (path == NULL || list == NULL)
		return 0;
	return listhelper(path, list);
}

unsigned int listlookcreat(char *path){ // looks for the proxy file, creating an inode for it if it does not currently exist
	if (path == NULL)
		return 0;
	if (list == NULL)
		return proxcreate(path);
	return creathelper(path, list);
}

prox *remhelper(unsigned int i, prox *p){ // helper to remove a proxy entry with the given inode i
	if (p == NULL)
		return NULL;
	if (p->inode == i){
		prox *n = p->next;
		free(p);
		return n;
	}
	p->next = remhelper(i, p);
	return p;
}

void listremove(unsigned int i){ // removes a proxy entry with inode i
	list = remhelper(i, list);
}

int cache_size_helper(bintree *b){ // calculates the total number of bytes in the cache, storing it in treesize
    if (b == NULL)
        return 0;
    treesize += b->c.s;
    cache_size_helper(b->left);
    cache_size_helper(b->right);
    return 1;
}

int cache_size(){
    treesize = 0;
    cache_size_helper(root);
    return 1;
}

int cache_send(char *path, int cfd){ // sends a file from the cache to the client
	int i; // returns 1 if the file was found and sent, 0 otherwise
	time_t m;
    if (root == NULL)
        return 0;
	if (access(path, F_OK) == -1){ // if file doesn't exist, look for the inode in the proxy linked list
		i = listlookup(path);
		m = 0;
		if (!i) // if inode is 0, exit
			return 0;
	} else { // if it is an actual file, retrieves its inode from file system
		struct stat s;
		stat(path, &s);
		i = s.st_ino;
		m = s.st_mtime;
	}
    bintree *ptr = root;
    while(1){ // finds the inode in the cache binary tree
        if (ptr == NULL)
            return 0;
        if (ptr->c.inode == i){

            if (m == ptr->c.t){
                write(cfd, ptr->c.file, ptr->c.s); // sends the file
                return 1;
            } else {
                return 0;
            }
        } else if (i > ptr->c.inode)
            ptr = ptr->right;
        else
            ptr = ptr->left;
    }
}

int cache_insert(bintree *b){ // inserts a node into the binary tree
    if (root == NULL){
        root = b;
    } else {
        unsigned int i = b->c.inode;
        bintree *ptr = root;
        while (1){
            if (i > ptr->c.inode){
                if (ptr->right == NULL){
                    ptr-> right = b;
                    break;
                } else
                    ptr = ptr->right;
            }else if (i == ptr->c.inode){ // if the inode already has an entry, update its file entry with the current entry
                listremove(i); // removes any proxies that may have this inode
                free(ptr->c.file);
                ptr->c = b->c;
                free(b);
                break;
            } else{
                if (ptr->left == NULL){
                    ptr->left = b;
                    break;
                } else
                    ptr = ptr->left;
            }
        }
    }
    return 1;
}

int cache_remove(){ // removes the root of the binary tree
    if (root == NULL) // if there's nothing in the tree, nothing can be removed
        return 0;
    bintree *ptr = root;
    bintree *left = root->left;
    bintree *right = root->right;
    size_t s = ptr->c.s;
    if (left == NULL)
        root = right;
    else if (right == NULL)
        root = left;
    else {
        if (r){ // if it is time for right, the right side of the tree is moved to the root
            root = right;
            bintree *nleft = root->left;
            root->left = left;
            if (nleft != NULL)
                cache_insert(nleft);
            r = 0;
        } else { // otherwise the left side is moved to the root
            root = left;
            bintree *nright = root->right;
            root->right = right;
            if (nright != NULL)
                cache_insert(nright);
            r = 1;
        }
    }
	listremove(ptr->c.inode); // removes any proxies that may have had that inode
    free(ptr->c.file); // frees the memory
    free(ptr);
    cache_size(); // calculates the size of the cache
    return 1;
}

int lockfile(int fd, short int l_type, int l){ // locks a file with the give specifications
    struct flock lock;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = l_type;
    lock.l_whence = 0;
    errno = 0;
    fcntl(fd, l, &lock);
    if (errno) // returns 1 if successful, 0 otherwise
        return 0;
    return 1;
}

int cache_create(int fd){ // creates an entry in the cache, from the given file descriptor
    if (!treemax){
        return 0;
    }
    struct stat s;
    fstat(fd, &s);
    if (s.st_size > treemax){ // if there are more bytes to write than the size of the tree, do not create an entry
        return 0;
    }
    size_t new_s = treesize + s.st_size;
    while (new_s > treemax){ // remove items from the cache until the cache can handle the new file
        if (!cache_remove()){
            return 0;
        }
        new_s = treesize + s.st_size;
    }

    bintree *b = (bintree *) malloc(sizeof(bintree)); // create the new node
    memset(b, 0, sizeof(bintree));
    b->c.s = s.st_size;

    b->c.file = (char *) malloc(sizeof(char) * s.st_size); // allocate space for the file
    char *loc = b->c.file;
    blksize_t blk = s.st_blksize;
    char buf[s.st_blksize];
    size_t t;
    while ((t = read(fd, buf, blk)) > 0){ // read from the cache file st_blksize bytes until the file is completely read
        memcpy(loc, buf, t);
        loc += t;
    }

	close(fd);


	int nfd = open("name.txt", O_RDONLY); // get the name of the file from the cache-name file
	lockfile(nfd, F_RDLCK, F_SETLKW);

	memset(buf, 0, s.st_blksize);
	read(nfd, buf, PATH_MAX + 1); // read in the name
	char *p = buf;
	close(nfd);

	if (access(p, F_OK) == -1){ // if the name is not a file on the host, create a proxy entry
		b->c.inode = listlookcreat(p);
		b->c.t = 0;
		if (b->c.inode == 0){
            free(b->c.file);
            free(b);
            return 0;
		}
	} else { // otherwise get its inode information
		stat(p, &s);
		b->c.inode = s.st_ino;
		b->c.t = s.st_mtime;
	}
    if(!cache_insert(b)){ // inserts the entry into the cache
        return 0;
    }
    cache_size(); // checks the cache size
    return 1;
}

void thread_handle(int clientfd){ // pre-function to facilitate thread connections without aborting
    handleconnection(clientfd);
    mythr_swap(1, 0);
}

int thr_create(int id, void (*func) (int), int arg){ // create a thread with a 4 kilobyte stack

    char *sta = alloca(sizeof(char) * 4096);
    mctx_create(&(contexts[id]), func, arg, sta, 4096);

    return 1;
}

int directsend(int fd, char *path){ // sends the directory to fd file by executing ls
    dup2(fd, 1);
    printf("HTTP/1.1 200 File Found\n", path);
    printf("Content-type: text/plain\n\n");
    execlp("ls","ls", path, NULL);
    perror("Exec Error");
}

int teesend(int clientfd, int fd, char *path){ // if caching is activated, what goes to the client is piped to tee
    dup2(clientfd, 1);
    dup2(fd, 0);
    int outfd = open("out.txt", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // opens and locks the cache file
    lockfile(outfd, F_WRLCK, F_SETLKW);

    int nfd = open("name.txt", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // opens and locks the name file for the name
    lockfile(nfd, F_WRLCK, F_SETLKW);
    write(nfd, path, strlen(path));
    close(nfd);

    execlp("tee", "tee", "-a", "out.txt", NULL); // information to be sent is piped in and sent to the client and written to the cache file
}

int checkcache(int clientfd, char *path){ // checks the cache for a file, sending it if it is in the cache
    if (cflag){
        if (cache_send(path, clientfd)){
            printf("Request handled via cache\n");
            close(clientfd);
            return 1;
        }
    }
    return 0;
}

int handleDirectory(int clientfd, char *path){ // handles a directory request
    printf("Directory request received for directory: %s\n", path);
    if (checkcache(clientfd, path)) // checks the cache
        return 1;
    pid_t id;
    if ((id = fork()) == 0){ // forks a new process so that threading will not be interrupted
        if (cflag){ // if caching, pipe the information for the client to the tee program
            int fd[2];
            if (pipe(fd)){
                perror("Pipe error\n");
                return 0;
            }
            if (fork() == 0){
                close(fd[0]);
                directsend(fd[1], path);
            } else{
                close(fd[1]);
                teesend(clientfd, fd[0], path);
            }
        } else { // otherwise, just send it to the client
            directsend(clientfd, path);
        }
    } else{ // wait for the process to finish, only affects threading
        waitpid(id);
    }
}

int senderror(int fd, char *stat, char *title, char *message){ // if there is an error with the request, sends a response
    write(fd, "HTTP/1.1", 8);
    write(fd, stat, strlen(stat));
    write(fd, "\nContent-type: text/html\n\n<html><head><title>", 45);
    write(fd, title, strlen(title));
    write(fd, "</title></head><body><h1>", 25);
    write(fd, title, strlen(title));
    write(fd, "</h1><p>", 8);
    write(fd, message, strlen(message));
    write(fd, "</p><p>Click <a href=\"/\">here</a> to return to homepage</p></body></html>\n", 75);
}

int handlecgi(char *path){ // handles a cgi request
    if (!strcmp(path, "./my-histogram.cgi")){ // special exec for my-histogram
        execv(path, args);
    } else { // normal exec for other cgi files
        execl(path, path, NULL);
    } // if it gets here, the file was unable to be accessed
    senderror(1, "403 Forbidden", "403 - Page Forbidden", "Access to the requested page is forbidden.");
    exit(0);
}

int filesend(int fd, char *path){ // sends the file to fd, checking its type and sending the appropriate header
    dup2(fd, 1);
    printf("HTTP/1.1 200 File Found\n");
    if (strstr(path, ".html") || strstr(path, ".htm"))
        printf("Content-type: text/html\n\n");
    else if (strstr(path, ".jpg") || strstr(path, ".jpeg"))
        printf("Content-type: image/jpeg\n\n");
    else if (strstr(path, ".gif"))
        printf("Content-type: image/gif\n\n");
    else if (strstr(path, ".cgi")){ // if cgi file, go to special handler
        handlecgi(path);
    } else
        printf("Content-type: text/plain\n\n", path);
    execlp("cat","cat", path, NULL); // all other files are handled via cat
    perror("Exec Error");
}

int handleFile(int clientfd, char *path){ // handles file requests
    printf("File request received for file: %s\n", path);
    if (checkcache(clientfd, path)){ // checks the cache
        return 1;
    }
    pid_t id;
    if ((id = fork()) == 0){ // forks new process (for threading)
        if (cflag){ // if cached, pipe output to tee to be sent to client and stored for the cache
            int fd[2];
            if (pipe(fd)){
                perror("Pipe error\n");
                return 0;
            }
            if (fork() == 0){
                close(fd[0]);
                filesend(fd[1], path);
            } else{
                close(fd[1]);
                teesend(clientfd, fd[0], path);
            }
        } else { // otherwise just send the file
            filesend(clientfd, path);
        }
    } else{ // wait for this process to finish (only affects threading)
        waitpid(id);
    }
}

int handleproxy(char *path, int clientfd){ // handles a proxy request
    path++;
    int i = 0;
    while (i++ < 7){
        path++;
    }
    path = strtok(path, "/"); // gets the host path
    char *port = NULL;
    char *f = NULL;
    if (strstr(path, ":")){ // retrieves the port if any
        path = strtok(path, ":");
        port = path;
        while (*port++ != 0);
        char *f = port;
    } else {
        f = path;
    }

    while(*f++ != 0);
    f = strtok(f, " ");
    char file[PATH_MAX];
    file[0] = '/';
    if (f != NULL && f != strstr(f, "HTTP"))
        strcat(file, f);

    // the above retrieves the name of the file to be requested or "/" if the default file is requested

    struct sockaddr_in serv_addr;
    struct hostent *server;

    int sfd = socket(AF_INET, SOCK_STREAM, 0); // creates a socket for the request
    if (sfd < 0){
        perror("Socket error");
        return 0;
    }

    server = gethostbyname(path); // gets the server information
    if (server == NULL) { // error if the server doesn't exist
        fprintf(stderr,"ERROR, no such host\n");
        senderror(clientfd, "404 Not Found", "404 - Host Not Found", "The Host you requested could not be found.");
        close(clientfd);
        return 0;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    int portno; // gets the right port number
    if (port == NULL)
        portno = 80;
    else
        portno = atoi(port);
    serv_addr.sin_port = htons(portno);
    if (connect(sfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) { // connects to the server for the request
        perror("ERROR connecting");
        return 0;
    }

    write(sfd, "GET ", 4); // sends the request
    write(sfd, file, strlen(file));
    write(sfd, " HTTP/1.1\nHost: ", 16);
    write(sfd, path, strlen(path));

    if (port != NULL){
        write(sfd, ":", 1);
        write(sfd, port, strlen(port));
    }
    write(sfd, "\n\n", 2);

	int outfd;

	if (cflag){ // if caching is activated, sets up the cache files

		outfd = open("out.txt", O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		lockfile(outfd, F_WRLCK, F_SETLKW);

		int nfd = open("name.txt", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		lockfile(nfd, F_WRLCK, F_SETLKW);
		write(nfd, path, strlen(path));
		write(nfd, file, strlen(file));
		close(nfd);
	}

	size_t t;

    int cache = 1;

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    fd_set readfd;

    while (t = read(sfd, file, PATH_MAX)) { // reads the response from the server
        write(clientfd, file, t);
        char *check = strstr(file, "HTTP/1.1 3"); // if the response is a 300 code, do not cache it
        if (check == file)
            cache = 0;
		if (cflag && cache)
			write(outfd, file, t);
        memset(file, 0, PATH_MAX);
        FD_ZERO(&readfd);
        FD_SET(sfd, &readfd);
        select(sfd + 1, &readfd, NULL, NULL, &tv);
        if (!FD_ISSET(sfd, &readfd)){ // if there's nothing more to be received, stop reading
            break;
        }
    }
    close(clientfd);

	if (cflag)
		close(outfd);

    if (!cache){
        int clfd = open("name.txt", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        close(clfd);
    }

    close(sfd);

    return 1;
}

int prehandleproxy(char *path, int clientfd){ // checks the cache and sets up the proxy path
    char *p = path;
    p += 8;
    if (!strrchr(p, '/')){
        strcat(path, "/");
    }
	if (checkcache(clientfd, p)){
        return 1;
    }
	handleproxy(path, clientfd);
	close(clientfd);
	return 1;
}

int checkservers(char *req, int clientfd){ // if a request doesn't exist on the server, check if it comes via proxy
	char *rest = req;
	while (*rest++ != 0);
	char *sub = strstr(rest, "Referer"); // if it is referred from a proxy file continue
	if (sub == NULL)
		return 0;
	sub = strstr(sub, "http");
	if (sub == NULL)
		return 0;
	sub += 8;
	sub = strstr(sub, "http");
	if (sub == NULL)
		return 0;
	char *p = sub;
	p += 8;
	strtok(p, "/\n");
	p = strrchr(sub, 0xd);
	if (p)
        *p = 0;
    // the above retrieves the location of the remote file

    write(clientfd, "HTTP/1.1 303 See Other\nLocation: ", 33); // sends back a response to tell the client to get the file on another server
    write(clientfd, sub, strlen(sub));
    write(clientfd, req, strlen(req));
    write(clientfd, "\n\n", 2);
    close(clientfd);

    printf("Request for file %s redirected\n", req);

	return 1;
}

int handleconnection(int clientfd){ // handles a connection
    char buf[1000];
    char *split;
    struct stat fstat;
    read(clientfd, &buf, 1000); // reads in the request from the client
    split = strtok(buf, " \n");

    if (strcmp(split, "GET")){ // if it is not a GET request, send back a 501 response
        printf("Non-implemented request received\n");
        senderror(clientfd, "501 Not Implemented", "501 - Not Implemented", "The request type has not been implemented.");
        close(clientfd);
        if (tflag)
            return;
        exit(0);
    }
    char *path = strtok(NULL, " \n");
    if (strstr(path, "/http") == path){ // if it is a proxy request, handle it as such
		printf("File sent via proxy: %s\n", path);
		prehandleproxy(path, clientfd);
		if (tflag)
			return 0;
		exit(0);
    }
    char p[PATH_MAX];
    memset(p, 0, PATH_MAX);
    p[0] = '.';
    strcat(p, path); // retrieves the specific file to be requested
    stat(p, &fstat);
    if (access(p, F_OK) == -1){ // if the file does not exist on this server
		if (checkservers(path, clientfd)){ // checks if it is requested via proxy
			if (tflag)
				return 0;
			exit(0);
		} // if not, send back a 404 File Not Found response
        printf("Requested file: %s not found\n", p);
        senderror(clientfd, "404 Not Found", "404 - Page Not Found", "The Page you requested could not be found.");

        close(clientfd);
        if (tflag)
			return 0;
        exit(0);
    }
    if (S_ISDIR(fstat.st_mode)){ // if it is a directory, handle as such
        handleDirectory(clientfd, p);
    } else if (S_ISREG(fstat.st_mode)){ // otherwise, handle the file
        handleFile(clientfd, p);
    }

}


int cache_handle(){ // gets a file into the cache

    if (access("out.txt", F_OK) == -1){ // if the cache does not exist, nothing is to be done
        return 0;
    }
    struct stat s;
    stat ("out.txt", &s);
    if (!s.st_size){ // if there's nothing in the cache file, nothing to be done
        return 0;
    }
    int cachefd = open("out.txt", O_RDWR);
    if (!lockfile(cachefd, F_WRLCK, F_SETLK)){ // if the cache file is currently being used, nothing to be done
        close(cachefd);
        return 0;
    }

    cache_create(cachefd); // otherwise load it into the cache
    int fd = open("out.txt", O_TRUNC); // then truncate it
    close(fd);
    return 1;
}

void forkaccept(int sockfd){ // accept requests via forking

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    while (1){
        fd_set readfd;
        FD_ZERO(&readfd);
        FD_SET(sockfd, &readfd);

        select(sockfd + 1, &readfd, NULL, NULL, &tv);

        if (FD_ISSET(sockfd, &readfd)){ // if there is a request from a client, handle it

            int clientfd = accept(sockfd, NULL, NULL);
            if (clientfd < 0)
                perror("ERROR on accept");
            else if (fork() == 0){
                handleconnection(clientfd);
                close(clientfd);
                exit(1);
            } else{
                close(clientfd);
                printf("Received request\n");
            }
        }
        if (cflag){ // otherwise, if caching is enabled, check and see if a file is ready to be cached
            cache_handle();
        }
    }
}

void threadaccept(int sockid){ // accept requests via threading

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    while (1){
        fd_set readfd;
        FD_ZERO(&readfd);
        FD_SET(sockid, &readfd);

        select(sockid + 1, &readfd, NULL, NULL, &tv);

        if (FD_ISSET(sockid, &readfd)){ // if there is a request from a client, handle it

            int clientfd = accept(sockid, NULL, NULL);
            if (clientfd < 0)
                perror("Error on accept");
            else{
                printf("Received request\n");
                thr_create(1, &thread_handle, clientfd);

                mythr_swap(0, 1);
                close(clientfd);
            }
        }

        if (cflag){ // otherwise, if caching is enabled, check and see if a file is ready to be cached
            cache_handle();
        }
    }

}

int main(int argc, char *argv[]){
    char c;
    int port;
    char *cache;
    while ((c = getopt(argc, argv, "tc:")) != -1){ // get the flag arguments
        if (c == 't')
            tflag = 1;
        else if (c == 'c'){
            cflag = 1;
            cache = optarg;
        } else if (c == '?'){
            if (optopt == 'c'){
                exit(0);
            }
        }
    }

    int i = optind;
    while (i < argc){ // search remaining arguments until a valid port is found
        port = atoi(argv[i++]);
        if (port < 5000 || port > 65536){
            port = 0;
            continue;
        }
        if(port)
            break;
    }
    if (!port){ // if no valid port, exit
        printf("Invalid port number (5000 - 65536)\n");
        return 0;
    }

    int sockfd;
    struct sockaddr_in serv;
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // create the socket
    if (sockfd < 0){
        perror("Socket Error");
        return 0;
    }
    bzero((char *) &serv, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv, sizeof(serv)) < 0){ // bind the socket
        perror("Binding Error");
        return 0;
    }
    listen(sockfd,10); // start the socket listening
    printf("Socket listening on port %d\n", port);
    if (cflag){ // if caching is enabled, set up the cache

        unsigned int kb = atoi(cache);
        if (kb < 4 || kb > 2048){
            printf("Invalid Cache size\n");
            exit(0);
        }
        treemax = kb * 1024;
        printf("Cache enabled with size %u kilobytes\n", kb);
    }
    if (tflag){ // if threading enabled, go to the thread handler
        printf("Threads enabled\n");
        threadaccept(sockfd);
    } else { // otherwise go to the fork handler
        forkaccept(sockfd);
    }
    close(sockfd);
    return 0;
}
