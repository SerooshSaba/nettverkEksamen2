#include "serverutils.h"

char* appendNumber(char* baseString, int num) {
    char* newString = malloc(strlen(baseString) + sizeof(num) + 1);
    sprintf(newString, "%s%d", baseString, num);
    return newString;
}

static int prepare_server_sock(int *identifier)
{
	struct sockaddr_un addr;
	int sd = -1, rc = -1;

	sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sd	== -1) {
		perror("socket()");
		return rc;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	
	char* NEW_SOCKET_NAME = appendNumber(SOCKET_NAME, *identifier);

    // Free the memory allocated for newString
    //free(newString); <!-------------------------------------------------------------------
	
	strncpy(addr.sun_path, NEW_SOCKET_NAME, sizeof(addr.sun_path) - 1);
	unlink(NEW_SOCKET_NAME);
	
	rc = bind(sd, (const struct sockaddr *)&addr, sizeof(addr));
	if (rc == -1) {
		perror("bind");
		close(sd);
		return rc;
	}

	rc = listen(sd, MAX_CONNS);
	if (rc == -1) {
		perror("listen()");
		close(sd);
		return rc;
	}
	return sd;
}

// epoll listens to file descriptors, this function sets which file descriptor epoll should listen to
static int add_to_epoll_table(int efd, struct epoll_event *ev, int fd)
{
	int rc = 0;
	ev->events = EPOLLIN;
	ev->data.fd = fd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, ev) == -1) {
		perror("epoll_ctl");
		rc = -1;
	}
	return rc;
}



