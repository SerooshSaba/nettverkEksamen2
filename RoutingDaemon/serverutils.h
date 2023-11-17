#ifndef _SERVERUTILS_H
#define _SERVERUTILS_H

#define SOCKET_NAME "server.socket"
#define MAX_CONNS 5
#define MAX_EVENTS 10

// Domain
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <ctype.h>
#include <math.h>
#include <float.h>
#include "serverutils.c"

// Raw
#include <stdint.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


static int prepare_server_sock(int *identifier);
static int add_to_epoll_table(int efd, struct epoll_event *ev, int fd);
char* appendNumber(char* baseString, int num);

#endif
