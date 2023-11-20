#include <time.h>
#include "serverutils.h"

#define MAX_EVENTS 10
#define BUF_SIZE 1450
#define DST_MAC_ADDR {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
#define STDIN_FD 0

struct sockaddr_ll MAC_ADDRESS;
int MIP_ADDRESS = 0;
uint8_t MAC_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint16_t ROUTER_PROTOCOL = 0x99B5; // Give the protocol a arbitrary value so that the routers only listen to router packets

/**** ROUTING ****/

// Variables to hold control over request and response state
int RESPONSES = 0;
int WAITING_FOR_ROUTE_RESPONSE_MESSAGE = 0;

/**
* Checks if two mac addresses are the same
* mac_addr1: First mac address used for comparison
* mac_addr2: Second mac address used for comparison
*
* Returns 0 If they are the same
*/
int compare_mac_addresses( uint8_t *mac_addr1, uint8_t *mac_addr2 ) {
	return memcmp(mac_addr1, mac_addr2, 6);
}

/**
* Gets the mac address of the host and sets the input parameters value to it
* so_name: Variable that contains struct that contains relevant information.
*
* Returns nothing
*/
void get_mac_from_interface(struct sockaddr_ll *so_name) {
	struct ifaddrs *ifaces, *ifp;
	if (getifaddrs(&ifaces)) {
		perror("getifaddrs");
		exit(-1);
	}
	for (ifp = ifaces; ifp != NULL; ifp = ifp->ifa_next) {
		/* We make certain that the ifa_addr member is actually set: */
		if (ifp->ifa_addr != NULL &&
		    ifp->ifa_addr->sa_family == AF_PACKET &&
		    (strcmp("lo", ifp->ifa_name)))
		        memcpy(so_name,
		           (struct sockaddr_ll*)ifp->ifa_addr,
		           sizeof(struct sockaddr_ll));
	}
	freeifaddrs(ifaces);
	return;
}

/***** ROUTING TABLE *****/

struct host {
	int mip;
	uint8_t mac[6];
};

struct host routing_table[255];

int table_iterator = 0;
 
/**
* Checks if a mac address exits in the routing table
* mac_addr: The mac address that is checked for
*
* Returns 1 if the mac address exists in the table
*/
int macInTable(uint8_t mac_addr[6]) {
	int found = 0;
	for ( int i = 0; i < 5; i++ ) {
		if ( compare_mac_addresses( routing_table[i].mac, mac_addr ) == 0 ) {
			found = 1;
			break;
		}
	}
	return found;
}

/**
* Checks if a mip address exits in the routing table
* mipaddr: The mip address that is checked for
*
* Returns 1 if the mip address exists in the table
*/
int mipInTable(int mipaddr) {
	int found = 0;
	for ( int i = 0; i < 5; i++ ) {
		if ( routing_table[i].mip == mipaddr ) {
			found = 1;
			break;
		}
	}
	return found;
}

/**
* Adds a mip and mac address pair to the routing table
* mipaddr: mip address to add
* mac_addr: mac address to add
*
* Returns void
*/
void addToTable( int mipaddr, uint8_t mac_addr[6] ) {
    memcpy(routing_table[table_iterator].mac, mac_addr, 6);
    routing_table[table_iterator].mip = mipaddr;
	table_iterator++;
}

/**
* Prints the contents of the routing table
*
* Returns void
*/
void printRoutingTable() {
	printf("*** Routing Table ***\n");
	for ( int i = 0; i < table_iterator; i++ ) {
		for (int j = 0; j < 6; j++) {
			printf("%02X ", routing_table[i].mac[j]);
		}
		printf(" ");
		printf(" %d", routing_table[i].mip);
		printf("\n");
	}
	printf("\n\n");
}

/**
* Structure to hold a hello messages
*/
struct hello_message {
	uint8_t macaddr[6];
	uint8_t mipaddr;
	uint8_t ttl;
};

/**
* Structure to hold a request messages
*/
struct request_message {
	uint8_t hostaddr[6];
	uint8_t ttl;
	uint8_t r;
	uint8_t e;
	uint8_t q;
	uint8_t lookupaddr;
};

/**
* Structure to hold a response messages
*/
struct response_message {
	uint8_t hostaddr[6];
	uint8_t ttl;
	uint8_t r;
	uint8_t s;
	uint8_t p;
	uint8_t nexthopaddr;
};

/**
* Creates a fully populated hello_message structure
* host_addr: The mac address of the host that is sending the request message
*
* Returns a hello message struct instance
*/
struct hello_message createHelloMessage(uint8_t host_addr[6]) {
	struct hello_message instance;
	memcpy(instance.macaddr, host_addr, 6);
	instance.mipaddr = MIP_ADDRESS;
	instance.ttl = 1;
	return instance;
};

/**
* Creates a fully populated request_message structure
* host_addr: The mac address of the host that is sending the request message
* lookup_addr: The mac address that is being searched for
*
* Returns a request message structure
*/
struct request_message createRequestMessage(uint8_t host_addr[6], uint8_t lookup_addr) {
	struct request_message instance;
	memcpy(instance.hostaddr, host_addr, 6);
	instance.ttl = 1;
	instance.r = 0x52;
	instance.e = 0x45;
	instance.q = 0x51;
	instance.lookupaddr = lookup_addr;
	return instance;
}

/**
* Creates a fully populated response_message structure
* host_addr: The mac address of the host that is sending the response message
* next_hop_addr: The mac address that is the answer to the request, aka the next hop address
*
* Returns a response message structure
*/
struct response_message createResponseMessage(uint8_t host_addr[6], uint8_t next_hop_addr) {
	struct response_message instance;
	memcpy(instance.hostaddr, host_addr, 6);
	instance.ttl = 1;
	instance.r = 0x52;
	instance.s = 0x53;
	instance.p = 0x50;
	instance.nexthopaddr = next_hop_addr;
	return instance;
}

/**
* Creates an empty response_message structure
*
* Returns an empty response_massage structure
*/
struct hello_message createEmptyHelloMessage() {
    struct hello_message msg;
    memset(&msg, 0, sizeof(struct hello_message));
    return msg;
}

/**
* Creates an empty request_message structure
*
* Returns an empty request_massage structure
*/
struct request_message createEmptyRequestMessage() {
    struct request_message msg;
    memset(&msg, 0, sizeof(struct request_message));
    return msg;
}

/**
* Creates an empty response_message structure
*
* Returns an empty response_message structure
*/
struct response_message createEmptyResponseMessage() {
    struct response_message msg;
    memset(&msg, 0, sizeof(struct response_message));
    return msg;
}

// This structure is the pdu that is stored in the ethernet frame
struct routerpdu {
	struct hello_message hello;
	struct request_message request;
	struct response_message response;
};

//************************************************************************************************************************************

// struct representing our ethernet frame
struct ether_frame {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t routing_proto;
	struct routerpdu pdu;
} __attribute__((packed));

/**
* Checks if a hello_message struct has fields that are set / populated
* hello: The hello_message struct that is checked
*
* Returns a boolean value representing if it is set or not
*/
bool helloIsSet(const struct hello_message hello) {
    if (hello.ttl != 0) {
        return true;
    }
    if (hello.mipaddr != 0) {
    	return true;
    }
    return false;
}

/**
* Checks if a request_message struct has fields that are set / populated
* request: The request_message struct that is checked
*
* Returns a boolean value representing if it is set or not
*/
bool requestIsSet(const struct request_message request) {
    if (request.ttl != 0 || request.r != 0 || request.e != 0 || request.q != 0) {
        return true;
    }
    if (request.lookupaddr != 0)
        return true;
    return false;
}

/**
* Checks if a response_message struct has fields that are set / populated
* response: The response_message struct that is checked
*
* Returns a boolean value representing if response is set or not
*/
bool responseIsSet(const struct response_message response) {
    if (response.ttl != 0 || response.r != 0 || response.s != 0 || response.p != 0) {
        return true;
    }
    for (int i = 0; i < 6; i++) {
        if (response.nexthopaddr != 0)
            return true;
    }

    return false;
}

/**
* Checks if an ethernet frame has a broadcast destination mac address
* incoming_frame: The ethernet frame that is being checked
*
* Returns an integer that represents if the ethernet frame is a broadcast or not
*/
int is_broadcast( struct ether_frame incoming_frame ) {
	/* 	If ethernet dst mac address is broadcast */ 
	if ( compare_mac_addresses( incoming_frame.dst_addr, MAC_BROADCAST_ADDR ) == 0 ) {
		return 1;
	}
	return 0;
}

/**
* Checks if an ethernet frame is meant to be sendt to the current host
* incoming_frame: The ethernet frame that is being checked
*
* Returns an integer that represents if the ethernet frame is destined for current host or not
*/
int request_is_for_host( struct ether_frame incoming_frame ) {
	if ( compare_mac_addresses( incoming_frame.dst_addr, MAC_ADDRESS.sll_addr ) == 0) {
		return 1; 
	}
	return 0;
}

/**
* Checks if an ethernet frame contains a mip pdu that is of type mip-arp, and if it is a response to a corresponding request the current host did
* incoming_frame: The ethernet frame to check
*
* Returns 1 if the ethernet frame is a mip-arp response to the current host
*/
int response_is_for_curr_host( struct ether_frame incoming_frame ) {
	if ( 	compare_mac_addresses( incoming_frame.dst_addr, MAC_ADDRESS.sll_addr ) == 0 )
			// && incoming_frame.pdu.sdu.type == 0x04 ) 
	{
		return 1;
	}
	return 0;
}

/**
* Creates an ethernet frame that contains a hello message pdu
* so_name: socket structure
* mac_dst_addr: the mac destination address where the packet is being sent to
*
* Returns an ethernet frame
*/
struct ether_frame* create_hello_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6]) {

    struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
    
	struct hello_message hello = createHelloMessage(mac_dst_addr);
	struct request_message request = createEmptyRequestMessage();
	struct response_message response = createEmptyResponseMessage();
	
	struct routerpdu pdu;
	pdu.hello = hello;
	pdu.request = request;
	pdu.response = response;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, mac_dst_addr, 6);
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->routing_proto = htons(ROUTER_PROTOCOL);
    
    ethernet_frame->pdu = pdu;
    return ethernet_frame;
}

/**
* Creates an ethernet frame that contains a request message pdu
* so_name: socket structure
* mac_dst_addr: the mac destination address where the packet is being sent to
* mipaddr: the mip address that is being requested
*
* Returns an ethernet frame
*/
struct ether_frame* create_request_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6], uint8_t mipaddr ) {
	
	struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
	
	struct hello_message hello = createEmptyHelloMessage();
	struct request_message request = createRequestMessage(mac_dst_addr, mipaddr);
	struct response_message response = createEmptyResponseMessage();
	
	struct routerpdu pdu;
	
	pdu.hello = hello;
	pdu.request = request;
	pdu.response = response;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, mac_dst_addr, 6);
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->routing_proto = htons(ROUTER_PROTOCOL);
    
    ethernet_frame->pdu = pdu;
    return ethernet_frame;
}

/**
* Creates an ethernet frame that contains a response message pdu
* so_name: socket structure
* mac_dst_addr: the mac destination address where the packet is being sent to
* mipaddr: the mip address that is representing the answear to a request
*
* Returns an ethernet frame
*/
struct ether_frame* create_response_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6], uint8_t mipaddr ) {
	
	struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
	
	struct hello_message hello = createEmptyHelloMessage();
	struct request_message request = createEmptyRequestMessage();
	struct response_message response = createResponseMessage( mac_dst_addr, mipaddr );
	
	struct routerpdu pdu;
	pdu.hello = hello;
	pdu.request = request;
	pdu.response = response;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, mac_dst_addr, 6);
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->routing_proto = htons(ROUTER_PROTOCOL);
    
    ethernet_frame->pdu = pdu;
    return ethernet_frame;
}

/********************* Sending & recieving packets *********************/

/**
* Sends a ethernet to a predetermined destination
* raw_socket_descriptor: integer representing the position of the raw socket in the file descriptor of program
* so_name: socket structure for the program
* ethernet_frame: the ethernet frame that is going to be sent
*
* Returns a code representing if the packet being sent was successful
*/
int send_raw_packet(int raw_socket_descriptor, struct sockaddr_ll *so_name, struct ether_frame* ethernet_frame) {
    struct msghdr *msg;
    struct iovec msgvec[1];
    
    msgvec[0].iov_base = ethernet_frame;
    msgvec[0].iov_len  = sizeof(struct ether_frame);
    
    msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));
    msg->msg_name    = so_name;
    msg->msg_namelen = sizeof(struct sockaddr_ll);
    msg->msg_iovlen  = 1;
    msg->msg_iov     = msgvec;
     
    int return_code = sendmsg(raw_socket_descriptor, msg, 0);
    if (return_code == -1) {
        perror("sendmsg");
        free(msg);
        return 1;
    }
    
    free(msg);
    return return_code;
}

/**
* Once the epoll register that a packet has been recieved, this function returns it
* sd: the index of the socket in the socket descriptor
*
* Returns a code representing if the packet being sent was successful
*/
struct ether_frame recv_raw_packet(int sd)
{
        struct sockaddr_ll so_name;
        int                return_code;

        struct ether_frame ethernet_frame;
        struct msghdr      msg;
        struct iovec       msgvec[1];

        /* Point to frame header */
        msgvec[0].iov_base = &ethernet_frame;
        msgvec[0].iov_len  = sizeof(struct ether_frame);

        /* Fill out message metadata struct */
        msg.msg_name    = &so_name;
        msg.msg_namelen = sizeof(struct sockaddr_ll);
        msg.msg_iovlen  = 1;
        msg.msg_iov     = msgvec;

        return_code = recvmsg(sd, &msg, 0);
        if (return_code == -1) {
        	perror("sendmsg");
        }

	return ethernet_frame;
}

/**
* This is the function that runs the loop/epoll eventloop
* identifier: a number representing the mip address of this host
*
* Returns void
*/
void server(int *identifier)
{
	
	MIP_ADDRESS = *identifier;
	
	/* Raw socket variables */
	int     	raw_sock;
	uint8_t 	buf[BUF_SIZE];
	//int epollfd;
	struct  sockaddr_ll so_name;
	//struct epoll_event ev, events[MAX_EVENTS];
	short unsigned int protocol = ROUTER_PROTOCOL;

	// Set up a raw AF_PACKET socket without ethertype filtering
	raw_sock = socket(AF_PACKET, SOCK_RAW, htons(protocol));
	if (raw_sock == -1) {
		perror("socket");
	}

	/* Fill the fields of so_name with info from interface */
	get_mac_from_interface(&so_name);
	get_mac_from_interface(&MAC_ADDRESS);
	
	/* Domain socket variables */
	struct epoll_event ev, events[MAX_EVENTS];
	int domain_socket_descriptor;
	int accept_sd;
	int epollfd;
	int rc;

	/********************************************/

	// Create the main epoll file descriptor for RAW and DOMAIN SOCKET
	epollfd = epoll_create1(0);
	
	/* RAW */
	
	// Add epoll file descriptor
	ev.events = EPOLLIN;
	ev.data.fd = raw_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
		perror("epoll_ctl: raw_sock");
		exit(EXIT_FAILURE);
	}

	printf("*** Router #%d is running ***\n\n", MIP_ADDRESS);

    // Add stdin to epoll
    struct epoll_event stdin_event;
    stdin_event.events = EPOLLIN;
    stdin_event.data.fd = STDIN_FD;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FD, &stdin_event);

	/**************************************************************************/
	
	// Start router by sending a hello message to all reachable hosts
	struct ether_frame* router_req_packet = create_hello_message( &so_name, MAC_BROADCAST_ADDR );
	send_raw_packet(raw_sock, &so_name, router_req_packet);
	free(router_req_packet);
	
	// Program loop
	while (1) {
	
		memset(buf, 0, BUF_SIZE);
		rc = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		
		if (rc == -1) {
			perror("epoll_wait");
			close(domain_socket_descriptor);
			exit(EXIT_FAILURE);
		} else {
			
			// RAW SOCKET EVENT
			if (events->data.fd == raw_sock) {
				
				// Return the raw packet
				struct ether_frame incoming_frame = recv_raw_packet(raw_sock);
				
				// If recieved a hello message
				if ( helloIsSet(incoming_frame.pdu.hello) && is_broadcast(incoming_frame) ) {
				
					// If the host is not in routing table
					if ( macInTable( incoming_frame.src_addr ) == 0 ) {
					
						printf("Recieved hello message from unknown host.\n");
						printf("Adding to routing table...\n");
						addToTable( incoming_frame.pdu.hello.mipaddr, incoming_frame.src_addr ); // Add to routing table
						printRoutingTable();
						// Broadcast a hello message back
						struct ether_frame* router_req_packet = create_hello_message( &so_name, MAC_BROADCAST_ADDR );
						send_raw_packet(raw_sock, &so_name, router_req_packet);
						free(router_req_packet);
					}
				}
				
				
				// If recieved a packet for this spesific host
				else if (request_is_for_host(incoming_frame)) {
					
					// If packet is a request
					if ( requestIsSet(incoming_frame.pdu.request) ) {
						printf("Recieved a request.\n");
						
						// If the mip address is not in the routing table
						if ( mipInTable( incoming_frame.pdu.request.lookupaddr ) == 0 ) {
							
							printf("Route %d is not in table.\n", incoming_frame.pdu.request.lookupaddr);
							
							// Send a no route response
							struct ether_frame* router_response_packet = create_response_message( &so_name, incoming_frame.src_addr, 255 );
							send_raw_packet(raw_sock, &so_name, router_response_packet);
							free(router_req_packet);
							
						
						// If the mip address is in table
						} else {
												
							printf("Route is in table.\n");
							printf("Sending back a response.\n");
							
							// Send a response
							struct ether_frame* router_req_packet = create_response_message( &so_name, incoming_frame.src_addr, MIP_ADDRESS );
							send_raw_packet(raw_sock, &so_name, router_req_packet);
							free(router_req_packet);
						}
						
						
					}
				
					// Packet is a response
					else if ( responseIsSet(incoming_frame.pdu.response) ) {
					
						printf("Recieved a response.\n");
						
						if ( incoming_frame.pdu.response.nexthopaddr == 255 ) {
							printf("No route\n");
						} else {
							printf("Recieved a route! \n");
						}
						
						// Return message to MIP daemon
						// Could not implement this ;(
					}
					
					
				}
			}
			
			// STDIN EVENT
			else if (events->data.fd == STDIN_FD) {
			
				char input[100];
				fgets(input, sizeof(input), stdin);
				int mip_address = atoi(input);
				
				if ( mipInTable(mip_address) == 0 ) {
					printf("MIP address %d is not in routing table, sending requests.\n", mip_address);
					
					// Sending requests to all routers in the routing table
					RESPONSES = 0;
					WAITING_FOR_ROUTE_RESPONSE_MESSAGE = 1;
					
					for ( int i = 0; i < table_iterator; i++ ) {
						struct ether_frame* router_req_packet = create_request_message( &so_name, routing_table[i].mac, mip_address );
						send_raw_packet(raw_sock, &so_name, router_req_packet);
						free(router_req_packet);
					}
					
				} else {
					printf("MIP address %d is in routing table.\n", mip_address);
				}
				
            }
		}
	}
	
	close(domain_socket_descriptor);
	unlink(SOCKET_NAME);
	exit(EXIT_SUCCESS);
}


int main (int argc, char *argv[])
{
	int opt, num = 0;
	
    if (argc != 2) {
        printf("Usage: %s <integer>\n", argv[0]);
        return 1;
    }
    
    num = atoi(argv[1]);
	
	server(&num);
	
	return 0;
}
