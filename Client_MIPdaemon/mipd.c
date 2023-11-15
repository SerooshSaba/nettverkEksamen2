#include <time.h>
#include "serverutils.h"

#define MAX_EVENTS 10
#define BUF_SIZE 1450
#define DST_MAC_ADDR {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

// global variables to save important information for later reuse
int DEBUG_MODE = 0;
uint8_t MIP_ADDRESS;
struct sockaddr_ll MAC_ADDRESS;

// control variable to know if a pong is expected
int expecting_pongs = 0;

// Often used addresses
uint8_t MAC_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint16_t MIP_PROTO = 0x88B5;

// struct representing the mapping between mip and mac addresses
struct mip_mac_mapping {
	uint8_t mip_addr;
	uint8_t mac_addr[6];
};

// struct representing our mip-arp sdu
struct MIP_ARP {
	uint8_t type; // 0x00 req - 0x01 res 
	uint8_t addr; // mip addr
	uint8_t pad[2]; 	
};

int arp_i = 0;
struct mip_mac_mapping ARP_TABLE[255];

// struct representing our mip pdu
struct MIP_PDU {
	uint8_t dst_addr;
	uint8_t src_addr;
	uint8_t ttl; // 1
	uint8_t sdu_len;
	uint8_t sdu_type;
	struct 	MIP_ARP sdu;
	char	buff[256];
};

// struct representing our ethernet frame
struct ether_frame {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_proto;
	struct MIP_PDU pdu;
} __attribute__((packed));


/******************************************* HELPER FUNCTIONS *******************************************/

/**
* Prints mac addresses
* addr: pointer to address to print
* len:  length of address
* dst:  integer that determines which type of printing to do
*
* Returns void
*/
void print_mac_addr(uint8_t *addr, size_t len, int dst ) {
	if ( dst == 1 )
		printf("dst: ");
	else if ( dst == 2 )
		printf("src: ");
		
	for (int i = 0; i < len - 1; i++) {
		printf("%02X ", addr[i]);
	}
}


/**
* Prints arp table
*
* Returns void
*/
void print_arp_table() {
	printf("_______________________ ARP TABLE _______________________\n");
	for(int i = 0; i < 255; i++) {
		// test if current mip-arp index is empty
		int empty = 1;
		for ( int j = 0; j < 6; j++ ) {
			if ( ARP_TABLE[i].mac_addr[j] != 0 )
				empty = 0;
		}
		if ( empty )
			break;
		// If not empty print arp mapping
		if ( !empty == 1 ) {
			printf( "MAC: " );
			print_mac_addr( ARP_TABLE[i].mac_addr, 6, 3 );
			printf(" <------->  MIP: %u\n", ARP_TABLE[i].mip_addr );
		}
	}
	printf("\n\n");
}


/**
* Iteratively looks up if a mip address exists in the arp table
* mip_addr: The address to look up
*
* Returns the mac address of the mip address
*/
uint8_t* search_arp_table(uint8_t mip_addr) {
    for(int i = 0; i < 255; i++) { // assuming the size of ARP_TABLE is 10
        if(ARP_TABLE[i].mip_addr == mip_addr) {
            return ARP_TABLE[i].mac_addr;
        }
    }
    return NULL;
}


/**
* Adds a mip-arp mapping to the mip-arp table
* mapping: struct that contains the mapping
*
* Returns int representing a successful append
*/
int add_to_table( struct mip_mac_mapping mapping ) {
	uint8_t* mac_address = search_arp_table( mapping.mip_addr );
	// Not found in table, add to table
	if(mac_address == NULL) {
		if ( arp_i <= 10 ) {
			ARP_TABLE[arp_i] = mapping;
			arp_i++;
			return 1;
		}
	}
	return 0;
}

/**
* Compares two mac addresses
* mac_addr1: First mac address to compare
* mac_addr2: Second mac address to compare
*
* Returns 0 if the two are the same, 1 if different
*/
int compare_mac_addresses( uint8_t *mac_addr1, uint8_t *mac_addr2 ) {
	return memcmp(mac_addr1, mac_addr2, 6);
}

/**
* Checks if an incoming ethernet frame had broadcast addresses
* incoming_frame: The ethernet frame to check
*
* Returns 1 if the ethernet frame is a broadcast
*/
int is_broadcast( struct ether_frame incoming_frame ) {
	/* 	If ethernet dst mac address is broadcast
		If MIP dst is broadcast 0xFF
		If MIP payload is ARP message aka 0x01
	*/ 
	if ( 	compare_mac_addresses( incoming_frame.dst_addr, MAC_BROADCAST_ADDR ) == 0 
		&& incoming_frame.pdu.dst_addr == 0xff 
		&& incoming_frame.pdu.sdu_type == 0x01 ) 
	{	
		return 1;
	}
	return 0;
}

/**
* Checks if an ethernet frame contains a mip pdu that is of type mip-arp, and if it requesting for the current host
* incoming_frame: The ethernet frame to check
*
* Returns 1 if the ethernet frame is requesting for current host
*/
int request_is_for_curr_host( struct ether_frame incoming_frame ) {
	/* 	If MIP-ARP type is Request
		If MIP-ARP request address is current host's address
	*/
	if ( 	incoming_frame.pdu.sdu.type == 0x00 
			&& incoming_frame.pdu.sdu.addr == MIP_ADDRESS ) 
	{
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
	/* 	If Ethernet dst_addr is current host's address
		If MIP-PDU sdu_type of type MIP-ARP 0x01
		If MIP-ARP type is Response
		If MIP-ARP request address is current host's address
	*/
	if ( 	compare_mac_addresses( incoming_frame.dst_addr, MAC_ADDRESS.sll_addr ) == 0 
		&& incoming_frame.pdu.sdu_type == 0x01
		&& incoming_frame.pdu.sdu.type == 0x01
		//&& incoming_frame.pdu.sdu.addr == MIP_ADDRESS   < - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ?????
	) {
		return 1;
	}
	return 0;
}

/**
* Checks if an ethernet frame contains a mip pdu of type ping
* incoming_frame: The ethernet frame to check
*
* Returns 1 if the ethernet frame contains a pdu of type ping
*/
int ping_is_for_host( struct ether_frame incoming_frame ) {
	if ( 	compare_mac_addresses( incoming_frame.dst_addr, MAC_ADDRESS.sll_addr ) == 0 	// mac addr match
			&& incoming_frame.pdu.sdu_type == 0x02						// ping
	) {
		return 1;
	}
	return 0;
}

/**
* Prints the contents of an ethernet frame
* incoming_frame: The ethernet frame to check
*
* Returns void
*/
void print_ethernet_frame( struct ether_frame frame ) {
	print_mac_addr( frame.dst_addr, 6, 1);
	printf("\n");
	print_mac_addr( frame.src_addr, 6, 2);
	printf("\n");
	printf("eth_proto: 0x%04X \n", frame.eth_proto);
	printf("    dst: %u \n", 	frame.pdu.dst_addr );
	printf("    src: %u \n", 	frame.pdu.src_addr );
	printf("    ttl: %u \n", 	frame.pdu.ttl );
	printf("    sdu len: %u \n", 	frame.pdu.sdu_len );
	printf("    sdu type: %02X \n", frame.pdu.sdu_type );
	printf("        type: %02X \n", frame.pdu.sdu.type );
	printf("        addr: %u \n", 	frame.pdu.sdu.addr );
}

/**
* Creates an ethernet frame that contains a mip pdu with type ping
* so_name: socket addresses struct
* mac_dst_addr: The mac address of the deamon this packet will be sent to
* mip_dst_addr: The mip address of the deamon this packet will be sent to
*
* Returns the creates ethernet frame
*/
struct ether_frame* create_ping_packet(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6], uint8_t mip_dst_addr ) {
    struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
    struct MIP_ARP arp;
    struct MIP_PDU pdu;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, mac_dst_addr, 6); 		// MAC address of reciever
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->eth_proto = htons(MIP_PROTO);
    
    // MIP PDU
    pdu.dst_addr = mip_dst_addr;	// Change to mip address of reciever
    pdu.src_addr = MIP_ADDRESS;		// From self
    pdu.ttl = 1;
    pdu.sdu_len = sizeof(arp);
    pdu.sdu_type = 0x02; 			// Ping
    
    ethernet_frame->pdu = pdu;
    
    return ethernet_frame;
}

/**
* Creates an ethernet frame that contains a mip pdu with type mip-arp, that is of type request
* so_name: socket addresses struct
* request_addr: The mip address we are requesting
*
* Returns the creates ethernet frame
*/
struct ether_frame* create_arp_request(struct sockaddr_ll *so_name, uint8_t request_addr ) {
    struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
    struct MIP_ARP arp;
    struct MIP_PDU pdu;
    
    // MIP-ARP
    arp.type = 0x00; 				// Request
    arp.addr = request_addr;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, MAC_BROADCAST_ADDR, 6); // broadcast
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->eth_proto = htons(MIP_PROTO);
    
    // MIP PDU
    pdu.dst_addr = 0xff; 			// broadcast
    pdu.src_addr = MIP_ADDRESS;
    pdu.ttl = 1;
    pdu.sdu_len = sizeof(arp);
    pdu.sdu_type = 0x01; 			// mip-arp
    pdu.sdu = arp;
    
    ethernet_frame->pdu = pdu;
    
    return ethernet_frame;
}

/**
* Creates an ethernet frame that contains a mip pdu with type mip-arp, that is of type response
* so_name: socket addresses struct
* request_src_mac_addr: The mac address we are responding to
* request_src_mip_addr: The mip address we are responding to
*
* Returns the creates ethernet frame
*/
struct ether_frame* create_arp_response(struct sockaddr_ll *so_name, uint8_t request_src_mac_addr[6], uint8_t request_src_mip_addr ) {
    
    struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
    struct MIP_ARP arp;
    struct MIP_PDU pdu;
    
    // MIP-ARP
    arp.type = 0x01; 		// Response
    arp.addr = MIP_ADDRESS; 	// Current host mip address
    
    // MIP PDU
    pdu.dst_addr = request_src_mip_addr;
    pdu.src_addr = MIP_ADDRESS;
    pdu.ttl = 1;
    pdu.sdu_len = sizeof(arp);
    pdu.sdu_type = 0x01;
    pdu.sdu = arp;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, request_src_mac_addr, 6);
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->eth_proto = htons(MIP_PROTO);
    ethernet_frame->pdu = pdu;
    
    return ethernet_frame;
}

/**
* Sends an ethernet frame trough a raw socket
* raw_socket_descriptor: The descriptor of a raw socket
* so_name: socket addresses struct
* ethernet_frame: the ethernet frame we are sending
*
* Returns a number representing if the packet was succesfully sent ( 1 = yes, 0 = no )
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
* Recieves a raw packet
* sd: The descriptor of a raw socket
*
* Returns the recieved ethernet frame
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
* Gets the mac address of current host
* so_name: socket addresses struct
*
* Returns the mac address
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

/**
* Handles incoming domain socket packets
* fd: file descriptor of the domain socket
* raw_socket_descriptor: raw socket descriptor that will be used to send raw packets
* so_name: socket addresses struct
*
* function is affected by the global variable DEBUG_MODE, it determines if it prints to cmd
*
* Returns void
*/
static void handle_client_input(int fd, int raw_socket_descriptor, struct sockaddr_ll *so_name)
{
	char buf[256];
	int rc;

	memset(buf, 0, sizeof(buf));

	// mip address|message
	rc = read(fd, buf, sizeof(buf));
	if (rc <= 0) {
		close(fd);
		return;
	}

	printf("recv buffer from socket: (%s) \n", buf);
	
	int mip_dest_addr;
	char str[256];
	if ( !sscanf(buf, "%d| %[^\n]", &mip_dest_addr, str) == 2 )
		printf("Error in processing client buffer.\n");
	
	// Does the mip destination already exist? Look up arp table.
	uint8_t* mac_address = search_arp_table(mip_dest_addr);
	
	// Address is not registered
	if (mac_address == NULL) {
	
		if ( DEBUG_MODE ) {
			printf("mip address is not registered in mip-arp.\n");
			printf("sending arp request for mip address %d\n", mip_dest_addr);
		}
		// Send mip-arp request
		struct ether_frame* broadcast = create_arp_request(so_name, mip_dest_addr);
		send_raw_packet(raw_socket_descriptor, so_name, broadcast);
		free(broadcast);
	}
	
	// Address is already registered
	else {
		if ( DEBUG_MODE ) {
			printf("mip address is registered in mip-arp.\n");
			printf("sending ping to mip address #%d\n", mip_dest_addr);
		}
		// Proceed to send ping
		struct ether_frame* ping_packet = create_ping_packet( so_name, mac_address, mip_dest_addr );
		send_raw_packet(raw_socket_descriptor, so_name, ping_packet);
		free(ping_packet);
		expecting_pongs++;
	}	
}



static void send_to_client(int socket_descriptor)
{
	
	char buf[256];
	int rc;

	memset(buf, 0, sizeof(buf));

	
	
	/*
	char message[256] = "Yo whats up?";
	
    ssize_t bytes_written = write(domain_socket_descriptor, message, 256);
    if (bytes_written == -1) {
        perror("write");
    }
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), stdin);
	*/
	
	
	rc = write(socket_descriptor, buf, strlen(buf));
	if (rc < 0) {
		perror("write");
		printf("Could not send to domain client.\n");
	}
	
}

/**
* Initializes domain and raw socket and runs them in an infinite loop
* identifier: a variable that represents the mip address of current host
*
* Returns void
*/
void server(int *identifier)
{
	
	/* Fill out ARP table */
	struct mip_mac_mapping mapping;
	mapping.mip_addr = 0;
	mapping.mac_addr[0] = 0;
	mapping.mac_addr[1] = 0;
	mapping.mac_addr[2] = 0;
	mapping.mac_addr[3] = 0;
	mapping.mac_addr[4] = 0;
	mapping.mac_addr[5] = 0;
	for ( int i = 0; i < 255; i++ ) {
		ARP_TABLE[i] = mapping;
	}
	

	/* Raw socket variables */
	int     	raw_sock; //, int rc2;
	uint8_t 	buf[BUF_SIZE];
	//int epollfd;
	struct  sockaddr_ll so_name;
	//struct epoll_event ev, events[MAX_EVENTS];
	short unsigned int protocol = MIP_PROTO;

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
	if (epollfd == -1) {
		perror("epoll_create1");
		close(domain_socket_descriptor);
		exit(EXIT_FAILURE);
	}
	
	/* RAW */
	
	// Add epoll file descriptor
	ev.events = EPOLLIN;
	ev.data.fd = raw_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
		perror("epoll_ctl: raw_sock");
		exit(EXIT_FAILURE);
	}

	printf("*** MIP #%d daemon is running! ***\n* Waiting for client input *\n\n", *identifier);

	/* DOMAIN */

	domain_socket_descriptor = prepare_server_sock(identifier);
	rc = add_to_epoll_table(epollfd, &ev, domain_socket_descriptor);
	if (rc == -1) {
		close(domain_socket_descriptor);
		exit(EXIT_FAILURE);
	}

	while (1) {
	
		memset(buf, 0, BUF_SIZE);
		rc = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		
		if (rc == -1) {
		
			perror("epoll_wait");
			close(domain_socket_descriptor);
			exit(EXIT_FAILURE);
			
		} else {
		
			/********** DOMAIN **********/
		
			// DOMAIN SOCKET EVENT
			if (events->data.fd == domain_socket_descriptor) {
			
				// Add client to epoll table
				accept_sd = accept(domain_socket_descriptor, NULL, NULL);
				if (accept_sd == -1) {
					perror("accept");
					continue;
				}

				rc = add_to_epoll_table(epollfd, &ev, accept_sd);
				if (rc == -1) {
					close(domain_socket_descriptor);
					exit(EXIT_FAILURE);
				}

			}
			
			// INCOMING RAW PACKET
			else if (events->data.fd == raw_sock) {

				struct ether_frame incoming_frame = recv_raw_packet(raw_sock);
				
				// RECIEVED MIP-ARP broadcast && requesting for current host's address
				if( is_broadcast(incoming_frame) && request_is_for_curr_host(incoming_frame) ) {
					
					if ( DEBUG_MODE ) {
						printf("recieved arp request message for mip addr. %u \n", incoming_frame.pdu.sdu.addr );
						printf("match!\n");
					}
					
					// Get mapping values
					struct mip_mac_mapping mapping;
					mapping.mip_addr = incoming_frame.pdu.src_addr;
					memcpy(mapping.mac_addr, incoming_frame.src_addr, 6);
					
					// Add to mapping table
					add_to_table(mapping);
					
					if ( DEBUG_MODE ) {
						printf("added mapping to arp table.\n");
						print_arp_table();
					}	
					
					// Send MIP-ARP response out
					struct ether_frame* response = create_arp_response( &so_name, mapping.mac_addr, mapping.mip_addr );
					send_raw_packet(raw_sock, &so_name, response);
					free(response);
					
					if ( DEBUG_MODE ) {
						printf("sending arp response back.\n" );
					}	
					
					//print_ethernet_frame( incoming_frame );
					
				}
				
				// RECIEVED MIP ARP RESPONSE TO THIS CLIENT
				if ( response_is_for_curr_host(incoming_frame) ) {

					if ( DEBUG_MODE ) {
						printf("recieved an arp response back. \n");
						printf("match!\n");					
					}	
					
					// Get mapping values
					struct mip_mac_mapping mapping;
					mapping.mip_addr = incoming_frame.pdu.src_addr;
					memcpy(mapping.mac_addr, incoming_frame.src_addr, 6);
					
					if ( add_to_table(mapping) ) {
						if ( DEBUG_MODE ) {
							printf("Mapping added to table. \n");
							print_arp_table();
						}
					}
					else {
						if ( DEBUG_MODE ) {
							printf("Mapping already exists \n");
						}
					}
					
					// PING
					struct ether_frame* ping_packet = create_ping_packet( &so_name, mapping.mac_addr, mapping.mip_addr );
					send_raw_packet(raw_sock, &so_name, ping_packet);
					free(ping_packet);
					expecting_pongs++;
					
					if ( DEBUG_MODE ) {
						printf("sending ping to mip daemon #%u \n", mapping.mip_addr);
					}
					
				}
				
				// RECIEVED PING // PONG
				else if ( ping_is_for_host(incoming_frame) ) {
					
					// The ping is a pong
					if ( expecting_pongs > 0 ) {
					
						// send ping struct trough the domain socket to server

						if ( DEBUG_MODE ) {
							printf( "recieved pong from mip daemon #%u \n", incoming_frame.pdu.src_addr );						
						}

						expecting_pongs--;
					}
					// recieved a ping, need to send a pong
					else {
					
						if ( DEBUG_MODE ) {
							printf("recieved ping from mip daemon #%u \n", incoming_frame.pdu.src_addr );
						}
						// send pong struct trough the domain socket to server
						// send_to_client(domain_socket_descriptor);
						
						// send pong back to src daemon
						struct ether_frame* pong_packet = create_ping_packet( &so_name, incoming_frame.src_addr, incoming_frame.pdu.src_addr );
						send_raw_packet(raw_sock, &so_name, pong_packet);
						free(pong_packet);
						
						if ( DEBUG_MODE ) {
							printf("sending pong back to mip daemon #%u \n", incoming_frame.pdu.src_addr);
						}
						
					}
				}
				
			}					
			
			// ping client sent buffer trough domain socket
			else {
			
				handle_client_input(events->data.fd, raw_sock, &so_name);

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
	
	while ((opt = getopt(argc, argv, "dhi:")) != -1) {
		switch (opt) {
			
			// Debug mode
			case 'd':
				DEBUG_MODE = 1;
				break;
				
			case 'i':
			
				//Passing identity variable to the MIP daemon
				if(isdigit(*optarg))
					num = atoi(optarg);
				else {
					printf("Please enter a numeric value for the argument \"n\"\n");
					exit(EXIT_FAILURE);
				}
				break;
			
			// Help mode
			case 'h':
				
				printf("mipd [-h] [-d] <socket_upper> <MIP address>\n\n");
				printf("This is a program for starting a MIP daemon on your computer.\n\n");
				printf("Usage: %s "
				"[-d] debug mode "
				"[-h] help\n", argv[0]);
				exit(EXIT_FAILURE);
			
			default:
				printf("Usage: %s "
				"[-d] debug mode "
				"[-h] help\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	// If the mip address is 255 or higher, exit program
	if ( num >= 255 || num == 0xff ) {
		printf("MIP indentifying addresses can only be between 0 - 254, exiting... \"n\"\n");
		exit(EXIT_FAILURE);
	}
	
	MIP_ADDRESS = num;
	server(&num);
	
	return 0;
}

