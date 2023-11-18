#include <time.h>
#include "serverutils.h"

#define MAX_EVENTS 10
#define BUF_SIZE 1450
#define DST_MAC_ADDR {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

/**** ROUTING ****/

int compare_mac_addresses( uint8_t *mac_addr1, uint8_t *mac_addr2 ) {
	return memcmp(mac_addr1, mac_addr2, 6);
}

struct host {
	uint8_t address[6];
};

struct host routing_table[255];

int table_iterator = 0;

int inTable(uint8_t mac_addr[6]) {
	int found = 0;
	for ( int i = 0; i < 5; i++ ) {
		if ( compare_mac_addresses( routing_table[i].address, mac_addr ) == 0 ) {
			found = 1;
			break;
		}
	}
	return found;
}

void addToTable( uint8_t mac_addr[6] ) {
    memcpy(routing_table[table_iterator].address, mac_addr, 6);
	table_iterator++;
}

void printRoutingTable() {
	printf("*** Routing Table ***\n");
	for ( int i = 0; i < table_iterator; i++ ) {
		for (int j = 0; j < 6; j++) {
			printf("%02X ", routing_table[i].address[j]);
		}
		printf("\n");
	}
	printf("\n\n");
}

struct sockaddr_ll MAC_ADDRESS;
uint8_t MAC_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint16_t MIP_PROTO = 0x88B5;
int DEBUG_MODE = 0;

struct MIP_ARP {
	uint8_t type; // 0x00 req - 0x01 res 
	uint8_t addr; // mip addr
	uint8_t pad[2]; 	
};

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

void print_mac_addr(uint8_t *addr, size_t len, int dst ) {
	if ( dst == 1 )
		printf("dst: ");
	else if ( dst == 2 )
		printf("src: ");
		
	for (int i = 0; i < len - 1; i++) {
		printf("%02X ", addr[i]);
	}
}

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

int is_broadcast( struct ether_frame incoming_frame ) {
	/* 	If ethernet dst mac address is broadcast */ 
	if ( compare_mac_addresses( incoming_frame.dst_addr, MAC_BROADCAST_ADDR ) == 0 )
	{	
		return 1;
	}
	return 0;
}

int request_is_for_host( struct ether_frame incoming_frame ) {
	if ( 	compare_mac_addresses( incoming_frame.dst_addr, MAC_ADDRESS.sll_addr ) == 0 	// mac addr match
			&& incoming_frame.pdu.sdu_type == 0x04						// Router
	) {
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
			&& incoming_frame.pdu.sdu.type == 0x04 ) 
	{
		return 1;
	}
	return 0;
}

struct ether_frame* create_hello_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6]) {
    struct ether_frame* ethernet_frame = malloc(sizeof(*ethernet_frame));
    struct MIP_ARP arp;
    struct MIP_PDU pdu;
    
    // FRAME
    memcpy(ethernet_frame->dst_addr, mac_dst_addr, 6);
    memcpy(ethernet_frame->src_addr, so_name->sll_addr, 6);
    ethernet_frame->eth_proto = htons(MIP_PROTO);
    
    // MIP PDU
    // pdu.dst_addr = mip_dst_addr;	// Change to mip address of reciever
    pdu.ttl = 1;					// TTL of 1 because this will be broadcast to reachable hosts
    pdu.sdu_len = sizeof(arp);
    pdu.sdu_type = 0x04; 			// Routing protocol
    ethernet_frame->pdu = pdu;
    
    return ethernet_frame;
}

struct ether_frame* create_request_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6]) {
	
}

struct ether_frame* create_response_message(struct sockaddr_ll *so_name, uint8_t mac_dst_addr[6]) {
	
}

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

void server(int *identifier)
{
	
	/* Raw socket variables */
	int     	raw_sock;
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
	
	/*
	if (epollfd == -1) {
		perror("epoll_create1");
		close(domain_socket_descriptor);
		exit(EXIT_FAILURE);
	}
	*/
	
	/* RAW */
	
	// Add epoll file descriptor
	ev.events = EPOLLIN;
	ev.data.fd = raw_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
		perror("epoll_ctl: raw_sock");
		exit(EXIT_FAILURE);
	}

	printf("*** Router is running ***\n\n");

	/* DOMAIN */
	
	/*
	domain_socket_descriptor = prepare_server_sock(identifier);
	rc = add_to_epoll_table(epollfd, &ev, domain_socket_descriptor);
	if (rc == -1) {
		close(domain_socket_descriptor);
		exit(EXIT_FAILURE);
	}
	*/

	/**************************************************************************/
	
	// Start router by sending broadcast request for filling routing table
	struct ether_frame* router_req_packet = create_hello_message( &so_name, MAC_BROADCAST_ADDR );
	send_raw_packet(raw_sock, &so_name, router_req_packet);
	free(router_req_packet);
	
	while (1) {
	
		memset(buf, 0, BUF_SIZE);
		rc = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		
		if (rc == -1) {
		
			perror("epoll_wait");
			close(domain_socket_descriptor);
			exit(EXIT_FAILURE);
			
		} else {
			
			// INCOMING RAW PACKET
			if (events->data.fd == raw_sock) {
				
				// Recieved a broadcast from another router
				struct ether_frame incoming_frame = recv_raw_packet(raw_sock);
				if ( is_broadcast(incoming_frame) ) {
					
					printf("Recieved hello message from unknown host."); //DEBUG
					
					// If the host is not in routing table
					if ( inTable( incoming_frame.src_addr ) == 0 ) {
						
						printf("Adding to routing table...\n"); //DEBUG
						
						addToTable( incoming_frame.src_addr );
						printRoutingTable();
						
						// Send broadcast
						struct ether_frame* router_req_packet = create_hello_message( &so_name, MAC_BROADCAST_ADDR );
						send_raw_packet(raw_sock, &so_name, router_req_packet);
						free(router_req_packet);

					}
					
				
				}
			}
			
			// ping client sent buffer trough domain socket
			else {
				// handle_client_input(events->data.fd, raw_sock, &so_name);
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
	
	server(&num);
	
	return 0;
}
