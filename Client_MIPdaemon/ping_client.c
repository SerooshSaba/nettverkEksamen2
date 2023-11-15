#include "serverutils.h"

/**
* Send a char* buffer into the designated domain socket
* socket_lower: path to domain socket file
* destination: mip address to the mip daemon we want to ping
* message: the message we want to deliver
*
* Returns void
*/
void client(char* socket_lower, char* destination, char* message)
{
	// init domain socket variables
	struct	sockaddr_un addr;
	int		sd, rc;
	char	buf[256];
	
	sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_lower, sizeof(addr.sun_path) - 1);
	rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	
	if ( rc < 0) {
		perror("connect");
		close(sd);
		exit(EXIT_FAILURE);
	}

	printf("PING: %s\n\n",message);

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s|%s", destination, message);
	rc = write(sd, buf, strlen(buf));
	if (rc < 0) {
		perror("write");
		close(sd);
		exit(EXIT_FAILURE);
	}

}

/**
* The main function takes arguments when this program is started and sends it to client function
*
* Returns just an int
*/
int main (int argc, char *argv[])
{

	if (argc < 4) {
		printf("Usage: %s <socket_lower> <destination_host> <message>\n", argv[0]);
		return 1;
	}
	
	int opt;
	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
			case 'h':
				printf("Help information:\n");
				printf("Usage: %s <socket_lower> <destination_host> <message>\n", argv[0]);
				exit(EXIT_FAILURE);
			default:
				printf("Unknown option! Please use -h for help.\n");
				return 1;
		}
	}

	char* socket_lower = argv[optind];
	char* destination = argv[optind + 1];
	char* message = argv[optind + 2];

	//printf("socket_lower %s \n", socket_lower);
	//printf("destination %s \n", destination);
	//printf("message %s \n", message);

	client(socket_lower, destination, message);
	
	return 0;
}
