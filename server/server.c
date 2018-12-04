#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>


/*--------------------Typedefs and Structure definitions-------------------*/
#define MAX_Q 10
#define BUFF_SIZE 4096

/*--------------------------Local function Prototype------------------------*/
void print_error(char *msg);
static int init_socket(struct sockaddr_in sock, char *ip, char *port);
static void handleRequest(int cfd);
static int parse_ConfigFile(const char *filename, char *username, char *password);


/*Function to print error message*/
void print_error(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static int init_socket(struct sockaddr_in sock, char *ip, char *port)
{
    int fd = 0, option = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
		perror("init_socket: socket\n");
        return -1;
	}

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if ((ip == NULL) || (port == NULL))
    	return -2;

	memset(&sock, 0, sizeof(sock));
	sock.sin_family = AF_INET;
	//sock.sin_addr.s_addr = inet_addr(ip);
	sock.sin_addr.s_addr = htonl(INADDR_ANY);
	sock.sin_port = htons(atoi(port));
    
	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) == -1) {
		perror("init_socket: bind\n");
		return -1;
	}

	return fd;
}

static void handleRequest(int cfd)
{
	char buffer[BUFF_SIZE];
	char cmd[10], flname[40], u_name[20], passkey[20];
	char auth_error[] = "Invalid Username/Password. Please try again.";
	char server_error[] = "Server failed to open the configuration file";
	ssize_t numRead;

	while ((numRead = read(cfd, buffer, BUFF_SIZE)) > 0) {
		printf("%s\n", buffer);

		sscanf(buffer, "%s %s %s %s", cmd, flname, u_name, passkey);

		if (parse_ConfigFile("dfs.conf", u_name, passkey) == -2) {

			send(cfd, auth_error, strlen(auth_error), 0);

		}
		else if (parse_ConfigFile("dfs.conf", u_name, passkey) == 1) {

			send(cfd, "Authentication Success", 22, 0);

		}
		else {

			send(cfd, server_error, strlen(server_error), 0);

		}
		
	}

	if (numRead == -1) {
		print_error("handleRequest: read");
	}
}

static int parse_ConfigFile(const char *filename, char *username, char *password)
{
    char buffer[256];
    char key[30], value[30];

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
        return -1;

    while (fgets(buffer, 256, (FILE *)fp))
    {
        sscanf(buffer, "%s %s", key, value);

        if ((strcmp(key, username) == 0) && (strcmp(value, password) == 0))
        {
            return 1;
		}
    }

    return -2;
}


int main(int argc, char **argv)
{
	if ((argc < 2) || (argc > 2)) {				
		printf("Usage --> ./[%s] [Port Number]\n", argv[0]);	//Should have a port number > 5000
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server, client;
	int sfd, cfd;
	ssize_t length;

	sfd = init_socket(server, "127.0.0.1", argv[1]);
	if (sfd < 0)
		exit(EXIT_FAILURE);

	if (listen(sfd, MAX_Q) == -1)
		print_error("Server: listen\n");

	while (1)
	{
		length = sizeof(client);
		cfd = accept(sfd, (struct sockaddr *) &client, (socklen_t *) &length);
		if (cfd == -1)
		{
			perror("Server: accept\n");
			continue;
		}

		switch(fork())
		{
			case -1:
				perror("Server: Cannot create the child\n");
				close(cfd);
				break;

			case 0:
				close(sfd);
				handleRequest(cfd);
				close(cfd);
				exit(EXIT_SUCCESS);

			default:
				close(cfd);
				break;
		}

	}

	return 0;
}
