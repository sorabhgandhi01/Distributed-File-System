#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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
static int log_in(int cfd);

/*Function to print error message*/
void print_error(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void clear_buffer(char *msg, ...)
{
    va_list va_args;
    va_start(va_args, msg);
    memset(msg, 0, sizeof(msg));
    va_end(va_args);
    fflush(stdout);
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
	ssize_t numRead;
	printf("Waiting for the client request\n");
	clear_buffer(buffer);

	while ((numRead = read(cfd, buffer, BUFF_SIZE)) > 0) {
		printf("%s\n", buffer);

		clear_buffer(buffer);
	}

	if (numRead == -1) {
		print_error("handleRequest: read");
	}
}


static int log_in(int cfd)
{
	char buffer[BUFF_SIZE], server_msg[256];
	char u_name[50], passkey[50];
	int auth_success = 0;
	ssize_t numRead;

	clear_buffer(buffer, server_msg, u_name, passkey);

	while (!auth_success)
	{
		numRead = read(cfd, buffer, BUFF_SIZE);
		printf("%s\n", buffer);
		sscanf(buffer, "%s %s", u_name, passkey);

		if (parse_ConfigFile("dfs.conf", u_name, passkey) == 1) {
			
			snprintf(server_msg, 256, "%s", "Authentication Success");
			send(cfd, server_msg, strlen(server_msg), 0);
			auth_success = 1;
			return 1;
        }
		else {

			sprintf(server_msg, 256, "%s", "Invalid Username/Password. Please try again");
			send(cfd, server_msg, strlen(server_msg), 0);
			return -1;
		}
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
		clear_buffer(buffer, key, value);
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
				if (log_in(cfd) == 1) {
					handleRequest(cfd);
					//printf("Auth Success\n");
				}
				close(cfd);
				exit(EXIT_SUCCESS);

			default:
				close(cfd);
				break;
		}

	}

	return 0;
}
