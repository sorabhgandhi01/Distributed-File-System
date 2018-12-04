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

/*---------------Typedef and Structure definations-------------*/
typedef struct server_config
{
    char name[10];
    char ip[100];
    char port[10];
}server_config;

typedef struct server_cred
{
    char u_name[20];
    char password[20];
}server_cred;


/*-----------------------Global Variable-----------------------*/
server_cred credential;
server_config server[4];


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


static int parse_ConfigFile(const char *filename)
{
    char buffer[256];
    char key[20], value[256], name[20];
    char dummy[100];
    int i = 0;

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
        return -1;

    while (fgets(buffer, 256, (FILE *)fp))
    {
        sscanf(buffer, "%s %s %s", key, name, value);

        if (strcmp(key, "Server") == 0)
        {
            strcpy(server[i].name, name);
            strcpy(server[i].ip, strtok(value, ":"));
            strcpy(server[i].port, strtok(NULL, ":"));
            i++;
        }
        else if (strcmp(key, "Username") == 0)
        {
            strcpy(credential.u_name, name);
        }
        else if (strcmp(key, "Password") == 0)
        {
            strcpy(credential.password, name);
        }
        else {

        }

		clear_buffer(buffer, key, value, dummy, name);
    }

    return 0;
}

/*void client_menu(int fd)
{
	char user_input[50];
	char cmd_send[128];

	printf("\n Menu \n Enter any of the following commands \n 1.) get [file_name] \n 2.) put [file_name] \n 3.) list \n 4.) exit \n");		
	scanf(" %[^\n]%*c", cmd_send);

	snprintf(cmd_send, 100, "%s %s %s", user_input, credential.u_name, credential.password);
	if (send(fd, cmd_send, strlen(cmd_send), 0) < 0)
		print_error("Client: send");

	clear_buffer(cmd_send, credential);
}*/

int main(int argc, char **argv)
{
	struct sockaddr_in sock;

	char user_input[50], cmd_send[128];
	char auth_resp[256];
    int dfs1 = 0, option = 1;
    ssize_t length;

	dfs1 = socket(AF_INET, SOCK_STREAM, 0);
    if (dfs1 == -1)
		print_error("Client: init_socket");

    setsockopt(dfs1, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	if (parse_ConfigFile("dfc.conf") == -1)
		print_error("Client: parse_ConfigFile");

    memset(&sock, 0, sizeof(sock));
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = inet_addr(server[0].ip);
    sock.sin_port = htons(atoi(server[0].port));

	if (connect(dfs1, (struct sockaddr *)&sock, sizeof(sock)) < 0)
		print_error("Client: connect");

	for (;;)
	{
		printf("\n Menu \n Enter any of the following commands \n 1.) get [file_name] \n 2.) put [file_name] \n 3.) list \n 4.) exit \n");
    	scanf(" %[^\n]%*c", cmd_send);

    	snprintf(cmd_send, 100, "%s %s %s", user_input, credential.u_name, credential.password);
    	if (send(dfs1, cmd_send, strlen(cmd_send), 0) < 0)
        	print_error("Client: send");

		read(dfs1, auth_resp, sizeof(auth_resp));
		printf("%s\n", auth_resp);

		clear_buffer(cmd_send, credential);
	}

	close(dfs1);

	return 0;
}
