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

typedef struct
{
	char command[32];
	char filename[32];
	char subfolder[32];
	char cred[128];
	size_t file_size;
	int file_part;
}packet_t;

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


int main(int argc, char **argv)
{
	struct sockaddr_in sock[4];
	packet_t packet;

	char user_input[50], cmd_send[128];
	char auth_resp[256];
    int dfs[4]; 
	int option = 1, auth_success = 0, i = 0;
    ssize_t length;

	if (parse_ConfigFile("dfc.conf") == -1)
		print_error("Client: parse_ConfigFile");

	for (i = 0; i < 4; i++) {

		memset(&sock[i], 0, sizeof(sock[i]));

		dfs[i] = socket(AF_INET, SOCK_STREAM, 0);
    	if (dfs[i] == -1)
			print_error("Client: init_socket");

    	setsockopt(dfs[i], SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

		sock[i].sin_family = AF_INET;
    	sock[i].sin_addr.s_addr = inet_addr(server[i].ip);
		sock[i].sin_port = htons(atoi(server[i].port));

		if (connect(dfs[i], (struct sockaddr *)&sock[i], sizeof(sock[i])) < 0) {
			close(dfs[i]);
			dfs[i] = -1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	for (;;)
	{
		clear_buffer(cmd_send, auth_resp, user_input);
		if (!auth_success) {

			printf("Trying to connect to the server\n");		
			snprintf(cmd_send, 128, "%s %s", credential.u_name, credential.password);

			for (i = 0; i < 4; i++) {
				if (send(dfs[i], cmd_send, strlen(cmd_send), 0) < 0)
					print_error("Client: send");

				read(dfs[i], auth_resp, sizeof(auth_resp));
			
				if (strcmp(auth_resp, "Invalid Username/Password. Please try again") == 0) {
					auth_success = 0;
					memset(&auth_resp, 0, sizeof(auth_resp));
					printf("Authentication Failed\n");
					exit(1);
					break;
				}
				else if (strcmp(auth_resp, "Authentication Success") == 0) {
					auth_success = 1;
					memset(&auth_resp, 0, sizeof(auth_resp));
				}
				else {
					exit(1);
				}
			}

			if (auth_success) {
				printf("Authentication Success\n");
			}
        	clear_buffer(cmd_send, auth_resp);
		}
		else {

			printf("\n Menu \n Enter any of the following commands \n 1.) get [file_name] \n 2.) put [file_name] \n 3.) list \n 4.) exit \n");
    		scanf(" %[^\n]%*c", user_input);

			for (i = 0; i < 4; i++) {
    		if (send(dfs[i], user_input, strlen(user_input), 0) < 0) {
				print_error("Client: send");
			}
			}

			clear_buffer(cmd_send, user_input, auth_resp);
		}
	}

	close(dfs[0]);
	close(dfs[1]);
	close(dfs[2]);
	close(dfs[3]);

	return 0;
}
