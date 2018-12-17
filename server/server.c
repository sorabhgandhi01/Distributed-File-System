#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
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
#define MAXBUFSIZE 1024

typedef struct
{
	char command[32];
	char filename[32];
	char subfolder[32];
	char cred[128];
	size_t file_size;
	int file_part;
}packet_t;

typedef struct
{
    int serv;
    int t_file;
    int t_folder;
    char filename[128][32];
    char file_part[128][2];
    char subfolder[128][32];
}list_t;

typedef struct{
	char packet_number[2];
	long int packet_size[2];
}get_t;


//list_t list = {0};
int file_counter=-1;
/*--------------------------Local function Prototype------------------------*/
void print_error(char *msg);
static int init_socket(struct sockaddr_in sock, char *ip, char *port);
static void handleRequest(int cfd, char *arg);
static int parse_ConfigFile(const char *filename, char *username, char *password);
static int log_in(int cfd);
void list(int sock, char *path);
void new_get(int sock, char *path, char *file_name);

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
	sock.sin_addr.s_addr = htonl(INADDR_ANY);
	sock.sin_port = htons(atoi(port));
    
	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) == -1) {
		perror("init_socket: bind\n");
		return -1;
	}

	return fd;
}

static void handleRequest(int cfd, char *arg)
{
	packet_t packet = {0};
	struct timeval timeout = {1,0};
	struct stat st = {0};
	char u_name[30], passkey[30], path[256], subpath[256], mkdir_path[256];
	int msg_recv;
	ssize_t numRead;
	FILE *fptr;

	printf("Waiting for the client request\n");
	//clear_buffer(u_name, passkey, path, subpath, mkdir_path, packet);
	memset(&packet, 0, sizeof(packet));

	while ((numRead = read(cfd, &packet, sizeof(packet))) > 0) {
		
		memset(u_name, 0, sizeof(u_name));
		memset(passkey, 0, sizeof(passkey));
		memset(subpath, 0, sizeof(subpath));
		memset(mkdir_path, 0, sizeof(mkdir_path));
		memset(path, 0, sizeof(path));

		msg_recv = 1;
		if (strcmp(packet.command, "get") != 0) {
			send(cfd, &msg_recv, sizeof(int), 0);
		}

		sscanf(packet.cred, "%s %s", u_name, passkey);
		sprintf(path, "%s/%s", arg, u_name);
		/*printf("Path	-->	%s\n", path);
		if (stat(path, &st) == -1) {
			system(mkdir_path);
			printf("New Folder Created -->	%s\n", mkdir_path);
		}*/

		snprintf(subpath, 256, "%s/%s/%s", arg, u_name, packet.subfolder);
		printf("subpath	-->	%s\n", subpath);
		sprintf(mkdir_path, "mkdir -p %s/%s/%s", arg, u_name, packet.subfolder);

		if(((strcmp(packet.command, "put") == 0)))
		{
			if (stat(subpath, &st) == -1) {
            	system(mkdir_path);
            	printf("New Folder Created -->  %s\n", mkdir_path);
        	}

			setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));
			
			char partname[30] = {0};
			sprintf(partname, "%s/%s.%d", subpath, packet.filename, packet.file_part+1);
			printf("partname - %s\n",partname);
			
			fptr = fopen(partname, "w");
			if (fptr == NULL)
				printf("File open failed\n");

			char *recv_buf = NULL;
			recv_buf = (char*)malloc(packet.file_size);
			
			size_t total_bytes = 0;
			numRead = 0;
			printf("Going to recieve file of size = %ld\n", packet.file_size);

			while (total_bytes != packet.file_size)
			{
				printf("Waiting for the file\n");
				if((numRead = recv(cfd, recv_buf, packet.file_size, 0)) > 0)
				{
					total_bytes += numRead;
					fwrite(recv_buf, 1, numRead, fptr);
					printf("Recieved --> %ld bytes of data\n", numRead);
					msg_recv = 1;
					send(cfd, &msg_recv, sizeof(int), 0);
				}
			}
			free(recv_buf);
			printf("Total file size recieved	-->	%ld\n", total_bytes);
			fclose(fptr);

			timeout.tv_sec = 0;
			timeout.tv_usec = 0;
			setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,	sizeof(struct timeval));
		}
		else if (((strcmp(packet.command, "get")) == 0) && (*(packet.filename) != '\0'))
        {
			timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(struct timeval));
			new_get(cfd, subpath, packet.filename);
		}
      	else if (((strcmp(packet.command, "list")) == 0))
        {
			printf("List called\n");
			list(cfd, subpath);
		}
		else if (((strcmp(packet.command, "mkdir")) == 0))
        {

		}
		else if (((strcmp(packet.command, "exit")) == 0))
		{
			close(cfd);
			exit(0);
		}
		else {
                printf("Invalid Command\n");
		}
		
		memset(u_name, 0, sizeof(u_name));
		memset(passkey, 0, sizeof(passkey));
		memset(subpath, 0, sizeof(subpath));
		memset(mkdir_path, 0, sizeof(mkdir_path));
		memset(path, 0, sizeof(path);
		memset(&packet, 0, sizeof(packet));
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

void new_get(int sock, char *path, char *file_name) {
    
    FILE *f;
    int total = 0;
    int nbytes;
    char file_buffer[MAXBUFSIZE];
    char path_buffer[MAXBUFSIZE];
	char temp[MAXBUFSIZE];
    unsigned char ch;
    char return_message[MAXBUFSIZE];
    char server_path[MAXBUFSIZE];
    char buffer[MAXBUFSIZE];

	if((path[strlen(path)-1]) != '/' && strlen(path)) {
		path[strlen(path)] = '/';
	}
	
    snprintf(server_path, MAXBUFSIZE, "%s%s.", path, file_name);

    int i = 0;
    int file_part = 0;
    for(i = 1; i <= 4; i++) {
        sprintf(buffer, "%s%d", server_path, i);
		printf("Server_path --> %s\n", buffer);
		if (access(buffer, F_OK) == 0) {
        	f = fopen(buffer, "r");
			//printf("File open successfully\n");
            file_part = file_part*10 + i;
			fclose(f);
        }
		memset(buffer, 0, sizeof(buffer));
    }
	
	//printf("File part = %d\n", file_part);
   
    if (send(sock, &file_part, sizeof(file_part), 0) < 0) {
		printf("Error in Sending file\n");
	}
    
	int request = 0;
	recv(sock, &request, sizeof(request), 0);

	if (request) {
    // send first file then second file
	request = 0;
    strcpy(path_buffer, server_path);
    snprintf(server_path, MAXBUFSIZE, "%s%d", path_buffer, file_part/10);
    f = fopen(server_path, "r+b");
    if(f != NULL) {
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        rewind(f);
        send(sock, &file_size, sizeof(file_size), 0);
		//printf("File Size = %ld\n", file_size);
        
		char *buf = (char *)malloc(file_size);
		fread(buf, 1, file_size, f);
        nbytes = send(sock, buf, file_size, 0);
			//printf("%s\n", buf);
        if(nbytes == -1) {
			printf("Error sending file\n");//, strerror(errno));
		}
		free(buf);
    }

    else {
        snprintf(return_message, MAXBUFSIZE, "Invalid file name. File does not exist.");
        send(sock, return_message, MAXBUFSIZE, 0);
    }

	memset(server_path, 0, sizeof(server_path));
    fclose(f);
    total = 0;
    int modFile = file_part % 10;
	strcpy(temp, path_buffer);
    snprintf(path_buffer, MAXBUFSIZE, "%s%d", temp, modFile);
    strcpy(server_path, path_buffer);
	printf("path_buffer = %s\n", server_path);
    f = fopen(server_path, "r+b");
    if(f != NULL) {
        fseek(f, 0, SEEK_END);
        long f_size = ftell(f);
        rewind(f);
        send(sock, &f_size, sizeof(f_size), 0);
		//printf("File Size = %ld\n", f_size);
        
		char *buf = (char *)malloc(f_size);
       
		fread(buf, 1, f_size, f);
        nbytes = send(sock, buf, f_size, 0);
        if(nbytes == -1) {
			printf("Error sending file\n");
        }
    
		printf("\nFile sent succesfully\n");
		free(buf);
    }
    
    else {
        snprintf(return_message, MAXBUFSIZE, "Invalid file name. File does not exist.");
        send(sock, return_message, MAXBUFSIZE, 0);
    }
    fclose(f);
	}
}

void list(int sock, char *path) {
    int max = 0;
    FILE *f;
    int nbytes;
    char ls[MAXBUFSIZE];
    snprintf(ls, MAXBUFSIZE, "ls -a %s", path);
    
    f = popen(ls, "r");
    char buf[MAXBUFSIZE];
    while(fgets(buf, sizeof(buf), f) != 0) {
        max++;
    }
    pclose(f);
    // send count
    nbytes = send(sock, &max, sizeof(max), 0);
    // if only . and .. (max == 2) then don't send anything further
    f = popen(ls, "r");
    if(max > 2) {
        
        while(fgets(buf, sizeof(buf), f) != 0) {
			printf("buff	->	%s\n", buf);
            send(sock, buf, MAXBUFSIZE, 0);
        }
    }
}


int main(int argc, char **argv)
{
	if ((argc < 3) || (argc > 3)) {				
		printf("Usage --> ./[%s][Local Folder][Port Number]\n", argv[0]);	//Should have a port number > 5000
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server, client;
	int sfd, cfd;
	ssize_t length;

	sfd = init_socket(server, "127.0.0.1", argv[2]);
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
					handleRequest(cfd, argv[1]);
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
