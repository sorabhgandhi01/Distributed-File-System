#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include <unistd.h>
#include <error.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

#define MAXBUFSIZE 1024
#define NUMSERVERS 4
#define SERVERNAME 50
#define LISTSIZE 4096
#define MAXFILES 25

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
	int frame;
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


struct files {
    int count;
    char file_name[MAXFILES][MAXBUFSIZE];
    int parts[MAXFILES][4];
};
/*-----------------------Global Variable-----------------------*/
server_cred credential;
server_config server[4];

char file[128][32] = {0};
char subfolder[128][32] = {0};
int part_flag[128][5] = {0};	
int file_count = 0;
int folder_count = 0;
int dfs[4];

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


unsigned char file_md5_counter(char *filename,size_t filesize, FILE *f)
{
  char *buf = NULL;
  unsigned char md5s[MD5_DIGEST_LENGTH] = {0};

 
  buf = (char*)malloc(filesize);

  fread(buf,1, filesize, f);
  fseek(f,0,SEEK_SET);

  MD5(buf, filesize, md5s);
  printf("MD5 (%s) = ", filename);
  for (int i=0; i < MD5_DIGEST_LENGTH; i++)
  {
    printf("%x",  md5s[i]);
  }  
  printf("\nRemainder - %d\n",md5s[15]%4);
  free(buf);
  return (md5s[15]%4);
}

void list(int sock[], struct files *fileList, packet_t packet) {
    int completeFile = 0;
    char buf[MAXBUFSIZE];
    char file_buffer[MAXBUFSIZE];
    int emptyFlag = 0;
    int count;
    int fileCount = 0;
    int part;
    int k = 0;
    int index = 0;
    int fileFlag = 0;
    
    memset(&fileList->file_name, 0, sizeof(fileList->file_name));
    memset(&fileList->parts, 0, sizeof(fileList->parts));
    fileList->count = 0;
    
    for(int i=0; i<4; i++) {
        //printf("SERVER %d\n", i);
        index = 0;
        if(sock[i] != -1) {
            send(sock[i], &packet, sizeof(packet), 0);

			int msg_accepted = 0;
			if(recv(sock[i], &msg_accepted, sizeof(int), 0) <= 0) {
                continue;;
            }

            if(recv(sock[i], &count, sizeof(count), 0) <= 0) {
                continue;;
            }
            if(count == 2) {
                emptyFlag = 1;
            }
            else {
                emptyFlag = 0;
                for (int j = 0; j<count; j++) {
                    //receive file_name;
                    memset(&buf, 0, MAXBUFSIZE);
                    recv(sock[i], buf, MAXBUFSIZE, 0);
                    if(strcmp(buf, ".\n") == 0) {
                        continue;
                    }
                    else if(strcmp(buf, "..\n") == 0) {
                        continue;
                    }
                    else {
                        snprintf(file_buffer, MAXBUFSIZE, "%s", &buf[0]);
						//printf("Buff	-->	%s\n", file_buffer);
                        k = strlen(file_buffer) - 1;
                        while(k >= 0) {
                            if(file_buffer[k] == '.') {
                                part = file_buffer[k+1] - '0';
                                file_buffer[k] = '\0';
                                break;
                            }
                            k--;
                        }
                    }
                    //printf("%s\t", file_buffer);
                    //printf("%d\n", part);
                    if(fileFlag == 0) {
                        snprintf(fileList->file_name[index], MAXBUFSIZE, "%s", file_buffer);
                        fileCount++;
                        fileFlag = 1;
                    }
                    else {
                        if(strcmp(fileList->file_name[index], file_buffer) != 0) {
                            //printf("%s:%s\n", fileList->file_name[index], file_buffer);
                            index++;
                            fileCount++;
                            snprintf(fileList->file_name[index], MAXBUFSIZE, "%s", file_buffer);
                        }
                    }
                    //printf("%d:%d:%d\n", index, fileCount, part);
                    fileList->parts[index][part-1] = 1;
                    if(index > fileList->count) {
                        fileList->count = index;
                    }
                }
            }
        }
        
    }
    if(emptyFlag == 1) {
        printf(".\n..\n");
    }
    else {
        for(int i=0; i<=fileList->count; i++) {
            //Check if we have all four parts
            if(fileList->parts[i][0] == 1 && fileList->parts[i][1] == 1
               && fileList->parts[i][2] == 1 && fileList->parts[i][3] == 1) {
                
                completeFile = 1;
                fileList->parts[i][0] = 0;
                fileList->parts[i][1] = 0;
                fileList->parts[i][2] = 0;
                fileList->parts[i][3] = 0;
            }
            
            // Add "incomplete" to file name if we don't have enough parts
            if(!completeFile) {
                strcat(fileList->file_name[i], " [incomplete]");
            }
            strcat(fileList->file_name[i], "\n");
            printf("%d. %s", i+1, fileList->file_name[i]);
        }
    }
    //printf("Going back to client main()\n");
}

void receive_file(int sock, FILE *f) {
    long file_size=0;
    int nbytes = 0;
    
    recv(sock, &file_size, sizeof(file_size), 0); //Receive size of file of part x
	printf("Reciving file size of %ld\n Now get the data!!! ", file_size);
	char *buf = (char *)malloc(file_size);
    nbytes = recv(sock, buf, file_size, 0);
        
	fwrite(buf, 1, nbytes, f);

	free(buf);
	file_size = 0;
    fclose(f);
}


void new_get(int sock[], packet_t packet) {
    //char message[MAXBUFSIZE];
    char buffer[MAXBUFSIZE];
	char file_name[32];
	strcpy(file_name, packet.filename);

    //snprintf(message, MAXBUFSIZE, "%s %s %d", "GET", path, 0);
    
    int fileparts[4] = {0,0,0,0};
    
    int offlineServerCount =0;
    int completeFile = 1;
    FILE *f;
    
    for(int i=0; i<4; i++) {
        if(sock[i] == -1) {
            offlineServerCount++;
        }
    }
    //printf("offline: %d\n", offlineServerCount);
    if(offlineServerCount>=3) {
        completeFile = 0;
    }
    if(completeFile) {
        int hash;

        for(int i = 0; i < 4; i++) {
            if(sock[i] != -1) {
            send(sock[i], &packet, sizeof(packet), 0);
			
            if (recv(sock[i], &fileparts[i], sizeof(fileparts[i]), 0) < 0) {
				printf("REcieved part number\n");
			}
            }
            printf("fileparts: %d\n", fileparts[i]);
        }
        
        if(fileparts[0] == 12 || fileparts[1] == 23 || fileparts[2] == 34 || fileparts[3] == 14) {
            hash = 0;
        }
        else if(fileparts[1] == 12 || fileparts[2] == 23 || fileparts[3] == 34 || fileparts[0] == 14) {
            hash = 1;
        }
        else if(fileparts[2] == 12 || fileparts[3] == 23 || fileparts[0] == 34 || fileparts[1] == 14) {
            hash = 2;
        }
        else {
            hash = 3;
        }
        printf("hash client: %d\n", hash);


        switch(hash) {
            case 0:
               
                if(sock[0] != -1 && sock[2] != -1) {
                    //Parts 1 and 2
                    //printf("Writing in file\n");
					int request = 1;
					send(sock[0], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[0], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                    //Parts 3 and 4
                    send(sock[2], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                }
				else {
                if(sock[1] != -1 && sock[3] != -1) {
                    //Parts 1 and 2
                    //printf("Writing in file\n");
					int request = 1;
                    send(sock[3], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[3], f);
                    send(sock[1], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    //Parts 3 and 4
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[3], f);
                }
				}
                break;
            case 1:
                
                if(sock[0] != -1 && sock[2] != -1) {
                    //Parts 1 and 2
                    printf("Writing in file from case 1 of if\n");
					int request = 1;
					send(sock[0], &request, sizeof(int), 0);	
                    f = fopen(file_name, "w+b");
                    receive_file(sock[0], f);
					send(sock[2], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                    //Parts 3 and 4
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                }
                else {
					if (sock[1] != -1 && sock[3] != -1) {
                    //Parts 1 and 2
                    printf("Writing in file from case 2 of else\n");
					int request = 1;
                    send(sock[3], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[3], f);
                    send(sock[1], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    //Parts 3 and 4
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[3], f);
                }
				}
                break;
            
            case 2:
                
                if(sock[0] != -1 && sock[2] != -1) {
                    //Parts 1 and 2
                    //printf("Writing in file\n");
					int request = 1;
                    send(sock[2], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[2], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                    //Parts 3 and 4
                    send(sock[0], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                }
				else {
                if(sock[1] != -1 && sock[3] != -1) {
                    //Parts 1 and 2
					int request = 1;
                    send(sock[1], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[1], f);
                    send(sock[3], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[3], f);
                    //Parts 3 and 4
                    f = fopen(file_name, "ab");
                    receive_file(sock[3], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                }
				}
                break;
            
            case 3:
                // (2,3) (3,4) (4,1) (1,2)
                if(sock[0] != -1 && sock[2] != -1) {
                    //Parts 1 and 2
					int request = 1;
                    send(sock[2], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[2], f);
                    send(sock[0], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                    //Parts 3 and 4
                    f = fopen(file_name, "ab");
                    receive_file(sock[0], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[2], f);
                    f = fopen(file_name, "rb");
                    fgets(buffer, MAXBUFSIZE, f);
                    printf("Buffer: %s\n", buffer);
                }
				else {
                if(sock[1] != -1 && sock[3] != -1) {
                    //Parts 1 and 2
					int request = 1;
                    send(sock[3], &request, sizeof(int), 0);
                    f = fopen(file_name, "w+b");
                    receive_file(sock[3], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[3], f);
                    //Parts 3 and 4
                    send(sock[1], &request, sizeof(int), 0);
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    f = fopen(file_name, "ab");
                    receive_file(sock[1], f);
                    f = fopen(file_name, "rb");
                    fgets(buffer, MAXBUFSIZE, f);
                    printf("Buffer: %s\n", buffer);
                }
				}
                break;
        }
    }
    else {
        printf("File is incomplete, cannot be downloaded from server.\n");
    }
}


int main(int argc, char **argv)
{
	if ((argc < 2) || (argc > 2)) {
        printf("Usage --> ./[%s] [Configuration File]\n", argv[0]);    //Should have a port number > 5000
        exit(EXIT_FAILURE);
    }

	struct sockaddr_in sock[4];
	struct stat st;
	struct timeval timeout = {1,0};
	struct files fileList;
	packet_t packet;
	FILE *fptr;

	char user_input[50], cmd_send[128], subdir[30];
	char auth_resp[256];
	unsigned char md5 = 3;

	int packet_part[4][4][2] = {{{3,0},{0,1},{1,2},{2,3}},
								{{0,1},{1,2},{2,3},{3,0}},
								{{1,2},{2,3},{3,0},{0,1}},
								{{2,3},{3,0},{0,1},{1,2}}};

	int option = 1, auth_success = 0, i = 0, msg_accepted = 0;
    ssize_t length;

	if (parse_ConfigFile(argv[1]) == -1)
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
		clear_buffer(cmd_send, auth_resp, user_input, subdir);
		memset(&packet, 0, sizeof(packet));
		memset(&fileList, 0, sizeof(fileList));
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

			sscanf(user_input, "%s %s %s", packet.command, packet.filename, subdir);
			snprintf(packet.cred, 128, "%s %s", credential.u_name, credential.password);

			if (strcmp(packet.command, "list") == 0 || strcmp(packet.command, "mkdir") == 0)
			{
				if ((packet.filename[strlen(packet.filename)-1]) != '/'  && strlen(packet.filename)) {
					//packet.filename[strlen(packet.filename)] = '/';
				}
				sprintf(packet.subfolder, "%s", packet.filename);
			}
			else {
				if((subdir[strlen(subdir)-1]) != '/' && strlen(subdir)) {
					//subdir[strlen(subdir)] = '/';
				}
	    		sprintf(packet.subfolder, "%s", subdir);  
    		}

			printf("Subfolder path %s\n", packet.subfolder);

			if (((strcmp(packet.command, "put")) == 0) && (*(packet.filename) != '\0'))
			{
				printf("Command --> %s	%s\n", packet.command, packet.filename);
				fptr = fopen(packet.filename, "rb");
				if (fptr == NULL) {
					printf("Wrong File name\n");
				}
				else {
					stat(packet.filename, &st);
					size_t f_size = st.st_size; 		//Size of the file
					printf("File Size = %ld\n", f_size);

					md5 = file_md5_counter(packet.filename, f_size, fptr);

					float f_data = f_size;
					f_data = (f_data/4);
					int file_part = round(f_data);

					for (packet.file_part = 0; packet.file_part < 4; packet.file_part++)
					{
						char *buf = NULL;

						if (packet.file_part == 3) {
							packet.file_size = (f_size - file_part*3);
							buf = (char *)malloc(packet.file_size);
						}
						else {
							packet.file_size = (file_part);
							buf = (char *)malloc(packet.file_size);
						}

						fread(buf, 1, packet.file_size, fptr);
						printf("\n\nSending %d part of file of Size	- %ld\n", (packet.file_part + 1), packet.file_size);

						int j = 0;
						for (j = 0; j < 2; j++)
						{
							send(dfs[packet_part[md5][packet.file_part][j]], &packet, sizeof(packet), 0);
							printf("Transfering file to dfs[%d]\n", packet_part[md5][packet.file_part][j]);
							msg_accepted = 0;
							read(dfs[packet_part[md5][packet.file_part][j]], &msg_accepted, sizeof(int));
							//printf("Message Accepted while sending the packet = %d\n", msg_accepted);

							if (msg_accepted) {
								printf("Server in working status\n");
							
								int byteread;
								if (byteread = send(dfs[packet_part[md5][packet.file_part][j]], buf, packet.file_size, 0) < 0)
									printf("Client: File send failed\n");

								//printf("read - %d	Buf - %s	strlen	-	%ld\n", byteread, buf, strlen(buf));
        						timeout.tv_sec = 1;
								timeout.tv_usec = 0;
								setsockopt(dfs[packet_part[md5][packet.file_part][j]], SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(struct timeval)); //Set timeout option for send                  
                          		msg_accepted = 0;
							  	read(dfs[packet_part[md5][packet.file_part][j]], &msg_accepted, sizeof(int));
								timeout.tv_sec = 1;
                            	timeout.tv_usec = 0;
                            	setsockopt(dfs[packet_part[md5][packet.file_part][j]], SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(struct timeval)); //Set timeout option for recv 
								//printf("Message Accepted while sending the buffer = %d\n", msg_accepted);
							}
							else {
                                printf("Server not in a working status. Please try again\n");
                                //exit(1);
                            }
						}
						free(buf);
					}
					printf("File sent\n");
				}
			}//put_end
			else if (((strcmp(packet.command, "get")) == 0) && (*(packet.filename) != '\0'))
			{
				new_get(dfs, packet);
			}
			else if (((strcmp(packet.command, "list")) == 0))
			{
				list(dfs, &fileList, packet);
			}
			else if (((strcmp(packet.command, "mkdir")) == 0))
			{

			}
			else if (((strcmp(packet.command, "exit")) == 0))
			{
				close(dfs[0]);
    			close(dfs[1]);
    			close(dfs[2]);
    			close(dfs[3]);
				exit(0);
			}
			else {
				printf("Invalid Command\n");
			}

			
			//clear_buffer(u_name, passkey, path, subpath, mkdir_path);
			memset(&packet, 0, sizeof(packet));
			memset(&fileList, 0, sizeof(fileList));
			auth_success = 1;
		} //else_end
	} //while_end

	close(dfs[0]);
	close(dfs[1]);
	close(dfs[2]);
	close(dfs[3]);

	return 0;
}
