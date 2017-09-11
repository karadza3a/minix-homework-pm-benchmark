#include <sys/cdefs.h>
#include <lib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

int BUFF_SIZE = 10240;

int login_ok(char *username, char *password) {
    message m;
    m.hss_command = username;
    m.hss_result = password;

    int e = _syscall(HSS_PROC_NR, HSS_RUN, &m);
    return e;
}

void run_remotely(char *command, char *result) {
    FILE *f;
    if ((f = popen(command, "r")) != NULL) {
        /* Read one byte at a time, up to BUFF_SIZE - 1 bytes, the last byte will be used for null termination. */
        size_t byte_count = fread(result, 1, BUFF_SIZE - 1, f);
        /* Apply null termination so that the read bytes can be treated as a string. */
        result[byte_count] = 0;
    }
    (void) pclose(f);
}

void get_host_port(char *host, int *port) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/remote.conf", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    int row = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        for (unsigned int j = 0; j < len; j++)
            if (line[j] == 10 || line[j] == 13)
                line[j] = '\0';
        if (row == 0)
            strcpy(host, line);
        else if (row == 1) {
            *port = atoi(line);
            break;
        }
        ++row;
    }

    fclose(fp);
    if (line)
        free(line);
}

void get_creds(char *username, char *password) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/remote.conf", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    int i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        for (unsigned int j = 0; j < len; j++)
            if (line[j] == 10 || line[j] == 13)
                line[j] = '\0';
            else if (i == 2)
                strcpy(username, line);
            else if (i == 3)
                strcpy(password, line);
        i++;
    }

    if (line)
        free(line);
    fclose(fp);
}

void start_listening(void) {
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    char buffer[BUFF_SIZE], username[BUFF_SIZE], password[BUFF_SIZE], command[BUFF_SIZE], result[BUFF_SIZE];
    int port = 0;
    get_host_port(buffer, &port);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    while (1) {
        connfd = accept(listenfd, (struct sockaddr *) NULL, NULL);
        int r;
        while (1) {
            bzero(buffer, BUFF_SIZE);
            bzero(result, BUFF_SIZE);
            r = read(connfd, buffer, BUFF_SIZE);
            if (read == 0) {
                write(connfd, "FAILED", strlen("FAILED"));
                break;
            }

            for (int i = 0; i < BUFF_SIZE; i++)
                if (buffer[i] == 13 || buffer[i] == 10)
                    buffer[i] = 0;

            printf("%s\n", buffer);
            r = sscanf(buffer, "%[^:]:%[^>]>%[^$]$", username, password, command);
            if (r != 3) {
                write(connfd, "Invalid format!", strlen("Invalid format!"));
                break;
            }

            if (login_ok(username, password) == 0) {
                run_remotely(command, result);
                write(connfd, result, strlen(result));
            } else {
                write(connfd, "Invalid username or password", strlen("Invalid username or password"));
                break;
            }
        }
        close(connfd);
        sleep(1);
    }
}

void send_command_loop(void) {
    char host[BUFF_SIZE], username[BUFF_SIZE], password[BUFF_SIZE];
    int port = 0;
    get_host_port(host, &port);
    get_creds(username, password);


    int sock;
    struct sockaddr_in server;
    char message[BUFF_SIZE], server_reply[BUFF_SIZE];

    //Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
        return;
    }
    printf("Socket created\n");

    server.sin_addr.s_addr = inet_addr(host);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return;
    }

    printf("Connected\n");

    char *command = NULL;
    size_t len = 0;
    ssize_t read = 0;

    while (read != -1) {
        printf("Enter command: ");
        read = getline(&command, &len, stdin);
        for (unsigned int i = 0; i < len; ++i) {
            if (command[i] == 10 || command[i] == 13) {
                command[i] = 0;
                break;
            }
        }

        sprintf(message, "%s:%s>%s$", username, password, command);

        //Send some data
        if (send(sock, message, strlen(message), 0) < 0) {
            printf("Send failed\n");
            return;
        }

        //Receive a reply from the server
        bzero(server_reply, BUFF_SIZE);
        if (recv(sock, server_reply, BUFF_SIZE, 0) < 0) {
            printf("recv failed\\n");
            break;
        }
        printf("%s\n", server_reply);
    }
    free(command);
    close(sock);
}
