/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/21, create
 */

# include <stdio.h>  
# include <stdlib.h>  
# include <errno.h>  
# include <error.h>
# include <unistd.h>
# include <string.h>  
# include <sys/stat.h>  
# include <sys/socket.h>  
# include <sys/un.h>  
#include <jemalloc/jemalloc.h>
int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("usage: %s path\n", argv[0]);
        exit(0);
    }

    int sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd < 0)
        error(1, errno, "socket fail");

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, argv[1], sizeof(un.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&un, sizeof(un)) < 0) {
        error(1, errno, "conect fail");
    }

    char *line = NULL;
    size_t buf_size = 0;
    while (getline(&line, &buf_size, stdin) != -1) {
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (struct sockaddr *)&un;
        msg.msg_namelen = sizeof(un);
        struct iovec io;
        io.iov_base = line;
        io.iov_len = strlen(line);
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;

        int ret = sendmsg(sockfd, &msg, 0);
        if (ret < 0) {
            error(1, errno, "sendmsg fail");
        }

        char buf[10240];
        struct sockaddr_un peer;
        msg.msg_name = (struct sockaddr *)&peer;
        msg.msg_namelen = sizeof(peer);
        io.iov_base = buf;
        io.iov_len = sizeof(buf);
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        ret = recvmsg(sockfd, &msg, 0);
        if (ret < 0) {
            error(1, errno, "recvmsg fail");
        }
        buf[ret] = 0;
        printf("%s", buf);
    }

    close(sockfd);

    return 0;
}

