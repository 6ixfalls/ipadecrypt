#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define IPC_SOCKET_PATH "/var/mobile/Library/IPADDecrypt/companion.sock"
#define MAX_MESSAGE 512
#define IO_TIMEOUT_SECONDS 10

static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void usage(FILE *stream) {
    fprintf(stream,
            "usage: ipadc status\n"
            "       ipadc unlock < PIN\n"
            "       ipadc idle-acquire TTL_SECONDS\n"
            "       ipadc idle-renew TOKEN TTL_SECONDS\n"
            "       ipadc idle-release TOKEN\n");
}

int main(int argc, char **argv) {
    char request[MAX_MESSAGE];
    int length = -1;

    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        length = snprintf(request, sizeof(request), "status\n");
    } else if (argc == 2 && strcmp(argv[1], "unlock") == 0) {
        char pin[64];
        if (!fgets(pin, sizeof(pin), stdin)) {
            fprintf(stderr, "PIN required on stdin\n");
            return 2;
        }
        pin[strcspn(pin, "\r\n")] = '\0';
        length = snprintf(request, sizeof(request), "unlock\t%s\n", pin);
        memset(pin, 0, sizeof(pin));
    } else if (argc == 3 && strcmp(argv[1], "idle-acquire") == 0) {
        length = snprintf(request, sizeof(request), "idle-acquire\t%s\n", argv[2]);
    } else if (argc == 4 && strcmp(argv[1], "idle-renew") == 0) {
        length = snprintf(request, sizeof(request), "idle-renew\t%s\t%s\n", argv[2], argv[3]);
    } else if (argc == 3 && strcmp(argv[1], "idle-release") == 0) {
        length = snprintf(request, sizeof(request), "idle-release\t%s\n", argv[2]);
    } else {
        usage(stderr);
        return 2;
    }

    if (length < 0 || (size_t)length >= sizeof(request)) {
        fprintf(stderr, "request too long\n");
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    int no_sigpipe = 1;
    struct timeval timeout = {
        .tv_sec = IO_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                   &no_sigpipe, sizeof(no_sigpipe)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0) {
        fprintf(stderr, "configure socket: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, IPC_SOCKET_PATH, sizeof(address.sun_path));

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "companion unavailable: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    if (write_all(fd, request, (size_t)length) != 0) {
        fprintf(stderr, "send request: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    shutdown(fd, SHUT_WR);

    char response[MAX_MESSAGE];
    size_t used = 0;
    while (used + 1 < sizeof(response)) {
        ssize_t n = read(fd, response + used, sizeof(response) - used - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            fprintf(stderr, "read response: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    response[used] = '\0';

    if (strncmp(response, "OK\t", 3) == 0) {
        fputs(response + 3, stdout);
        return 0;
    }
    if (strncmp(response, "ERR\t", 4) == 0) {
        fputs(response + 4, stderr);
        return 1;
    }

    fprintf(stderr, "invalid companion response\n");
    return 1;
}
