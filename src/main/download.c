#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    int err = 0;
    const char *hostname = "www.unicode.org";
    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.1\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    struct addrinfo *res, *res0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((err = getaddrinfo(hostname, "http", &hints, &res0))) {
        printf("error %s", gai_strerror(err));
        // error
    }

    int sockfd = -1;
    for (res = res0; res; res = res->ai_next) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            // socket failed
            continue;
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
            // connect failed
            close(sockfd);
            sockfd = -1;
            continue;
        }

        printf("success!\n");
        break; // success
    }

    send(sockfd, message, strlen(message), 0);

    char response[4096];
    memset(response, 0, sizeof(response));
    int total = sizeof(response)-1;
    int received = 0;
    int bytes = 0;
    do {
        bytes = recv(sockfd, response, total, 0);
        if (bytes < 0)
            printf("ERROR reading response from socket");
        printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    freeaddrinfo(res0);
    shutdown(sockfd, 2); // 0 = stop recv; 1 = stop send; 2 = stop both
    close(sockfd);

    return 0;
}
