#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ip.h"
#include "tcp.h"

int main() {
    printf("Test server started.\n");
    // Initialize IP layer (server: 9000, client: 9001)
    if (ip_init(9000, "127.0.0.1", 9001) != 0) {
        printf("IP init failed!\n");
        return 1;
    }
    // Listen for TCP connection
    int listen_sock = tcp_listen(5000);
    if (listen_sock < 0) {
        printf("TCP listen failed!\n");
        return 1;
    }
    printf("Waiting for TCP connection...\n");
    int conn_sock = tcp_accept(listen_sock);
    if (conn_sock >= 0) {
        printf("TCP connection established! (sock=%d)\n", conn_sock);
        
        // Receive data from client
        char buf[1024];
        ssize_t n = tcp_recv(conn_sock, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received from client: '%s' (%zd bytes)\n", buf, n);
        } else {
            printf("Failed to receive data from client.\n");
        }
    } else {
        printf("TCP accept failed or timed out.\n");
    }
    return 0;
} 