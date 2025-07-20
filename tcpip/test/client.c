#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ip.h"
#include "tcp.h"

int main() {
    printf("Test client started.\n");
    // Initialize IP layer with 10% packet loss to test retransmission
    if (ip_init(9001, "127.0.0.1", 9000) != 0) {
        printf("IP init failed!\n");
        return 1;
    }
    // Connect to server using TCP
    int sock = tcp_connect("127.0.0.1", 5000);
    if (sock >= 0) {
        printf("TCP connection established! (sock=%d)\n", sock);
        
        // Send data to server (may trigger retransmission due to packet loss)
        const char *msg = "Hello, TCP! This is a test message from the client idiot.";
        ssize_t n = tcp_send(sock, msg, strlen(msg));
        if (n > 0) {
            printf("Sent to server: '%s' (%zd bytes)\n", msg, n);
        } else {
            printf("Failed to send data to server.\n");
        }
    } else {
        printf("TCP connect failed or timed out.\n");
    }
    return 0;
} 