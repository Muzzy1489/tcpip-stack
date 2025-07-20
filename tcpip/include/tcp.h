#ifndef TCP_H
#define TCP_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define TCP_MAX_SEGMENT_SIZE 1460

// TCP states
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

struct tcp_segment {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags; // SYN, ACK, FIN, etc.
    uint16_t window_size;
    uint8_t *payload;
    size_t payload_len;
};

// TCP socket handle
typedef int tcp_sock_t;

// TCP API
int tcp_listen(uint16_t port);
tcp_sock_t tcp_accept(int listen_sock);
tcp_sock_t tcp_connect(const char *ip, uint16_t port);
ssize_t tcp_send(tcp_sock_t sock, const void *buf, size_t len);
ssize_t tcp_recv(tcp_sock_t sock, void *buf, size_t len);
int tcp_close(tcp_sock_t sock);

#endif // TCP_H 