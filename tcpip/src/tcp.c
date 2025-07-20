#include "tcp.h"
#include "ip.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>

// TCP flag definitions
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define MAX_TCP_SOCKETS 16
#define INITIAL_SEQ 1000
#define TCP_MAX_SEGMENT_SIZE 1460 // MTU - IP header (20) - TCP header (20) = 1460
#define INITIAL_WINDOW_SIZE 4096
#define INITIAL_CWND 1460
#define MAX_WINDOW_SIZE 65535

// Timeout and retransmission constants
#define INITIAL_RTO_MS 1000  // 1 second initial timeout
#define MAX_RTO_MS 60000     // 60 second max timeout
#define MIN_RTO_MS 200       // 200ms minimum timeout
#define ALPHA 0.125          // RTT smoothing factor
#define BETA 0.25            // RTT variation factor

// Pending segment for retransmission
struct pending_segment {
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;
    uint8_t *payload;
    size_t payload_len;
    struct timeval send_time;
    int retransmit_count;
};

struct tcp_sock {
    tcp_state_t state;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t remote_ip[4];
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t peer_seq_num;
    
    // Sliding window and congestion control
    uint32_t send_window;         // Flow control window (from peer)
    uint32_t congestion_window;   // Congestion window (AIMD)
    uint32_t recv_window;         // Our advertised window
    uint32_t unacked_seq;         // Oldest unacknowledged seq
    
    // Timeout and retransmission
    int rto_ms;                    // Retransmission timeout
    int srtt_ms;                   // Smoothed RTT
    int rttvar_ms;                 // RTT variation
    struct pending_segment pending; // Last unacknowledged segment
    int dup_ack_count;             // Duplicate ACK counter
    uint32_t last_ack_num;         // Last ACK number received
};

// Forward declarations
static int send_tcp_segment(struct tcp_sock *sock, uint8_t flags, uint32_t seq, uint32_t ack, const void *payload, size_t plen);
static int recv_tcp_segment(struct tcp_sock *sock, struct tcp_segment *seg, int timeout_ms);

static struct tcp_sock tcp_table[MAX_TCP_SOCKETS];
static int tcp_table_used[MAX_TCP_SOCKETS] = {0};

// Update alloc_tcp_sock to initialize window variables
static int alloc_tcp_sock() {
    for (int i = 0; i < MAX_TCP_SOCKETS; ++i) {
        if (!tcp_table_used[i]) {
            tcp_table_used[i] = 1;
            memset(&tcp_table[i], 0, sizeof(struct tcp_sock));
            tcp_table[i].rto_ms = INITIAL_RTO_MS;
            tcp_table[i].send_window = INITIAL_WINDOW_SIZE;
            tcp_table[i].congestion_window = INITIAL_CWND;
            tcp_table[i].recv_window = INITIAL_WINDOW_SIZE;
            tcp_table[i].unacked_seq = INITIAL_SEQ;
            return i;
        }
    }
    return -1;
}

static void free_tcp_sock(int idx) {
    if (idx >= 0 && idx < MAX_TCP_SOCKETS) {
        if (tcp_table[idx].pending.payload) {
            free(tcp_table[idx].pending.payload);
        }
        tcp_table_used[idx] = 0;
    }
}

// Get current time in milliseconds
static int64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Update RTT and timeout when ACK is received
static void update_rtt(struct tcp_sock *sock, int rtt_ms) {
    if (sock->srtt_ms == 0) {
        // First RTT measurement
        sock->srtt_ms = rtt_ms;
        sock->rttvar_ms = rtt_ms / 2;
    } else {
        // Update smoothed RTT and variation
        sock->rttvar_ms = (1 - BETA) * sock->rttvar_ms + BETA * abs(rtt_ms - sock->srtt_ms);
        sock->srtt_ms = (1 - ALPHA) * sock->srtt_ms + ALPHA * rtt_ms;
    }
    
    // Calculate new timeout
    sock->rto_ms = sock->srtt_ms + 4 * sock->rttvar_ms;
    if (sock->rto_ms < MIN_RTO_MS) sock->rto_ms = MIN_RTO_MS;
    if (sock->rto_ms > MAX_RTO_MS) sock->rto_ms = MAX_RTO_MS;
}

// Check if pending segment has timed out
static int is_timeout(struct tcp_sock *sock) {
    if (sock->pending.payload == NULL) return 0;
    int64_t now = get_time_ms();
    int64_t send_time = (int64_t)sock->pending.send_time.tv_sec * 1000 + 
                        sock->pending.send_time.tv_usec / 1000;
    return (now - send_time) > sock->rto_ms;
}

// Retransmit pending segment
static int retransmit_segment(struct tcp_sock *sock) {
    if (sock->pending.payload == NULL) return 0;
    
    sock->pending.retransmit_count++;
    gettimeofday(&sock->pending.send_time, NULL);
    
    printf("[tcp] retransmitting segment (seq=%u, retry=%d, rto=%dms)\n", 
           sock->pending.seq_num, sock->pending.retransmit_count, sock->rto_ms);
    
    // Exponential backoff for timeout
    if (sock->pending.retransmit_count > 1) {
        sock->rto_ms *= 2;
        if (sock->rto_ms > MAX_RTO_MS) sock->rto_ms = MAX_RTO_MS;
    }
    
    return send_tcp_segment(sock, sock->pending.flags, 
                           sock->pending.seq_num, sock->pending.ack_num,
                           sock->pending.payload, sock->pending.payload_len);
}

// Store segment for potential retransmission
static void store_pending_segment(struct tcp_sock *sock, uint8_t flags, 
                                 uint32_t seq, uint32_t ack, 
                                 const void *payload, size_t plen) {
    // Free previous pending segment
    if (sock->pending.payload) {
        free(sock->pending.payload);
    }
    
    sock->pending.seq_num = seq;
    sock->pending.ack_num = ack;
    sock->pending.flags = flags;
    sock->pending.payload_len = plen;
    sock->pending.retransmit_count = 0;
    gettimeofday(&sock->pending.send_time, NULL);
    
    if (plen > 0 && payload) {
        sock->pending.payload = malloc(plen);
        memcpy(sock->pending.payload, payload, plen);
    } else {
        sock->pending.payload = NULL;
    }
}

// Clear pending segment when ACK is received
static void clear_pending_segment(struct tcp_sock *sock) {
    if (sock->pending.payload) {
        free(sock->pending.payload);
        sock->pending.payload = NULL;
    }
}

// Serialize a TCP segment into a buffer
size_t tcp_serialize_segment(const struct tcp_segment *seg, uint8_t *buf, size_t buflen) {
    if (!seg || !buf || buflen < 20 + seg->payload_len) return 0;
    // 20 bytes header: src_port(2), dst_port(2), seq(4), ack(4), flags(1), window(2), payload_len(2), reserved(3)
    uint16_t sp = htons(seg->src_port);
    uint16_t dp = htons(seg->dst_port);
    uint32_t seq = htonl(seg->seq_num);
    uint32_t ack = htonl(seg->ack_num);
    uint16_t win = htons(seg->window_size);
    uint16_t plen = htons((uint16_t)seg->payload_len);
    memcpy(buf, &sp, 2);
    memcpy(buf+2, &dp, 2);
    memcpy(buf+4, &seq, 4);
    memcpy(buf+8, &ack, 4);
    buf[12] = seg->flags;
    memcpy(buf+13, &win, 2);
    memcpy(buf+15, &plen, 2);
    memset(buf+17, 0, 3); // reserved
    if (seg->payload && seg->payload_len > 0)
        memcpy(buf+20, seg->payload, seg->payload_len);
    return 20 + seg->payload_len;
}

// Deserialize a TCP segment from a buffer
int tcp_deserialize_segment(struct tcp_segment *seg, const uint8_t *buf, size_t buflen) {
    if (!seg || !buf || buflen < 20) return -1;
    memset(seg, 0, sizeof(*seg));
    seg->src_port = ntohs(*(uint16_t*)(buf));
    seg->dst_port = ntohs(*(uint16_t*)(buf+2));
    seg->seq_num = ntohl(*(uint32_t*)(buf+4));
    seg->ack_num = ntohl(*(uint32_t*)(buf+8));
    seg->flags = buf[12];
    seg->window_size = ntohs(*(uint16_t*)(buf+13));
    seg->payload_len = ntohs(*(uint16_t*)(buf+15));
    // skip reserved (3 bytes)
    if (seg->payload_len > 0 && buflen >= 20 + seg->payload_len && seg->payload_len < 2048) {
        seg->payload = malloc(seg->payload_len);
        if (!seg->payload) return -1;
        memcpy(seg->payload, buf+20, seg->payload_len);
    } else {
        seg->payload = NULL;
        if (seg->payload_len > 0) return -1; // invalid/corrupt packet
    }
    return 0;
}

// Helper: send a TCP segment via IP with retransmission support
static int send_tcp_segment(struct tcp_sock *sock, uint8_t flags, uint32_t seq, uint32_t ack, const void *payload, size_t plen) {
    struct tcp_segment seg = {0};
    seg.src_port = sock->local_port;
    seg.dst_port = sock->remote_port;
    seg.seq_num = seq;
    seg.ack_num = ack;
    seg.flags = flags;
    // Piggyback our advertised window size
    seg.window_size = (uint16_t)(sock->recv_window > MAX_WINDOW_SIZE ? MAX_WINDOW_SIZE : sock->recv_window);
    seg.payload = (uint8_t*)payload;
    seg.payload_len = plen;
    uint8_t buf[1500];
    size_t seglen = tcp_serialize_segment(&seg, buf, sizeof(buf));
    struct ip_packet pkt = {0};
    memcpy(pkt.src.addr, "\x7f\x00\x00\x01", 4); // 127.0.0.1
    memcpy(pkt.dst.addr, sock->remote_ip, 4);
    pkt.protocol = 6; // TCP
    pkt.payload = buf;
    pkt.payload_len = seglen;
    
    // Store for retransmission if it's a data segment
    if (flags & TCP_FLAG_PSH) {
        store_pending_segment(sock, flags, seq, ack, payload, plen);
    }
    
    return ip_send(&pkt);
}

// Helper: receive a TCP segment via IP with timeout handling
static int recv_tcp_segment(struct tcp_sock *sock, struct tcp_segment *seg, int timeout_ms) {
    struct ip_packet pkt = {0};
    int n = ip_recv(&pkt, timeout_ms);
    if (n <= 0) return n;
    int ret = tcp_deserialize_segment(seg, pkt.payload, pkt.payload_len);
    if (ret != 0) {
        free(pkt.payload);
        return ret;
    }
    
    // Check if this segment is for this socket
    // For listening sockets, accept any SYN to our port
    if (sock->state == TCP_LISTEN) {
        if (seg->dst_port != sock->local_port) {
            printf("[tcp] recv_tcp_segment: packet dst_port %u != listen_port %u, dropping\n", seg->dst_port, sock->local_port);
            free(pkt.payload);
            return -1;
        }
    } else {
        // For established sockets, check both local and remote ports
        if (seg->dst_port != sock->local_port || seg->src_port != sock->remote_port) {
            printf("[tcp] recv_tcp_segment: packet mismatch (dst=%u,src=%u) != socket (local=%u,remote=%u), dropping\n", 
                   seg->dst_port, seg->src_port, sock->local_port, sock->remote_port);
            free(pkt.payload);
            return -1;
        }
    }
    
    free(pkt.payload);
    return 0;
}

int tcp_listen(uint16_t port) {
    int idx = alloc_tcp_sock();
    if (idx < 0) return -1;
    tcp_table[idx].state = TCP_LISTEN;
    tcp_table[idx].local_port = port;
    printf("[tcp] listen on port %u (sock=%d)\n", port, idx);
    return idx;
}

tcp_sock_t tcp_accept(int listen_sock) {
    struct tcp_sock *lsock = &tcp_table[listen_sock];
    if (lsock->state != TCP_LISTEN) return -1;
    printf("[tcp] waiting for SYN...\n");
    struct tcp_segment seg;
    while (1) {
        if (recv_tcp_segment(lsock, &seg, 5000) == 0) {
            if (seg.flags & TCP_FLAG_SYN) {
                // Accept connection
                int idx = alloc_tcp_sock();
                if (idx < 0) return -1;
                struct tcp_sock *csock = &tcp_table[idx];
                csock->state = TCP_SYN_RECEIVED;
                csock->local_port = lsock->local_port;
                csock->remote_port = seg.src_port;
                memcpy(csock->remote_ip, "\x7f\x00\x00\x01", 4); // only localhost for now
                csock->seq_num = INITIAL_SEQ;
                csock->peer_seq_num = seg.seq_num;
                csock->ack_num = seg.seq_num + 1;
                // Send SYN-ACK and store for retransmission
                send_tcp_segment(csock, TCP_FLAG_SYN | TCP_FLAG_ACK, csock->seq_num, csock->ack_num, NULL, 0);
                store_pending_segment(csock, TCP_FLAG_SYN | TCP_FLAG_ACK, csock->seq_num, csock->ack_num, NULL, 0);
                printf("[tcp] sent SYN-ACK, waiting for ACK...\n");
                // Wait for ACK with retransmission
                int retry_count = 0;
                const int max_retries = 5;
                while (retry_count < max_retries) {
                    if (recv_tcp_segment(csock, &seg, csock->rto_ms) == 0) {
                        if ((seg.flags & TCP_FLAG_ACK) && seg.ack_num == csock->seq_num + 1) {
                            clear_pending_segment(csock);
                            csock->state = TCP_ESTABLISHED;
                            printf("[tcp] connection established (sock=%d)\n", idx);
                            return idx;
                        }
                    } else {
                        // Timeout, retransmit SYN-ACK
                        retry_count++;
                        if (retry_count < max_retries) {
                            printf("[tcp] SYN-ACK timeout, retransmitting (retry %d/%d)...\n", retry_count, max_retries);
                            retransmit_segment(csock);
                        }
                    }
                }
                printf("[tcp] SYN-ACK retransmission failed\n");
                free_tcp_sock(idx);
            }
        } else {
            break;
        }
    }
    return -1;
}

tcp_sock_t tcp_connect(const char *ip, uint16_t port) {
    (void)ip; // silence unused parameter warning
    int idx = alloc_tcp_sock();
    if (idx < 0) return -1;
    struct tcp_sock *sock = &tcp_table[idx];
    sock->state = TCP_SYN_SENT;
    sock->local_port = 10000 + (rand() % 1000); // random local port
    sock->remote_port = port;
    // Only support 127.0.0.1 for now
    memcpy(sock->remote_ip, "\x7f\x00\x00\x01", 4);
    sock->seq_num = INITIAL_SEQ;
    // Send SYN and store for retransmission
    send_tcp_segment(sock, TCP_FLAG_SYN, sock->seq_num, 0, NULL, 0);
    store_pending_segment(sock, TCP_FLAG_SYN, sock->seq_num, 0, NULL, 0);
    printf("[tcp] sent SYN, waiting for SYN-ACK...\n");
    struct tcp_segment seg;
    int retry_count = 0;
    const int max_retries = 5;
    while (retry_count < max_retries) {
        if (recv_tcp_segment(sock, &seg, sock->rto_ms) == 0) {
            if ((seg.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                clear_pending_segment(sock);
                sock->ack_num = seg.seq_num + 1;
                sock->peer_seq_num = seg.seq_num;
                // Send ACK
                send_tcp_segment(sock, TCP_FLAG_ACK, sock->seq_num + 1, sock->ack_num, NULL, 0);
                sock->state = TCP_ESTABLISHED;
                printf("[tcp] connection established (sock=%d)\n", idx);
                return idx;
            }
        } else {
            // Timeout, retransmit SYN
            retry_count++;
            if (retry_count < max_retries) {
                printf("[tcp] SYN timeout, retransmitting (retry %d/%d)...\n", retry_count, max_retries);
                retransmit_segment(sock);
            }
        }
    }
    printf("[tcp] SYN retransmission failed\n");
    free_tcp_sock(idx);
    return -1;
}

ssize_t tcp_send(tcp_sock_t sock, const void *buf, size_t len) {
    struct tcp_sock *tsock = &tcp_table[sock];
    if (tsock->state != TCP_ESTABLISHED) return -1;
    
    // Check for timeout and retransmit if needed
    if (is_timeout(tsock)) {
        retransmit_segment(tsock);
    }
    
    // Simple segmentation: send data in chunks
    size_t sent = 0;
    const uint8_t *data = (const uint8_t*)buf;
    while (sent < len) {
        uint32_t window = tsock->send_window < tsock->congestion_window ? tsock->send_window : tsock->congestion_window;
        uint32_t in_flight = tsock->seq_num - tsock->unacked_seq;
        if (in_flight >= window) {
            // Window full, wait for ACKs
            printf("[tcp] window full (in_flight=%u, window=%u), waiting for ACK...\n", in_flight, window);
            struct tcp_segment seg;
            if (recv_tcp_segment(tsock, &seg, tsock->rto_ms) < 0) return sent;
            if (seg.flags & TCP_FLAG_ACK && seg.ack_num > tsock->unacked_seq) {
                tsock->unacked_seq = seg.ack_num;
                // AIMD: increase congestion window additively
                tsock->congestion_window += TCP_MAX_SEGMENT_SIZE;
                if (tsock->congestion_window > MAX_WINDOW_SIZE) tsock->congestion_window = MAX_WINDOW_SIZE;
                printf("[tcp] congestion window increased to %u\n", tsock->congestion_window);
            }
            if (seg.payload) free(seg.payload);
            continue;
        }
        size_t chunk = (len - sent > TCP_MAX_SEGMENT_SIZE) ? TCP_MAX_SEGMENT_SIZE : (len - sent);
        int ret = send_tcp_segment(tsock, TCP_FLAG_PSH | TCP_FLAG_ACK, 
                                  tsock->seq_num, tsock->ack_num, 
                                  data + sent, chunk);
        if (ret < 0) return -1;
        tsock->seq_num += chunk;
        sent += chunk;
        printf("[tcp] sent %u bytes (seq=%u, cwnd=%u, swnd=%u)\n", (unsigned int)chunk, tsock->seq_num - chunk, tsock->congestion_window, tsock->send_window);
    }
    return (ssize_t)sent;
}

ssize_t tcp_recv(tcp_sock_t sock, void *buf, size_t len) {
    struct tcp_sock *tsock = &tcp_table[sock];
    if (tsock->state != TCP_ESTABLISHED) return -1;
    
    // Check for timeout and retransmit if needed
    if (is_timeout(tsock)) {
        retransmit_segment(tsock);
    }
    
    struct tcp_segment seg;
    int ret = recv_tcp_segment(tsock, &seg, 5000); // 5 second timeout
    if (ret < 0) {
        printf("[tcp] tcp_recv: recv_tcp_segment returned %d\n", ret);
        return -1;
    }
    
    // Update send_window from peer's advertised window
    tsock->send_window = seg.window_size * TCP_MAX_SEGMENT_SIZE;

    printf("[tcp] tcp_recv: received segment flags=0x%02x, seq=%u, ack=%u, payload_len=%zu\n", seg.flags, seg.seq_num, seg.ack_num, seg.payload_len);

    if (seg.flags & TCP_FLAG_ACK) {
        // Handle ACK for our sent data
        if (tsock->pending.payload && seg.ack_num > tsock->last_ack_num) {
            int64_t rtt_ms = get_time_ms() - 
                ((int64_t)tsock->pending.send_time.tv_sec * 1000 + 
                 tsock->pending.send_time.tv_usec / 1000);
            update_rtt(tsock, (int)rtt_ms);
            clear_pending_segment(tsock);
            tsock->dup_ack_count = 0;
            printf("[tcp] ACK received (ack=%u, rtt=%dms, rto=%dms)\n", 
                   seg.ack_num, (int)rtt_ms, tsock->rto_ms);
        } else if (seg.ack_num == tsock->last_ack_num) {
            tsock->dup_ack_count++;
            printf("[tcp] duplicate ACK %d (ack=%u)\n", tsock->dup_ack_count, seg.ack_num);
            if (tsock->dup_ack_count >= 3 && tsock->pending.payload) {
                printf("[tcp] fast retransmit triggered\n");
                tsock->congestion_window /= 2;
                if (tsock->congestion_window < TCP_MAX_SEGMENT_SIZE) tsock->congestion_window = TCP_MAX_SEGMENT_SIZE;
                retransmit_segment(tsock);
            }
        }
        tsock->last_ack_num = seg.ack_num;
    }
    
    if (seg.flags & TCP_FLAG_PSH) {
        size_t copy_len = (seg.payload_len < len) ? seg.payload_len : len;
        if (seg.payload && copy_len > 0) {
            memcpy(buf, seg.payload, copy_len);
            tsock->ack_num = seg.seq_num + seg.payload_len;
            send_tcp_segment(tsock, TCP_FLAG_ACK, tsock->seq_num, tsock->ack_num, NULL, 0);
            printf("[tcp] received %zu bytes (seq=%u, ack=%u, adv_win=%u)\n", copy_len, seg.seq_num, tsock->ack_num, tsock->recv_window);
            free(seg.payload);
            seg.payload = NULL;
            return (ssize_t)copy_len;
        } else {
            printf("[tcp] tcp_recv: PSH segment with no payload or zero copy_len (payload=%p, copy_len=%zu)\n", seg.payload, copy_len);
        }
    } else {
        printf("[tcp] tcp_recv: segment did not have PSH flag\n");
    }
    if (seg.payload) {
        free(seg.payload);
        seg.payload = NULL;
    }
    return 0;
} 