#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>

#define IP_ADDR_LEN 4
#define IP_MAX_PACKET_SIZE 1500

struct ip_addr {
    uint8_t addr[IP_ADDR_LEN];
};

struct ip_packet {
    struct ip_addr src;
    struct ip_addr dst;
    uint8_t protocol; // e.g., 6 for TCP
    uint8_t *payload;
    size_t payload_len;
};

// Send an IP packet
int ip_send(const struct ip_packet *pkt);

// Receive an IP packet
int ip_recv(struct ip_packet *pkt, int timeout_ms);

int ip_init(uint16_t local_port, const char *remote_addr, uint16_t remote_port);

#endif // IP_H 