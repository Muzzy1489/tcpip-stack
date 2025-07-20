#include "ip.h"
#include "network_sim.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

// For now, use a static network_sim context (should be initialized/configured elsewhere)
static struct network_sim ip_net_sim;
static int ip_initialized = 0;

// Helper: initialize the network simulator (should be called before using ip_send/ip_recv)
int ip_init(uint16_t local_port, const char *remote_addr, uint16_t remote_port) {
    if (ip_initialized) return 0;
    // Disable packet loss for reliable testing
    int ret = network_sim_init(&ip_net_sim, local_port, remote_addr, remote_port, 0.0, 0, 0, 0);
    if (ret == 0) ip_initialized = 1;
    return ret;
}

int ip_send(const struct ip_packet *pkt) {
    if (!ip_initialized || !pkt || !pkt->payload || pkt->payload_len == 0) return -1;
    // Serialize IP header and payload
    uint8_t buf[IP_MAX_PACKET_SIZE];
    if (pkt->payload_len + 10 > sizeof(buf)) return -1;
    // Simple header: src(4) dst(4) proto(1) len(1)
    memcpy(buf, pkt->src.addr, 4);
    memcpy(buf+4, pkt->dst.addr, 4);
    buf[8] = pkt->protocol;
    buf[9] = (uint8_t)pkt->payload_len;
    memcpy(buf+10, pkt->payload, pkt->payload_len);
    struct net_packet npkt = { .data = buf, .len = pkt->payload_len + 10 };
    return network_sim_send(&ip_net_sim, &npkt);
}

int ip_recv(struct ip_packet *pkt, int timeout_ms) {
    if (!ip_initialized || !pkt) return -1;
    struct net_packet npkt = {0};
    int n = network_sim_recv(&ip_net_sim, &npkt, timeout_ms);
    if (n <= 0) return n;
    if (npkt.len < 10) { free(npkt.data); return -1; }
    memcpy(pkt->src.addr, npkt.data, 4);
    memcpy(pkt->dst.addr, npkt.data+4, 4);
    pkt->protocol = npkt.data[8];
    pkt->payload_len = npkt.data[9];
    if (pkt->payload_len + 10 > npkt.len) { free(npkt.data); return -1; }
    pkt->payload = malloc(pkt->payload_len);
    if (!pkt->payload) { free(npkt.data); return -1; }
    memcpy(pkt->payload, npkt.data+10, pkt->payload_len);
    free(npkt.data);
    
    // For TCP packets, we need to accept packets for both:
    // 1. Our listening port (5000) - for new connections
    // 2. Any established connection ports - for data exchange
    // For now, accept all TCP packets and let TCP layer handle routing
    if (pkt->protocol == 6 && pkt->payload_len >= 2) { // TCP protocol
        // Don't filter by port - let TCP layer handle socket matching
        // This allows both handshake packets and data packets to be processed
    }
    
    return (int)pkt->payload_len;
} 