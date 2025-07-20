#ifndef NETWORK_SIM_H
#define NETWORK_SIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Simulated network packet
struct net_packet {
    uint8_t *data;
    size_t len;
};

// Network simulator context
struct network_sim {
    int udp_sock; // Underlying UDP socket
    uint16_t local_port;
    char remote_addr[64]; // IP or hostname
    uint16_t remote_port;
    // Simulation parameters
    double loss_prob;
    double reorder_prob;
    int min_delay_ms;
    int max_delay_ms;
};

// Initialize the network simulator with real UDP socket
// local_port: UDP port to bind locally
// remote_addr: remote IP/hostname to send packets to
// remote_port: remote UDP port
// loss_prob, reorder_prob, min_delay_ms, max_delay_ms: simulation params (set to 0 to disable)
int network_sim_init(struct network_sim *sim, uint16_t local_port, const char *remote_addr, uint16_t remote_port,
                    double loss_prob, double reorder_prob, int min_delay_ms, int max_delay_ms);

// Send a packet (non-blocking, unreliable if simulation enabled)
int network_sim_send(struct network_sim *sim, const struct net_packet *pkt);

// Receive a packet (blocking or with timeout)
int network_sim_recv(struct network_sim *sim, struct net_packet *pkt, int timeout_ms);

// Clean up simulator resources
void network_sim_cleanup(struct network_sim *sim);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_SIM_H