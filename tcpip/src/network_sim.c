#include "network_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>

// Helper: random double in [0,1)
static double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

int network_sim_init(struct network_sim *sim, uint16_t local_port, const char *remote_addr, uint16_t remote_port,
                    double loss_prob, double reorder_prob, int min_delay_ms, int max_delay_ms) {
    if (!sim) return -1;
    memset(sim, 0, sizeof(*sim));
    sim->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sim->udp_sock < 0) return -1;

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(local_port);
    if (bind(sim->udp_sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        close(sim->udp_sock);
        return -1;
    }
    strncpy(sim->remote_addr, remote_addr, sizeof(sim->remote_addr)-1);
    sim->remote_port = remote_port;
    sim->loss_prob = loss_prob;
    sim->reorder_prob = reorder_prob;
    sim->min_delay_ms = min_delay_ms;
    sim->max_delay_ms = max_delay_ms;
    srand(time(NULL));
    return 0;
}

int network_sim_send(struct network_sim *sim, const struct net_packet *pkt) {
    if (!sim || !pkt || !pkt->data || pkt->len == 0) return -1;
    // Simulate loss
    if (sim->loss_prob > 0 && rand_double() < sim->loss_prob) {
        // Drop packet
        return (int)pkt->len;
    }
    // Simulate delay
    if (sim->max_delay_ms > 0) {
        int delay = sim->min_delay_ms;
        if (sim->max_delay_ms > sim->min_delay_ms) {
            delay += rand() % (sim->max_delay_ms - sim->min_delay_ms + 1);
        }
        usleep(delay * 1000);
    }
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(sim->remote_port);
    if (inet_aton(sim->remote_addr, &remote.sin_addr) == 0) {
        // Try DNS
        struct hostent *he = gethostbyname(sim->remote_addr);
        if (!he) return -1;
        memcpy(&remote.sin_addr, he->h_addr, he->h_length);
    }
    ssize_t sent = sendto(sim->udp_sock, pkt->data, pkt->len, 0,
                          (struct sockaddr*)&remote, sizeof(remote));
    return (int)sent;
}

int network_sim_recv(struct network_sim *sim, struct net_packet *pkt, int timeout_ms) {
    if (!sim || !pkt) return -1;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sim->udp_sock, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rv = select(sim->udp_sock + 1, &fds, NULL, NULL, timeout_ms >= 0 ? &tv : NULL);
    if (rv <= 0) return -1; // timeout or error
    uint8_t buf[2048];
    ssize_t n = recvfrom(sim->udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
    if (n <= 0) return -1;
    // Simulate loss
    if (sim->loss_prob > 0 && rand_double() < sim->loss_prob) {
        // Drop packet
        return 0;
    }
    // Simulate delay
    if (sim->max_delay_ms > 0) {
        int delay = sim->min_delay_ms;
        if (sim->max_delay_ms > sim->min_delay_ms) {
            delay += rand() % (sim->max_delay_ms - sim->min_delay_ms + 1);
        }
        usleep(delay * 1000);
    }
    pkt->data = malloc(n);
    if (!pkt->data) return -1;
    memcpy(pkt->data, buf, n);
    pkt->len = n;
    return (int)n;
}

void network_sim_cleanup(struct network_sim *sim) {
    if (!sim) return;
    if (sim->udp_sock >= 0) close(sim->udp_sock);
    sim->udp_sock = -1;
} 