# Simulated TCP/IP Stack in C

This project implements a simplified TCP/IP stack in C, including both client and server support, with a simulated unreliable network layer. It is designed for educational purposes and demonstrates key features of TCP, such as reliability, congestion control, and flow control, without requiring raw socket privileges.

## Project Structure

```
tcpip/
├── include/
│   ├── ip.h
│   ├── tcp.h
│   ├── socket.h
│   └── network_sim.h
├── src/
│   ├── ip.c
│   ├── tcp.c
│   └── network_sim.c
├── test/
│   ├── client.c
│   └── server.c
├── Makefile
└── README.md
```

## Module Overview

- **network_sim.[ch]**: Simulates an unreliable network (packet loss, delay, reordering).
- **ip.[ch]**: Handles IP packet structure, encapsulation, and decapsulation.
- **tcp.[ch]**: Implements TCP state machine, segmentation, reassembly, timeouts, retransmission, sliding window, cumulative ACK, fast retransmit, piggybacking, and AIMD.
- **socket.[ch]**: Provides a user-facing API (connect, listen, accept, send, recv, close).
- **test/client.c & test/server.c**: Example programs for testing the stack.

## Build

Use the provided Makefile:

```
make
```

## Run

```
./test/server
./test/client
```

## Features
- Simulated unreliable network
- TCP reliability (retransmission, timeouts)
- Sliding window, cumulative ACKs
- Fast retransmit
- Congestion and flow control (AIMD)
- Stream socket API 
