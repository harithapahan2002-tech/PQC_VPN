// udp_support.h
// UDP socket creation and packet send/receive for the VPN tunnel.
//
// Depends on: pqc_common.h

#ifndef UDP_SUPPORT_H
#define UDP_SUPPORT_H

#include "pqc_common.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

// ============================================================================
// CONSTANTS
// ============================================================================

// Maximum safe UDP payload over standard Ethernet:
//   Ethernet MTU (1500) - IP header (20) - UDP header (8) = 1472 bytes
// Our encrypted packets are MAX_TUN_PAYLOAD (1400) + VPN_HEADER_SIZE (36)
// = 1436 bytes, which is comfortably within this limit.
#define MAX_UDP_PAYLOAD  1472

// ============================================================================
// SOCKET LIFECYCLE
// ============================================================================

// Create a UDP socket bound to the given port.
// Pass port=0 to let the kernel assign an ephemeral port.
// Returns socket fd on success, -1 on failure.
int create_udp_socket(uint16_t port);

// Get the local port number a socket is bound to.
// Useful after create_udp_socket(0) to find the assigned port.
// Returns port number on success, 0 on failure.
uint16_t get_socket_port(int sock);

// Set a socket to non-blocking mode.
// Returns 0 on success, -1 on failure.
int set_nonblocking(int sock);

// ============================================================================
// PACKET I/O
// ============================================================================

// Send a UDP datagram to dest.
// Returns number of bytes sent on success, -1 on failure.
ssize_t send_udp(int sock,
                 const void             *data,
                 size_t                  len,
                 const struct sockaddr_in *dest);

// Receive a UDP datagram into data.
//
//   data       : receive buffer
//   len        : size of buffer
//   src        : if non-NULL, populated with the sender's address
//   timeout_ms : milliseconds to wait
//                  -1 = block forever
//                   0 = non-blocking (return immediately)
//                  >0 = wait up to timeout_ms milliseconds
//
// Returns: bytes received on success
//          0 on timeout (when timeout_ms >= 0)
//         -1 on error
//
// Non-blocking fix from previous version:
//   The old recv_udp with timeout_ms=0 used poll() then a blocking recvfrom.
//   If poll() returned POLLIN but the packet was consumed between the two
//   calls (race), recvfrom would block. The new version sets O_NONBLOCK
//   on the socket for the duration of a non-blocking call, eliminating
//   the race.
ssize_t recv_udp(int sock,
                 void             *data,
                 size_t            len,
                 struct sockaddr_in *src,
                 int               timeout_ms);

#endif // UDP_SUPPORT_H