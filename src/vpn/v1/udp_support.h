// udp_support.h
// UDP networking layer for VPN communication

#ifndef UDP_SUPPORT_H
#define UDP_SUPPORT_H

#include <stdint.h>
#include <netinet/in.h>

// ============================================================================
// CONSTANTS
// ============================================================================

// Maximum UDP packet size
// Ethernet MTU (1500) - IP header (20) - UDP header (8) = 1472
// We use slightly less to be safe
#define MAX_UDP_PACKET 1500

// ============================================================================
// UDP FUNCTIONS
// ============================================================================

// Create UDP socket bound to specified port
//
// Parameters:
//   port: Port number to bind to (0 = let kernel choose)
//
// Returns: Socket file descriptor on success, -1 on error
int create_udp_socket(uint16_t port);

// Send UDP packet to destination
//
// Parameters:
//   sock: UDP socket file descriptor
//   data: Data to send
//   len: Length of data
//   dest: Destination address (IP + port)
//
// Returns: Number of bytes sent, -1 on error
ssize_t send_udp(int sock, const void *data, size_t len, 
                 const struct sockaddr_in *dest);

// Receive UDP packet (with optional timeout)
//
// Parameters:
//   sock: UDP socket file descriptor
//   data: Buffer to store received data
//   len: Size of buffer
//   src: Output - source address of sender (can be NULL)
//   timeout_ms: Timeout in milliseconds (-1 = block forever, 0 = non-blocking)
//
// Returns: 
//   Number of bytes received on success
//   0 on timeout
//   -1 on error
ssize_t recv_udp(int sock, void *data, size_t len, 
                 struct sockaddr_in *src, int timeout_ms);

// Set socket to non-blocking mode
//
// Parameters:
//   sock: Socket file descriptor
//
// Returns: 0 on success, -1 on error
int set_nonblocking(int sock);

// Get local port number of socket
//
// Parameters:
//   sock: Socket file descriptor
//
// Returns: Port number on success, 0 on error
uint16_t get_socket_port(int sock);

#endif // UDP_SUPPORT_H
