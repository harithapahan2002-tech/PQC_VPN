// udp_support.c
// Implementation of UDP networking functions

#define _POSIX_C_SOURCE 200809L

#include "udp_support.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

// ============================================================================
// UDP SOCKET CREATION
// ============================================================================

int create_udp_socket(uint16_t port) {
    int sock;
    struct sockaddr_in addr;

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Allow address reuse (helpful for development/testing)
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        // Not critical, continue
    }

    // Bind to port
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    // If port was 0, kernel assigned one - retrieve it
    if (port == 0) {
        socklen_t addr_len = sizeof(addr);
        if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) == 0) {
            port = ntohs(addr.sin_port);
        }
    }

    return sock;
}

// ============================================================================
// UDP SEND/RECEIVE
// ============================================================================

ssize_t send_udp(int sock, const void *data, size_t len,
                 const struct sockaddr_in *dest) {
    ssize_t sent = sendto(sock, data, len, 0,
                          (const struct sockaddr*)dest, sizeof(*dest));
    
    if (sent < 0) {
        perror("sendto");
        return -1;
    }

    return sent;
}

ssize_t recv_udp(int sock, void *data, size_t len,
                 struct sockaddr_in *src, int timeout_ms) {
    
    // Use poll() for timeout support
    if (timeout_ms >= 0) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0) {
            if (errno != EINTR) {
                perror("poll");
            }
            return -1;
        }
        
        if (ret == 0) {
            // Timeout
            return 0;
        }
    }

    // Receive packet
    socklen_t src_len = sizeof(*src);
    struct sockaddr_in temp_src;
    
    // If caller doesn't want source address, use temporary
    struct sockaddr_in *src_ptr = src ? src : &temp_src;
    
    ssize_t received = recvfrom(sock, data, len, 0,
                                (struct sockaddr*)src_ptr, &src_len);
    
    if (received < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recvfrom");
        }
        return -1;
    }

    return received;
}

// ============================================================================
// SOCKET UTILITIES
// ============================================================================

int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL");
        return -1;
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL");
        return -1;
    }

    return 0;
}

uint16_t get_socket_port(int sock) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) < 0) {
        perror("getsockname");
        return 0;
    }
    
    return ntohs(addr.sin_port);
}