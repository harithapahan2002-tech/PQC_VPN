// udp_support.c
// UDP socket implementation for the VPN tunnel.
//
// Depends on: udp_support.h, pqc_common.h

#define _POSIX_C_SOURCE 200809L

#include "udp_support.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

// Get/set O_NONBLOCK on a socket without disturbing other flags.
static int get_flags(int sock) {
    return fcntl(sock, F_GETFL, 0);
}

static int set_flags(int sock, int flags) {
    return fcntl(sock, F_SETFL, flags);
}

// ============================================================================
// SOCKET LIFECYCLE
// ============================================================================

int create_udp_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // SO_REUSEADDR allows restarting the server quickly without waiting
    // for TIME_WAIT to expire on the port.
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        // Non-fatal — continue
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "❌ bind() on port %d failed: %s\n",
                port, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

uint16_t get_socket_port(int sock) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getsockname(sock, (struct sockaddr *)&addr, &len) < 0) {
        perror("getsockname");
        return 0;
    }

    return ntohs(addr.sin_port);
}

int set_nonblocking(int sock) {
    int flags = get_flags(sock);
    if (flags < 0) { perror("fcntl F_GETFL"); return -1; }
    if (set_flags(sock, flags | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL");
        return -1;
    }
    return 0;
}

// ============================================================================
// PACKET I/O
// ============================================================================

ssize_t send_udp(int sock,
                 const void               *data,
                 size_t                    len,
                 const struct sockaddr_in *dest) {

    ssize_t sent = sendto(sock, data, len, 0,
                          (const struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) {
        if (errno != EINTR && errno != EAGAIN)
            perror("sendto");
        return -1;
    }

    return sent;
}

ssize_t recv_udp(int                sock,
                 void              *data,
                 size_t             len,
                 struct sockaddr_in *src,
                 int                timeout_ms) {

    // -----------------------------------------------------------------------
    // Non-blocking path (timeout_ms == 0)
    //
    // Previous version bug: poll() then blocking recvfrom() had a race —
    // if poll() returned POLLIN but the datagram was consumed before
    // recvfrom() ran (unlikely but possible), recvfrom() would block
    // indefinitely.
    //
    // Fix: set O_NONBLOCK before recvfrom, restore flags after.
    // EAGAIN/EWOULDBLOCK from recvfrom means nothing arrived — return 0
    // (same as a timeout) so the caller's poll loop continues normally.
    // -----------------------------------------------------------------------
    if (timeout_ms == 0) {
        int saved_flags = get_flags(sock);
        if (saved_flags < 0) return -1;

        if (set_flags(sock, saved_flags | O_NONBLOCK) < 0) return -1;

        struct sockaddr_in tmp;
        struct sockaddr_in *sptr = src ? src : &tmp;
        socklen_t src_len = sizeof(*sptr);

        ssize_t n = recvfrom(sock, data, len, 0,
                             (struct sockaddr *)sptr, &src_len);

        // Restore flags regardless of outcome
        set_flags(sock, saved_flags);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; // No data
            if (errno == EINTR)                          return 0; // Signal
            perror("recvfrom");
            return -1;
        }

        return n;
    }

    // -----------------------------------------------------------------------
    // Blocking path (timeout_ms == -1) or timed path (timeout_ms > 0)
    //
    // poll() handles the timeout cleanly. recvfrom() runs only after
    // poll() confirms data is available, so it should never block.
    // We leave MSG_DONTWAIT off here — the socket remains blocking, and
    // poll() guarantees a datagram is ready before we call recvfrom().
    // -----------------------------------------------------------------------
    if (timeout_ms != -1) {
        // Timed wait
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int r = poll(&pfd, 1, timeout_ms);

        if (r < 0) {
            if (errno == EINTR) return 0;
            perror("poll");
            return -1;
        }

        if (r == 0) return 0;   // Timeout — no data arrived
    }
    // If timeout_ms == -1 we skip poll() and go straight to recvfrom(),
    // which will block until a datagram arrives.

    struct sockaddr_in tmp;
    struct sockaddr_in *sptr = src ? src : &tmp;
    socklen_t src_len = sizeof(*sptr);

    ssize_t n = recvfrom(sock, data, len, 0,
                         (struct sockaddr *)sptr, &src_len);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            perror("recvfrom");
        return -1;
    }

    return n;
}