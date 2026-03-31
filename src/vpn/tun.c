// tun.c
// TUN virtual network interface implementation.
//
// Depends on: tun.h, pqc_common.h

// _GNU_SOURCE must be defined before any system headers.
// It unlocks struct ifreq, IFNAMSIZ, IFF_UP, and IFF_RUNNING in <net/if.h>,
// which are guarded behind __USE_MISC and not exposed by _POSIX_C_SOURCE alone.
#define _GNU_SOURCE

#include "tun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// <net/if.h> must come before <linux/if_tun.h>.
// <linux/if_tun.h> pulls in <linux/if.h> which defines a kernel-space
// struct ifreq that conflicts with the userspace definition in <net/if.h>
// if the order is reversed.
#include <net/if.h>
#include <linux/if_tun.h>

// ============================================================================
// LIFECYCLE
// ============================================================================

int tun_create(tun_device_t *dev, const char *name) {
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;

    // Open the TUN/TAP clone device
    int fd = open(TUN_DEV_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "❌ tun_create: open(%s) failed: %s\n",
                TUN_DEV_PATH, strerror(errno));
        fprintf(stderr, "   Is the tun kernel module loaded? "
                        "Try: sudo modprobe tun\n");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // IFF_TUN  : IP-level packets (no Ethernet header)
    // IFF_NO_PI: do not prepend packet information header
    //            (we handle raw IP packets directly)
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (name && name[0] != '\0') {
        // Request a specific interface name
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }
    // If name is NULL/empty, kernel assigns the next available name

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        fprintf(stderr, "❌ tun_create: TUNSETIFF failed: %s\n",
                strerror(errno));
        fprintf(stderr, "   Run as root or with CAP_NET_ADMIN\n");
        close(fd);
        return -1;
    }

    dev->fd = fd;
    strncpy(dev->name, ifr.ifr_name, TUN_NAME_LEN - 1);

    printf("   ✅ TUN interface '%s' created (fd=%d)\n", dev->name, dev->fd);
    return 0;
}

int tun_set_ip(tun_device_t *dev,
               const char   *local_ip,
               const char   *peer_ip,
               const char   *netmask) {

    // We use a temporary socket to issue SIOCSIFADDR / SIOCSIFDSTADDR /
    // SIOCSIFNETMASK ioctls — these operate on the interface by name,
    // not on the TUN fd itself.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "❌ tun_set_ip: socket() failed: %s\n",
                strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

    // Helper macro to reduce repetition for the three ioctl calls
#define SET_ADDR(ioctl_cmd, ip_str, label)                          \
    do {                                                            \
        memset(&ifr, 0, sizeof(ifr));                               \
        strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);            \
        addr->sin_family = AF_INET;                                 \
        if (inet_pton(AF_INET, (ip_str), &addr->sin_addr) != 1) {  \
            fprintf(stderr, "❌ tun_set_ip: invalid IP '%s'\n",     \
                    (ip_str));                                       \
            close(sock);                                            \
            return -1;                                              \
        }                                                           \
        if (ioctl(sock, (ioctl_cmd), &ifr) < 0) {                  \
            fprintf(stderr, "❌ tun_set_ip: %s ioctl failed: %s\n", \
                    (label), strerror(errno));                      \
            close(sock);                                            \
            return -1;                                              \
        }                                                           \
    } while (0)

    SET_ADDR(SIOCSIFADDR,    local_ip, "SIOCSIFADDR");
    SET_ADDR(SIOCSIFDSTADDR, peer_ip,  "SIOCSIFDSTADDR");
    SET_ADDR(SIOCSIFNETMASK, netmask,  "SIOCSIFNETMASK");

#undef SET_ADDR

    close(sock);

    printf("   ✅ IP configured: local=%s peer=%s mask=%s\n",
           local_ip, peer_ip, netmask);
    return 0;
}

int tun_up(tun_device_t *dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "❌ tun_up: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);

    // Read current flags first, then OR in IFF_UP
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "❌ tun_up: SIOCGIFFLAGS failed: %s\n",
                strerror(errno));
        close(sock);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "❌ tun_up: SIOCSIFFLAGS failed: %s\n",
                strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    printf("   ✅ Interface '%s' is up\n", dev->name);
    return 0;
}

int tun_down(tun_device_t *dev) {
    if (dev->fd < 0) return 0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags &= ~IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &ifr);    // Best-effort — ignore error
    }

    close(sock);
    return 0;
}

void tun_close(tun_device_t *dev) {
    if (dev->fd >= 0) {
        close(dev->fd);
        dev->fd = -1;
    }
    memset(dev->name, 0, TUN_NAME_LEN);
}

// ============================================================================
// PACKET I/O
// ============================================================================

ssize_t tun_read(tun_device_t *dev, uint8_t *buf, size_t buf_len) {
    if (dev->fd < 0 || !buf || buf_len == 0) return -1;

    // Enforce MTU: we pass the caller's buf_len to read(), but then
    // explicitly reject anything larger than MAX_TUN_PAYLOAD.
    // If buf_len itself is smaller than MAX_TUN_PAYLOAD, we still cap —
    // the caller should always pass a buffer of at least MAX_TUN_PAYLOAD.
    ssize_t n = read(dev->fd, buf, buf_len);

    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return -1;
        fprintf(stderr, "❌ tun_read: read failed: %s\n", strerror(errno));
        return -1;
    }

    if (n == 0) return 0;   // Should not happen on a TUN fd, but handle it

    // MTU enforcement — key fix from the previous version.
    // The old code used a hardcoded 2048-byte buffer with no size check.
    // If the kernel delivered a packet larger than the encrypt buffer,
    // it would silently overflow. We now reject oversized packets here,
    // at the point of read, before they reach the encryption path.
    if ((size_t)n > MAX_TUN_PAYLOAD) {
        fprintf(stderr, "⚠️  tun_read: packet too large (%zd > %d) — "
                        "discarded\n", n, MAX_TUN_PAYLOAD);
        return -1;
    }

    return n;
}

ssize_t tun_write(tun_device_t *dev, const uint8_t *buf, size_t len) {
    if (dev->fd < 0 || !buf || len == 0) return -1;

    if (len > MAX_TUN_PAYLOAD) {
        fprintf(stderr, "❌ tun_write: packet too large (%zu > %d)\n",
                len, MAX_TUN_PAYLOAD);
        return -1;
    }

    ssize_t n = write(dev->fd, buf, len);
    if (n < 0) {
        fprintf(stderr, "❌ tun_write: write failed: %s\n", strerror(errno));
        return -1;
    }

    return n;
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

void print_ip_packet(const uint8_t *buf, size_t len) {
    // Need at least a minimal IPv4 header (20 bytes)
    if (!buf || len < 20) return;

    uint8_t version = (buf[0] >> 4) & 0x0f;

    if (version == 4) {
        // IPv4
        uint8_t  protocol = buf[9];
        uint32_t src = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                       ((uint32_t)buf[14] <<  8) |  (uint32_t)buf[15];
        uint32_t dst = ((uint32_t)buf[16] << 24) | ((uint32_t)buf[17] << 16) |
                       ((uint32_t)buf[18] <<  8) |  (uint32_t)buf[19];

        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];

        struct in_addr sa = { .s_addr = htonl(src) };
        struct in_addr da = { .s_addr = htonl(dst) };
        inet_ntop(AF_INET, &sa, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &da, dst_str, sizeof(dst_str));

        const char *proto_str = "?";
        if      (protocol == 1)  proto_str = "ICMP";
        else if (protocol == 6)  proto_str = "TCP";
        else if (protocol == 17) proto_str = "UDP";

        printf("   IPv4 %s → %s  proto=%s  len=%zu\n",
               src_str, dst_str, proto_str, len);

    } else if (version == 6) {
        printf("   IPv6 packet len=%zu\n", len);
    } else {
        printf("   Unknown IP version %u len=%zu\n", version, len);
    }
}