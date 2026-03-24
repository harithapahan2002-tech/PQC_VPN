// tun.c
// Implementation of TUN interface management

#define _POSIX_C_SOURCE 200809L

#include "tun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <errno.h>

// ============================================================================
// TUN INTERFACE CREATION
// ============================================================================

int tun_create(tun_device_t *tun, const char *dev_name) {
    struct ifreq ifr;
    int fd, err;

    // Open the TUN device
    // /dev/net/tun is a special character device that creates virtual interfaces
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("❌ open /dev/net/tun");
        fprintf(stderr, "   Hint: Run with sudo or as root\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    
    // IFF_TUN: This is a TUN device (Layer 3, IP packets)
    //          vs IFF_TAP (Layer 2, Ethernet frames)
    // IFF_NO_PI: No packet information header
    //            (We don't need the extra 4 bytes of metadata)
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // Set interface name if provided
    if (dev_name && *dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    // Create the interface
    // TUNSETIFF: ioctl command to create TUN/TAP device
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("❌ ioctl TUNSETIFF");
        fprintf(stderr, "   Hint: Make sure /dev/net/tun exists\n");
        close(fd);
        return err;
    }

    // Save interface name (kernel may have assigned one)
    strncpy(tun->name, ifr.ifr_name, TUN_IFNAME_MAX - 1);
    tun->name[TUN_IFNAME_MAX - 1] = '\0';
    tun->fd = fd;

    printf("✅ TUN interface created: %s (fd=%d)\n", tun->name, fd);
    return fd;
}

// ============================================================================
// TUN INTERFACE CONFIGURATION
// ============================================================================

int tun_set_ip(tun_device_t *tun, 
               const char *local_ip, 
               const char *remote_ip,
               const char *netmask) {
    char cmd[256];

    // Parse and store IP addresses
    if (inet_pton(AF_INET, local_ip, tun->local_ip) != 1) {
        fprintf(stderr, "❌ Invalid local IP address: %s\n", local_ip);
        return -1;
    }
    
    if (inet_pton(AF_INET, remote_ip, tun->remote_ip) != 1) {
        fprintf(stderr, "❌ Invalid remote IP address: %s\n", remote_ip);
        return -1;
    }

    if (inet_pton(AF_INET, netmask, tun->netmask) != 1) {
        fprintf(stderr, "❌ Invalid netmask: %s\n", netmask);
        return -1;
    }

    // Use 'ip' command to configure the interface
    // This is simpler than using netlink sockets
    // Format: ip addr add LOCAL/NETMASK dev INTERFACE
    
    // Calculate CIDR prefix length from netmask
    uint32_t mask;
    memcpy(&mask, tun->netmask, 4);
    mask = ntohl(mask);
    int prefix = __builtin_popcount(mask);  // Count number of 1 bits

    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s", 
             local_ip, prefix, tun->name);
    
    if (system(cmd) != 0) {
        fprintf(stderr, "❌ Failed to set IP address\n");
        fprintf(stderr, "   Command: %s\n", cmd);
        return -1;
    }

    printf("✅ IP address set: %s/%d on %s\n", local_ip, prefix, tun->name);
    return 0;
}

int tun_up(tun_device_t *tun) {
    char cmd[256];
    
    // Bring interface UP
    snprintf(cmd, sizeof(cmd), "ip link set %s up", tun->name);
    if (system(cmd) != 0) {
        fprintf(stderr, "❌ Failed to bring interface up\n");
        return -1;
    }

    // Set MTU (Maximum Transmission Unit)
    snprintf(cmd, sizeof(cmd), "ip link set %s mtu %d", tun->name, TUN_MTU);
    if (system(cmd) != 0) {
        fprintf(stderr, "⚠️  Warning: Failed to set MTU (continuing anyway)\n");
        // Don't fail on MTU error - it's not critical
    }

    printf("✅ Interface %s is UP (MTU: %d)\n", tun->name, TUN_MTU);
    return 0;
}

int tun_down(tun_device_t *tun) {
    char cmd[256];
    
    snprintf(cmd, sizeof(cmd), "ip link set %s down", tun->name);
    if (system(cmd) != 0) {
        fprintf(stderr, "❌ Failed to bring interface down\n");
        return -1;
    }

    printf("✅ Interface %s is DOWN\n", tun->name);
    return 0;
}

// ============================================================================
// TUN I/O OPERATIONS
// ============================================================================

ssize_t tun_read(tun_device_t *tun, void *buf, size_t len) {
    return read(tun->fd, buf, len);
}

ssize_t tun_write(tun_device_t *tun, const void *buf, size_t len) {
    return write(tun->fd, buf, len);
}

void tun_close(tun_device_t *tun) {
    if (tun->fd >= 0) {
        close(tun->fd);
        printf("✅ TUN interface %s closed\n", tun->name);
        tun->fd = -1;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void print_ip_packet(const uint8_t *packet, size_t len) {
    if (len < 20) {
        printf("   ⚠️  Packet too short (%zu bytes, need at least 20)\n", len);
        return;
    }

    // Parse IP header (simplified)
    // See: https://en.wikipedia.org/wiki/IPv4#Header
    
    uint8_t version = (packet[0] >> 4) & 0x0F;
    uint8_t ihl = packet[0] & 0x0F;  // Internet Header Length (in 32-bit words)
    uint8_t protocol = packet[9];
    
    // Extract source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, packet + 12, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, packet + 16, dst_ip, sizeof(dst_ip));

    // Determine protocol name
    const char *proto_name = "UNKNOWN";
    if (protocol == 1) proto_name = "ICMP";       // ping
    else if (protocol == 6) proto_name = "TCP";   // web, ssh, etc
    else if (protocol == 17) proto_name = "UDP";  // DNS, etc

    printf("   📦 IPv%d %s: %s → %s (%zu bytes, hdr_len=%d)\n", 
           version, proto_name, src_ip, dst_ip, len, ihl * 4);
    
    // If it's ICMP, show more details
    if (protocol == 1 && len >= 20 + 8) {
        uint8_t icmp_type = packet[20];
        uint8_t icmp_code = packet[21];
        
        const char *icmp_name = "unknown";
        if (icmp_type == 0) icmp_name = "Echo Reply (pong)";
        else if (icmp_type == 8) icmp_name = "Echo Request (ping)";
        else if (icmp_type == 3) icmp_name = "Dest Unreachable";
        
        printf("      └─ ICMP: type=%d code=%d (%s)\n", 
               icmp_type, icmp_code, icmp_name);
    }
}

