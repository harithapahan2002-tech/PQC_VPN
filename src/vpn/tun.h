// tun.h
// TUN (network tunnel) interface management for VPN
// TUN operates at Layer 3 (IP packets)

#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <sys/types.h>

// ============================================================================
// CONSTANTS
// ============================================================================

// Reduced MTU to account for encryption overhead
// Standard Ethernet: 1500 bytes
// Our VPN adds: IV (12) + TAG (16) + framing (4) = 32 bytes
// So we use 1400 to be safe
#define TUN_MTU 1400

// Maximum interface name length
#define TUN_IFNAME_MAX 16

// ============================================================================
// TUN DEVICE STRUCTURE
// ============================================================================

typedef struct {
    int fd;                        // File descriptor for TUN device
    char name[TUN_IFNAME_MAX];     // Interface name (e.g., "tun0")
    uint8_t local_ip[4];           // Local IP address (e.g., 10.8.0.1)
    uint8_t remote_ip[4];          // Remote IP address (e.g., 10.8.0.2)
    uint8_t netmask[4];            // Network mask (e.g., 255.255.255.0)
} tun_device_t;

// ============================================================================
// TUN INTERFACE FUNCTIONS
// ============================================================================

// Create and configure TUN interface
// 
// Parameters:
//   tun: Pointer to tun_device_t structure to initialize
//   dev_name: Desired interface name (e.g., "tun0")
//             If NULL or empty, kernel assigns a name
//
// Returns: 
//   File descriptor on success (>=0)
//   -1 on error
//
// Note: Requires root privileges or CAP_NET_ADMIN capability
int tun_create(tun_device_t *tun, const char *dev_name);

// Configure IP address on TUN interface
//
// Parameters:
//   tun: TUN device structure
//   local_ip: Local IP address as string (e.g., "10.8.0.1")
//   remote_ip: Remote IP address as string (e.g., "10.8.0.2")
//   netmask: Network mask as string (e.g., "255.255.255.0")
//
// Returns: 0 on success, -1 on error
//
// Note: Uses system() calls to 'ip' command (simple but requires 'ip' tool)
int tun_set_ip(tun_device_t *tun, 
               const char *local_ip, 
               const char *remote_ip,
               const char *netmask);

// Bring TUN interface UP (activate it)
//
// Parameters:
//   tun: TUN device structure
//
// Returns: 0 on success, -1 on error
int tun_up(tun_device_t *tun);

// Bring TUN interface DOWN (deactivate it)
//
// Parameters:
//   tun: TUN device structure
//
// Returns: 0 on success, -1 on error
int tun_down(tun_device_t *tun);

// Read an IP packet from TUN interface (blocking)
//
// Parameters:
//   tun: TUN device structure
//   buf: Buffer to store packet
//   len: Size of buffer
//
// Returns: Number of bytes read, -1 on error
//
// Note: This reads a complete IP packet from the kernel
ssize_t tun_read(tun_device_t *tun, void *buf, size_t len);

// Write an IP packet to TUN interface
//
// Parameters:
//   tun: TUN device structure  
//   buf: Packet data to write
//   len: Length of packet
//
// Returns: Number of bytes written, -1 on error
//
// Note: This delivers the packet to the kernel's network stack
ssize_t tun_write(tun_device_t *tun, const void *buf, size_t len);

// Close TUN interface and clean up
//
// Parameters:
//   tun: TUN device structure
void tun_close(tun_device_t *tun);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Print IP packet information for debugging
//
// Parameters:
//   packet: Raw IP packet data
//   len: Length of packet
//
// Note: Parses and displays IP header info (src, dst, protocol)
void print_ip_packet(const uint8_t *packet, size_t len);

#endif // TUN_H
