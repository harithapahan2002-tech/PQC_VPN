// tun.h
// TUN virtual network interface abstraction.
//
// A TUN device is a virtual network interface operated in userspace.
// The kernel sends outgoing IP packets to it (via tun_read), and we
// inject incoming IP packets into the kernel's network stack (via tun_write).
//
// This module handles:
//   - Creating and naming the TUN interface
//   - Assigning IP addresses and bringing the interface up
//   - Reading/writing IP packets with MTU enforcement
//   - Clean teardown
//
// Depends on: pqc_common.h (for MAX_TUN_PAYLOAD)

#ifndef TUN_H
#define TUN_H

#include "pqc_common.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// ============================================================================
// CONSTANTS
// ============================================================================

#define TUN_NAME_LEN   16       // Max interface name length (IFNAMSIZ)
#define TUN_DEV_PATH   "/dev/net/tun"

// ============================================================================
// TUN DEVICE HANDLE
// ============================================================================

typedef struct {
    int  fd;                    // File descriptor for the TUN device
    char name[TUN_NAME_LEN];    // Interface name, e.g. "tun0"
} tun_device_t;

// ============================================================================
// LIFECYCLE
// ============================================================================

// Create and open a TUN interface with the given name.
// If name is NULL or empty, the kernel assigns a name (e.g. "tun0").
// Populates dev->fd and dev->name on success.
//
// Must be run as root (or with CAP_NET_ADMIN).
// Returns 0 on success, -1 on failure.
int tun_create(tun_device_t *dev, const char *name);

// Assign IP addresses and point-to-point peer to the interface.
// Sets local_ip as the interface address and peer_ip as the P2P destination.
//
//   local_ip : IP address for this end, e.g. "10.8.0.1"
//   peer_ip  : IP address for the remote end, e.g. "10.8.0.2"
//   netmask  : subnet mask, e.g. "255.255.255.0"
//
// Returns 0 on success, -1 on failure.
int tun_set_ip(tun_device_t *dev,
               const char   *local_ip,
               const char   *peer_ip,
               const char   *netmask);

// Bring the interface up (equivalent to: ip link set <dev> up).
// Returns 0 on success, -1 on failure.
int tun_up(tun_device_t *dev);

// Bring the interface down.
// Returns 0 on success, -1 on failure.
int tun_down(tun_device_t *dev);

// Close the TUN file descriptor and zero the device handle.
void tun_close(tun_device_t *dev);

// ============================================================================
// PACKET I/O
// ============================================================================

// Read one IP packet from the TUN interface into buf.
//
// MTU ENFORCEMENT: if the kernel offers a packet larger than
// MAX_TUN_PAYLOAD bytes, it is discarded and -1 is returned.
// This prevents the caller from overflowing its fixed-size buffers.
// In the old version there was no such check — a large packet could
// silently overflow the 2048-byte stack buffer in vpn_server/client.
//
//   buf     : destination buffer — must be at least MAX_TUN_PAYLOAD bytes
//   buf_len : size of buf (should be MAX_TUN_PAYLOAD)
//
// Returns: number of bytes read on success (1 .. MAX_TUN_PAYLOAD),
//          -1 on error or oversized packet.
ssize_t tun_read(tun_device_t *dev, uint8_t *buf, size_t buf_len);

// Write one IP packet to the TUN interface (inject into kernel stack).
//
//   buf  : IP packet data
//   len  : packet length — must be > 0 and <= MAX_TUN_PAYLOAD
//
// Returns: number of bytes written on success, -1 on failure.
ssize_t tun_write(tun_device_t *dev, const uint8_t *buf, size_t len);

// ============================================================================
// DIAGNOSTICS
// ============================================================================

// Print a brief summary of the IP packet in buf for debug logging.
// Reads the IP version, source/destination from the header.
// Safe to call on any buffer — does nothing if len < 20.
void print_ip_packet(const uint8_t *buf, size_t len);

#endif // TUN_H