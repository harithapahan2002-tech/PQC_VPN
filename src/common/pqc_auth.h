// pqc_auth.h
// Pre-shared key (PSK) authentication layer.
//
// PURPOSE
// -------
// The ML-KEM key exchange provides confidentiality but no authentication —
// without this layer, an active attacker can intercept the client's public
// key, substitute their own, and establish a session with both sides
// believing they are talking to the legitimate peer (MITM attack).
//
// This module adds a mutual authentication step using a pre-shared key.
// Both sides must prove knowledge of the PSK before the KEM exchange
// proceeds. A peer that does not know the PSK cannot complete the
// handshake and receives no key material.
//
// PROTOCOL (challenge-response over the existing UDP socket)
// ----------------------------------------------------------
//
//   Client                              Server
//   ------                              ------
//   1. Generate client_challenge (32B random)
//   2. Send client_challenge  --------->
//                                        3. Verify nothing yet (just receive)
//                                        4. Compute server_mac =
//                                             HMAC-SHA256(auth_key,
//                                               "server" || client_challenge)
//                                        5. Generate server_challenge (32B)
//                                        6. Send server_mac || server_challenge
//   7. Verify server_mac      <---------
//   8. Compute client_mac =
//        HMAC-SHA256(auth_key,
//          "client" || server_challenge)
//   9. Send client_mac        --------->
//                                       10. Verify client_mac
//                                       11. Auth complete → proceed to KEM
//   12. Auth complete → proceed to KEM
//
// The auth_key is derived from the raw PSK bytes via HKDF with a fixed
// info label ("pqvpn-auth-v1"), keeping it separate from the session key
// derived from the KEM shared secret.
//
// Domain separation ("server" / "client" prefixes in the HMAC input)
// prevents the server's MAC from being replayed as the client's MAC.
//
// Depends on: pqc_common.h

#ifndef PQC_AUTH_H
#define PQC_AUTH_H

#include "pqc_common.h"
#include <netinet/in.h>

// ============================================================================
// CONSTANTS
// ============================================================================

#define PSK_FILE_PATH    "psk.conf"     // Relative to working directory
#define PSK_HEX_LEN      64             // 32 bytes = 64 hex chars
#define PSK_BYTES        32             // Raw PSK length in bytes
#define AUTH_KEY_LEN     32             // HKDF output length for auth key
#define CHALLENGE_LEN    32             // Random challenge length in bytes
#define HMAC_LEN         32             // HMAC-SHA256 output length

// Handshake timeout — how long to wait for each auth message (ms)
#define AUTH_TIMEOUT_MS  10000          // 10 seconds

// ============================================================================
// AUTH CONTEXT
// ============================================================================

// Holds the derived authentication key for one session.
// Populated by auth_load_psk(), used by auth_server() / auth_client().
typedef struct {
    uint8_t auth_key[AUTH_KEY_LEN];  // HKDF(PSK, info="pqvpn-auth-v1")
    int     loaded;                  // 1 if auth_load_psk() succeeded
} auth_context_t;

// ============================================================================
// PSK LOADING
// ============================================================================

// Load the PSK from psk.conf and derive the authentication key.
//
// psk.conf format: a single line containing exactly 64 lowercase hex
// characters (32 bytes), no spaces, no prefix, terminated by newline.
// Example:
//   a3f1c2e4b5d6789012345678abcdef01a3f1c2e4b5d6789012345678abcdef01
//
//   ctx      : auth context to populate
//   psk_path : path to psk.conf (typically PSK_FILE_PATH)
//
// Returns 0 on success, -1 on failure (file not found, bad format, etc.)
int auth_load_psk(auth_context_t *ctx, const char *psk_path);

// ============================================================================
// HANDSHAKE FUNCTIONS
// ============================================================================

// Server-side authentication handshake.
//
// Receives the client challenge, responds with server MAC + server challenge,
// then verifies the client MAC. Blocks until complete or timeout.
//
//   ctx         : populated auth context (call auth_load_psk first)
//   udp_sock    : bound UDP socket (the same one used for the KEM exchange)
//   client_addr : populated with the client's address on return
//
// Returns 0 on success (peer authenticated), -1 on failure.
int auth_server(const auth_context_t   *ctx,
                int                     udp_sock,
                struct sockaddr_in     *client_addr);

// Client-side authentication handshake.
//
// Sends client challenge, verifies server MAC, then sends client MAC.
// Blocks until complete or timeout.
//
//   ctx         : populated auth context (call auth_load_psk first)
//   udp_sock    : connected UDP socket
//   server_addr : server's address
//
// Returns 0 on success (peer authenticated), -1 on failure.
int auth_client(const auth_context_t     *ctx,
                int                       udp_sock,
                const struct sockaddr_in *server_addr);

// ============================================================================
// UTILITY
// ============================================================================

// Generate a psk.conf file containing a fresh random PSK.
// Useful for initial setup — run once on either peer, copy to the other.
//
//   psk_path : output file path
//
// Returns 0 on success, -1 on failure.
int auth_generate_psk_file(const char *psk_path);

#endif // PQC_AUTH_H