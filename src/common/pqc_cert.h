// pqc_cert.h
// Post-quantum certificate system using ML-DSA-65 (NIST FIPS 204).
//
// PURPOSE
// -------
// Replaces the PSK mutual authentication layer with certificate-based
// identity verification. Both server and client hold a certificate signed
// by a trusted Certificate Authority (CA). During the handshake, each
// peer presents its certificate; the other side verifies it against the
// CA public key. No shared secret needs to be distributed — only the CA
// public key, which is not secret.
//
// This closes the main practical limitation of the PSK system: PSK
// required manual out-of-band distribution of a shared secret to every
// client. Certificate-based auth scales — new clients only need a
// certificate signed by the CA, and the CA public key is already on
// every peer.
//
// ALGORITHM
// ---------
// ML-DSA-65 (CRYSTALS-Dilithium Level 3), standardised as NIST FIPS 204
// (August 2024). Based on the Module Learning With Errors problem —
// no known quantum speedup exists for this problem, making signatures
// secure against both classical and quantum adversaries.
//
// ML-DSA-65 parameters:
//   Public key  : 1952 bytes
//   Private key : 4000 bytes
//   Signature   : 3309 bytes
//
// CERTIFICATE FORMAT
// ------------------
// Intentionally simple — no X.509, no ASN.1. The certificate is a flat
// binary structure containing the identity, public key, validity window,
// and CA signature over the preceding fields. This is sufficient for a
// research VPN and is straightforward to explain and verify.
//
// Wire size: sizeof(pqc_cert_t) = 64 + 1952 + 8 + 8 + 3309 = 5341 bytes
//
// FILE LAYOUT
// -----------
//   ca_key.priv       CA ML-DSA-65 private key  (secret — never distribute)
//   ca_cert.pub       CA ML-DSA-65 public key   (public — copy to all peers)
//   server_cert.bin   Server certificate         (public — copy to client)
//   server_key.priv   Server ML-DSA-65 private key (secret — server only)
//   client_cert.bin   Client certificate         (public — copy to server)
//   client_key.priv   Client ML-DSA-65 private key (secret — client only)
//
// SETUP WORKFLOW
// --------------
//   1. sudo ./bin/gen_ca
//      → writes ca_key.priv + ca_cert.pub
//      → copy ca_cert.pub to all peers (it is not secret)
//
//   2. sudo ./bin/gen_cert server
//      → writes server_cert.bin + server_key.priv
//      → keep both on the server; copy server_cert.bin to clients
//        if you want clients to verify server identity (recommended)
//
//   3. sudo ./bin/gen_cert client
//      → writes client_cert.bin + client_key.priv
//      → keep client_key.priv on the client only
//      → copy client_cert.bin to server so server can verify client
//
// Depends on: pqc_common.h, liboqs (ML-DSA-65)

#ifndef PQC_CERT_H
#define PQC_CERT_H

#include "pqc_common.h"
#include <stdint.h>
#include <netinet/in.h>

// ============================================================================
// ALGORITHM PARAMETERS
// ============================================================================

#define CERT_ALG            "ML-DSA-65"     // NIST FIPS 204 signature scheme

#define CERT_PUBKEY_LEN     1952            // ML-DSA-65 public key bytes
#define CERT_PRIVKEY_LEN    4032            // ML-DSA-65 private key bytes (liboqs)
#define CERT_SIG_LEN        3309            // ML-DSA-65 signature bytes
#define CERT_IDENTITY_LEN   64              // Max identity string length

// Certificate validity — 365 days from issuance
#define CERT_VALIDITY_DAYS  365
#define CERT_VALIDITY_SEC   (CERT_VALIDITY_DAYS * 24 * 3600)

// ============================================================================
// FILE PATHS  (relative to working directory)
// ============================================================================

#define CA_KEY_PATH         "ca_key.priv"
#define CA_CERT_PATH        "ca_cert.pub"
#define SERVER_CERT_PATH    "server_cert.bin"
#define SERVER_KEY_PATH     "server_key.priv"
#define CLIENT_CERT_PATH    "client_cert.bin"
#define CLIENT_KEY_PATH     "client_key.priv"

// ============================================================================
// CERTIFICATE STRUCTURE
// ============================================================================

// The CA signs over all fields EXCEPT the signature itself.
// Specifically: identity + public_key + issued_at + expires_at
// This is the "to-be-signed" (TBS) region.
//
// __attribute__((packed)) ensures no padding — the struct layout is
// the wire format. The static assert below enforces the expected size.
typedef struct {
    char     identity[CERT_IDENTITY_LEN];   // e.g. "vpn-server", "vpn-client"
    uint8_t  public_key[CERT_PUBKEY_LEN];   // ML-DSA-65 public key
    uint64_t issued_at;                     // Unix timestamp (big-endian)
    uint64_t expires_at;                    // Unix timestamp (big-endian)
    uint8_t  signature[CERT_SIG_LEN];       // CA's ML-DSA-65 sig over TBS
} __attribute__((packed)) pqc_cert_t;

// Size of the to-be-signed region (everything before the signature)
#define CERT_TBS_SIZE  (CERT_IDENTITY_LEN + CERT_PUBKEY_LEN + 8 + 8)

// Compile-time size check
_Static_assert(sizeof(pqc_cert_t) ==
               CERT_IDENTITY_LEN + CERT_PUBKEY_LEN + 8 + 8 + CERT_SIG_LEN,
               "pqc_cert_t size mismatch");

// ============================================================================
// CA KEY CONTEXT
// ============================================================================

// Holds the CA keypair in memory during certificate operations.
// Zeroed with cert_ca_free() when no longer needed.
typedef struct {
    uint8_t public_key[CERT_PUBKEY_LEN];
    uint8_t private_key[CERT_PRIVKEY_LEN];
    int     loaded;
} cert_ca_t;

// ============================================================================
// CA OPERATIONS
// ============================================================================

// Generate a new CA keypair and write to CA_KEY_PATH and CA_CERT_PATH.
// Run once ever per deployment.
// Returns 0 on success, -1 on failure.
int cert_generate_ca(void);

// Load the CA public key from CA_CERT_PATH.
// Used by server and client to verify peer certificates.
// Returns 0 on success, -1 on failure.
int cert_load_ca_pubkey(uint8_t ca_pubkey[CERT_PUBKEY_LEN]);

// ============================================================================
// CERTIFICATE ISSUANCE
// ============================================================================

// Issue a signed certificate for the given identity.
//
//   identity      : name string, e.g. "vpn-server" or "vpn-client"
//   cert_out_path : where to write the certificate, e.g. SERVER_CERT_PATH
//   key_out_path  : where to write the private key, e.g. SERVER_KEY_PATH
//
// Loads the CA private key from CA_KEY_PATH to sign the certificate.
// The CA private key is zeroed from memory immediately after signing.
// Returns 0 on success, -1 on failure.
int cert_issue(const char *identity,
               const char *cert_out_path,
               const char *key_out_path);

// ============================================================================
// CERTIFICATE LOADING AND VERIFICATION
// ============================================================================

// Load a certificate from disk into cert.
// Returns 0 on success, -1 on failure.
int cert_load(const char *cert_path, pqc_cert_t *cert);

// Load a private key from disk into privkey.
// Returns 0 on success, -1 on failure.
int cert_load_privkey(const char *key_path,
                      uint8_t privkey[CERT_PRIVKEY_LEN]);

// Verify a certificate against the CA public key.
// Checks:
//   1. CA signature over the TBS region is valid
//   2. Certificate has not expired (compared against current time)
//
// Returns 0 if valid, -1 if invalid (bad signature, expired, or error).
int cert_verify(const pqc_cert_t          *cert,
                const uint8_t ca_pubkey[CERT_PUBKEY_LEN]);

// ============================================================================
// HANDSHAKE FUNCTIONS
// ============================================================================

// Server-side certificate handshake.
//
// Receives the client certificate, verifies it, then sends the server
// certificate. Populates client_addr with the verified client's address.
//
//   ca_pubkey   : CA public key (from cert_load_ca_pubkey)
//   server_cert : server's own certificate (sent to client for verification)
//   udp_sock    : bound UDP socket
//   client_addr : populated with client address on return
//
// Returns 0 on success, -1 on failure.
int cert_handshake_server(const uint8_t       ca_pubkey[CERT_PUBKEY_LEN],
                          const pqc_cert_t    *server_cert,
                          int                  udp_sock,
                          struct sockaddr_in  *client_addr);

// Client-side certificate handshake.
//
// Sends the client certificate to the server, then receives and verifies
// the server certificate.
//
//   ca_pubkey   : CA public key (from cert_load_ca_pubkey)
//   client_cert : client's own certificate (sent to server for verification)
//   udp_sock    : UDP socket
//   server_addr : server's address
//
// Returns 0 on success, -1 on failure.
int cert_handshake_client(const uint8_t            ca_pubkey[CERT_PUBKEY_LEN],
                          const pqc_cert_t         *client_cert,
                          int                       udp_sock,
                          const struct sockaddr_in *server_addr);

// ============================================================================
// UTILITY
// ============================================================================

// Print certificate details to stdout (identity, validity, key fingerprint).
void cert_print(const pqc_cert_t *cert);

// Zero and free a CA context.
void cert_ca_free(cert_ca_t *ca);

#endif // PQC_CERT_H