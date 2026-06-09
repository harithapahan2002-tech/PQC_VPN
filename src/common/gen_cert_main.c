// gen_cert_main.c
// Certificate issuance tool.
// Issues an ML-DSA-65 certificate signed by the CA.
//
// Usage:
//   ./bin/gen_cert server    → server_cert.bin + server_key.priv
//   ./bin/gen_cert client    → client_cert.bin + client_key.priv
//   ./bin/gen_cert <name>    → <name>_cert.bin + <name>_key.priv

#include <stdio.h>
#include <string.h>
#include "../common/pqc_cert.h"

int main(int argc, char *argv[]) {
    printf("PQ-VPN Certificate Issuance Tool\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <identity>\n", argv[0]);
        fprintf(stderr, "  Examples:\n");
        fprintf(stderr, "    %s server\n", argv[0]);
        fprintf(stderr, "    %s client\n", argv[0]);
        return 1;
    }

    const char *identity = argv[1];

    // Build output paths: <identity>_cert.bin and <identity>_key.priv
    // For "server" and "client" use the standard path constants.
    // For custom identities build the path dynamically.
    char cert_path[256];
    char key_path[256];

    if (strcmp(identity, "server") == 0) {
        snprintf(cert_path, sizeof(cert_path), "%s", SERVER_CERT_PATH);
        snprintf(key_path,  sizeof(key_path),  "%s", SERVER_KEY_PATH);
    } else if (strcmp(identity, "client") == 0) {
        snprintf(cert_path, sizeof(cert_path), "%s", CLIENT_CERT_PATH);
        snprintf(key_path,  sizeof(key_path),  "%s", CLIENT_KEY_PATH);
    } else {
        snprintf(cert_path, sizeof(cert_path), "%s_cert.bin", identity);
        snprintf(key_path,  sizeof(key_path),  "%s_key.priv", identity);
    }

    printf("Identity  : %s\n", identity);
    printf("Cert out  : %s\n", cert_path);
    printf("Key out   : %s\n\n", key_path);

    if (cert_issue(identity, cert_path, key_path) != 0) {
        fprintf(stderr, "❌ Certificate issuance failed\n");
        fprintf(stderr, "   Make sure %s exists "
                        "(run ./bin/gen_ca first)\n", CA_KEY_PATH);
        return 1;
    }

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("✅ Certificate issued successfully\n\n");

    if (strcmp(identity, "server") == 0) {
        printf("Server setup:\n");
        printf("  Keep %s and %s on the server\n",
               SERVER_CERT_PATH, SERVER_KEY_PATH);
        printf("  Copy %s to the client machine\n\n", CA_CERT_PATH);
    } else if (strcmp(identity, "client") == 0) {
        printf("Client setup:\n");
        printf("  Keep %s and %s on the client\n",
               CLIENT_CERT_PATH, CLIENT_KEY_PATH);
        printf("  Copy %s to the client machine\n\n", CA_CERT_PATH);
    }

    printf("  chmod 600 %s\n", key_path);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    return 0;
}
