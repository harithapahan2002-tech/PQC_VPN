// gen_ca_main.c
// CA keypair generator.
// Run once ever per deployment — generates ca_key.priv and ca_cert.pub.
//
// Usage:
//   ./bin/gen_ca

#include <stdio.h>
#include "../common/pqc_cert.h"

int main(void) {
    printf("PQ-VPN Certificate Authority Generator\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Algorithm : %s (NIST FIPS 204)\n\n", CERT_ALG);

    if (cert_generate_ca() != 0) {
        fprintf(stderr, "❌ CA generation failed\n");
        return 1;
    }

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Next steps:\n");
    printf("  1. Copy %s to every peer (not secret)\n", CA_CERT_PATH);
    printf("  2. Keep %s secret — never distribute it\n", CA_KEY_PATH);
    printf("  3. Run: ./bin/gen_cert server\n");
    printf("  4. Run: ./bin/gen_cert client\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    return 0;
}
