// gen_psk_main.c
// PSK generator utility entry point.
//
// Generates a fresh cryptographically random psk.conf.
// Run this once on either peer, then copy psk.conf to the other.
//
// Usage:
//   ./bin/gen_psk              — writes psk.conf in current directory
//   ./bin/gen_psk /path/to/psk.conf  — writes to specified path

#include <stdio.h>
#include "../common/pqc_auth.h"

int main(int argc, char *argv[]) {
    const char *path = (argc > 1) ? argv[1] : PSK_FILE_PATH;

    printf("PQ-VPN PSK Generator\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Generating 256-bit random PSK...\n\n");

    if (auth_generate_psk_file(path) != 0) {
        fprintf(stderr, "❌ Failed to generate PSK file\n");
        return 1;
    }

    printf("\n⚠️  Keep psk.conf secret — treat it like a private key.\n");
    printf("   Copy it to both server and client before starting the VPN.\n");
    printf("   chmod 600 %s\n", path);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    return 0;
}