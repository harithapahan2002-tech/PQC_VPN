// test_tun.c
// Test program for TUN interface

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "tun.h"

static volatile int running = 1;

void sigint_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\n🛑 Stopping TUN test...\n");
}

int main() {
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║         TUN Interface Test Program            ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    printf("This program will:\n");
    printf("  1. Create a TUN interface (tun0)\n");
    printf("  2. Configure IP: 10.8.0.1\n");
    printf("  3. Listen for packets\n");
    printf("  4. Echo packets back (makes ping work!)\n\n");
    
    printf("⚠️  Note: This requires root/sudo privileges\n");
    printf("   If you see 'Permission denied', run: sudo %s\n\n", 
           "bin/test_tun");
    
    printf("Press Ctrl+C to exit\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Set up signal handler for graceful exit
    signal(SIGINT, sigint_handler);

    tun_device_t tun;
    memset(&tun, 0, sizeof(tun));

    // Step 1: Create TUN interface
    printf("1️⃣  Creating TUN interface...\n");
    if (tun_create(&tun, "tun0") < 0) {
        fprintf(stderr, "\n❌ Failed to create TUN interface\n");
        fprintf(stderr, "   Did you run with sudo?\n");
        return 1;
    }
    printf("\n");

    // Step 2: Configure IP address
    printf("2️⃣  Configuring IP address...\n");
    if (tun_set_ip(&tun, "10.8.0.1", "10.8.0.2", "255.255.255.0") < 0) {
        tun_close(&tun);
        return 1;
    }
    printf("\n");

    // Step 3: Bring interface UP
    printf("3️⃣  Bringing interface UP...\n");
    if (tun_up(&tun) < 0) {
        tun_close(&tun);
        return 1;
    }
    printf("\n");

    // Step 4: Listen for packets
    printf("4️⃣  TUN interface is ready!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("✅ You can now test it:\n");
    printf("   Terminal 2: ping 10.8.0.1\n");
    printf("   Terminal 2: ping 10.8.0.2\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    uint8_t buffer[2048];
    int packet_count = 0;

    while (running) {
        ssize_t nread = tun_read(&tun, buffer, sizeof(buffer));
        
        if (nread < 0) {
            if (running) {
                perror("tun_read error");
            }
            break;
        }

        if (nread == 0) {
            // EOF
            break;
        }

        packet_count++;
        printf("\n📬 Packet #%d received (%zd bytes):\n", packet_count, nread);
        print_ip_packet(buffer, nread);

        // Echo the packet back!
        // This makes ping work - we receive ICMP Echo Request,
        // send it back, kernel generates ICMP Echo Reply
        ssize_t nwrite = tun_write(&tun, buffer, nread);
        if (nwrite < 0) {
            perror("tun_write error");
            break;
        }
        
        printf("   ↩️  Echoed back (%zd bytes)\n", nwrite);
    }

    printf("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 Statistics:\n");
    printf("   Total packets: %d\n", packet_count);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Cleanup
    printf("🧹 Cleaning up...\n");
    tun_down(&tun);
    tun_close(&tun);
    
    printf("\n✅ TUN test completed successfully!\n");
    return 0;
}
