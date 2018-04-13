#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <math.h>

#include "arpUtils.h"
#include "ArpPacket.h"

#include "DEBUG.h"
#include <errno.h>
#include <string.h>
void printPacket(struct ArpPacket *p) {
    for (int i = 0; i < sizeof(struct ArpPacket); ++i) {
        int c = *((char*)p+i) & 0xFF;
        printf("%2x ", c);
        if (i%8 == 7)
            printf("\n");
    }
    printf("\n");
}

int readNetworkAddr(const char *string,
                    uint8_t dstAddr[PROTOCOL_ADDRESS_LENGTH],
                    uint8_t *dstPrefix) {
    if (convertNetworkAddr(string, dstAddr, dstPrefix)) {
        fprintf(stderr, "Cannot recognize network address from: %s\n", string);
        exit(1);
    }
    DEBUG(
            printf("========= RECOGNIZED NETWORK ADDRESS ===========\n");
            printf("IP address: ");
            for (int j = 0; j < PROTOCOL_ADDRESS_LENGTH; ++j) {
                printf("%i ", (int)dstAddr[j]);
            }
            printf("\nNet prefix: %i\n", (int)(*dstPrefix) );
    )
}

void printIP(const uint8_t ip[PROTOCOL_ADDRESS_LENGTH]) {
    for (int i = 0; i < PROTOCOL_ADDRESS_LENGTH; ++i) {
        printf("%d.", (int)ip[i]);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: <interface name> <network address>.\n"
                "For example: scan eth0 192.168.0.1/24\n");
        return 1;
    }
    // opening socket in link layer
    int s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (s == -1) {
        perror("Error in opening socket: ");
        return 1;
    }
    // reading network address
    uint8_t netAddr[PROTOCOL_ADDRESS_LENGTH];
    uint8_t netPrefix;
    readNetworkAddr(argv[2], netAddr, &netPrefix);
    DEBUG(
        setHostPart(netAddr, 255, 8);
        printf("IP address: ");
        for (int j = 0; j < PROTOCOL_ADDRESS_LENGTH; ++j) {
            printf("%i ", (int)netAddr[j]);
        }
        printf("\n");
    )
    // prepearing sockaddr
    struct sockaddr_ll addr;
    prepareSockaddrll(&addr, argv[1]);
    // preparing arp packet
    struct ArpPacket packet;
    prepareArpPacket(&packet, &addr, argv[1]);
    DEBUG(
        printf("Packet hex dump: \n");
        printPacket(&packet);
    )
    for (int i = 1; i < powl(2, (32 - netPrefix) ) - 1; ++i) {
        setHostPart(netAddr, i, 32 - netPrefix);
        setDstIP(netAddr, &packet);
        DEBUG(
            printf("Sending ARP request to IP ");
            printIP(netAddr);
            printf(" ..............");
        )
        if(sendto(s, &packet, sizeof(packet), 0,(struct sockaddr*) &addr, sizeof(addr)) == -1) {
            perror("Error in sending ARP request: ");
            fprintf(stderr, "Error in sending ARP request: %s\n", strerror(errno));
            return 1;
        }
        DEBUG(printf("[ DONE ]\n");)
    }
    return 0;
}
