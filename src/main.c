#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "arpUtils.c"

#define DEBUG(command) command

#include <errno.h>
#include <string.h>

void printPacket(struct ArpPacket *p) {
    for (int i = 0; i < sizeof(struct ArpPacket); ++i) {
        int c = *((char*)p+i) & 0xFF;
        printf("%2x ", c);
        if (i%8 == 7)
            printf("\n");
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
    if (convertNetworkAddr(argv[2], netAddr, &netPrefix)) {
        fprintf(stderr, "Cannot recognize network address from: %s\n", argv[2]);
        return 1;
    }
    DEBUG(
            printf("========= RECOGNIZED NETWORK ADDRESS ===========\n");
            printf("IP address: ");
            for (int j = 0; j < PROTOCOL_ADDRESS_LENGTH; ++j) {
                printf("%i ", (int)netAddr[j]);
            }
            printf("\nNet prefix: %i\n", (int)netPrefix);
    )
    // prepearing sockaddr
    struct sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = getInterfaceIndex(argv[1]);
    addr.sll_pkttype = PACKET_BROADCAST;
    addr.sll_halen = HARDWARE_ADDRESS_LENGTH;
    addr.sll_hatype = 0;
    DEBUG(fprintf(stderr, "Interface %s has index %u\n", argv[1], addr.sll_ifindex);)
    uint8_t mac[HARDWARE_ADDRESS_LENGTH];
    if (getInterfaceHardwareAddress(mac, argv[1])) {
        fprintf(stderr, "Cannot get address of interface %s: interface not found\n", argv[1]);
        return 1;
    }
    DEBUG(
            fprintf(stderr, "Mac address of interface: ");
            for (int i = 0; i < HARDWARE_ADDRESS_LENGTH; ++i) {
                fprintf(stderr, "%x:",mac[i]);
            }
            fprintf(stderr, "\n");
    )
    memset(&addr.sll_addr, 0xFF, 6);
    // preparing arp packet
    struct ArpPacket packet;
    preparePacket(&packet);
    memcpy(&packet.senderHardwareAddress, mac, sizeof(mac));
    packet.senderLogicAddress[0] = 0xc0;
    packet.senderLogicAddress[1] = 0xa8;
    packet.senderLogicAddress[2] = 0x00;
    packet.senderLogicAddress[3] = 0x66;

    packet.targetLogicAddress[0] = 0xc0;
    packet.targetLogicAddress[1] = 0xa8;
    packet.targetLogicAddress[2] = 0x00;
    packet.targetLogicAddress[3] = 0xef;

    packet.operation = htons(1);
    DEBUG(
        printf("Packet hex dump: \n");
        printPacket(&packet);
    )
    if(sendto(s, &packet, sizeof(packet), 0,(struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("Error in sending ARP request: ");
        fprintf(stderr, "Error in sending ARP request: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
