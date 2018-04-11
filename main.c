#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "arpUtils.c"

#define DEBUG(command) command

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: <interface name> <network address>.\n"
                "For example: scan eth0 192.168.0.1/24\n");
        return 1;
    }
    // opening socket in link layer
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s == -1) {
        perror("Error in opening socket: ");
        return 1;
    }
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
    // preparing arp packet
    struct ArpPacket packet;
    preparePacket(&packet);
    return 0;
}