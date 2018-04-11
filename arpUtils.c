//
// Created by asem on 11.04.18.
//
#include "ArpPacket.h"
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

const uint16_t HARDWARE_TYPE = 0x0001; // for Ethernet
const uint16_t PROTOCOL_TYPE = 0x0800; // for IPv4
const uint8_t HARDWARE_ADDRESS_LENGTH = 6; // MAC address size
const uint8_t PROTOCOL_ADDRESS_LENGTH = 4; // IPv4 address size


void preparePacket(struct ArpPacket *p) {
   p->hardwareType = htons(HARDWARE_TYPE);
   p->protocolType = htons(PROTOCOL_TYPE);
   p->hardwareAddressLength = HARDWARE_ADDRESS_LENGTH;
   p->protocolAddressLength = PROTOCOL_ADDRESS_LENGTH;
}

unsigned int getInterfaceIndex(const char *interfaceName) {
    return if_nametoindex(interfaceName);
}

char getInterfaceHardwareAddress(uint8_t outAddr[HARDWARE_ADDRESS_LENGTH],
                                 const char *interfaceName) {
    struct ifaddrs *addrs;
    if (getifaddrs(&addrs)) {
        perror("Error during getting interface address: ");
        exit(1);
    }
    struct ifaddrs *curAddr = addrs;
    while (curAddr) {
        if (!strcmp(curAddr->ifa_name, interfaceName) && curAddr->ifa_addr->sa_family == AF_PACKET) {
            for (int i = 0; i < HARDWARE_ADDRESS_LENGTH; ++i) {
                outAddr[i] = curAddr->ifa_addr->sa_data[10 + i];
            }
            freeifaddrs(addrs);
            return 0;
        }
        curAddr = curAddr->ifa_next;
    }
    freeifaddrs(addrs);
    return 1;
}
