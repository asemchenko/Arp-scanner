//
// Created by asem on 11.04.18.
//
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/if_ether.h>

#include "arpUtils.h"
#include "DEBUG.h"


void prepareArpPacket(struct ArpPacket *dst,
                      struct sockaddr_ll *addr,
                      const char *interfaceName) {
    // setting service field
    dst->hardwareType = htons(HARDWARE_TYPE);
    dst->protocolType = htons(PROTOCOL_TYPE);
    dst->hardwareAddressLength = HARDWARE_ADDRESS_LENGTH;
    dst->protocolAddressLength = PROTOCOL_ADDRESS_LENGTH;
    uint8_t mac[HARDWARE_ADDRESS_LENGTH];
    // setting other field except dst->targetLogicAddress
    if (getInterfaceHardwareAddress(dst->senderHardwareAddress, interfaceName)) {
        fprintf(stderr, "Cannot get address of interface %s: interface not found\n", interfaceName);
        exit(1);
    }
    DEBUG(
            fprintf(stderr, "Mac address of interface: ");
    for (int i = 0; i < HARDWARE_ADDRESS_LENGTH; ++i) {
        fprintf(stderr, "%x:",dst->senderHardwareAddress[i]);
    }
    fprintf(stderr, "\n");
    )
    memset(&dst->targetHardwareAddress, 0xFF, HARDWARE_ADDRESS_LENGTH);\
    if (getInterfaceIP(dst->senderLogicAddress, interfaceName) ) {
        fprintf(stderr, "Interface %s not found\n", interfaceName);
        exit(1);
    }
    DEBUG(
            fprintf(stderr, "Interface %s has IP: ", interfaceName);
    for (int j = 0; j < PROTOCOL_ADDRESS_LENGTH; ++j) {
        fprintf(stderr, "%d:", (int)(dst->senderLogicAddress[j]) );
    }
    fprintf(stderr, "\n");
    )
    dst->operation = htons(1);
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

int convertNetworkAddr(const char *inString,
                       uint8_t outNetAddr[PROTOCOL_ADDRESS_LENGTH],
                       uint8_t *netPrefix) {
    char *invalidCharPtr;
    // reading 3 octets
    for (int i = 0; i < PROTOCOL_ADDRESS_LENGTH - 1; ++i) {
        unsigned long octet = strtoul(inString, &invalidCharPtr, 10);
        if (octet >= 256 || *invalidCharPtr != '.') {
            return 1;
        }
        inString = invalidCharPtr + 1;
        outNetAddr[i] = (uint8_t) octet;
    }
    // reading last octet
    unsigned long octet = strtoul(inString, &invalidCharPtr, 10);
    if (octet >= 256 || *invalidCharPtr != '/') {
        return 1;
    }
    inString = invalidCharPtr + 1;
    outNetAddr[PROTOCOL_ADDRESS_LENGTH - 1] = octet;
    unsigned long prefix = strtoul(inString, &invalidCharPtr, 10);
    if (prefix > 32 || invalidCharPtr == inString) {
        return 1;
    }
    *netPrefix = prefix;
    // bitwise AND ip address and netmask
    uint8_t hostPartLength = PROTOCOL_ADDRESS_LENGTH * 8 - prefix;
    for (int j = 0; j < hostPartLength / 8; ++j) {
        outNetAddr[PROTOCOL_ADDRESS_LENGTH - 1 - j] = 0x00;
    }
    if (hostPartLength % 8) {
        uint8_t mask = (0xFF >> hostPartLength % 8) << hostPartLength % 8;
        outNetAddr[PROTOCOL_ADDRESS_LENGTH - hostPartLength / 8 - 1] &= mask;
    }
    return 0;
}

int getInterfaceIP(uint8_t dstIP[PROTOCOL_ADDRESS_LENGTH],
                    const char *interfaceName) {
    struct ifaddrs *addrs;
    if (getifaddrs(&addrs)) {
        perror("Error during getting interface address: ");
        exit(1);
    }
    struct ifaddrs *curAddr = addrs;
    while (curAddr) {
        if (!strcmp(curAddr->ifa_name, interfaceName) && curAddr->ifa_addr->sa_family == AF_INET) {
            for (int i = 0; i < PROTOCOL_ADDRESS_LENGTH; ++i) {
                dstIP[i] = curAddr->ifa_addr->sa_data[2 + i];
            }
            freeifaddrs(addrs);
            return 0;
        }
        curAddr = curAddr->ifa_next;
    }
    freeifaddrs(addrs);
    return 1;
}

void prepareSockaddrll(struct sockaddr_ll *dstAddr,
                       const char *interfaceName) {
    dstAddr->sll_family = AF_PACKET;
    dstAddr->sll_protocol = htons(ETH_P_ARP);
    dstAddr->sll_ifindex = getInterfaceIndex(interfaceName);
    dstAddr->sll_pkttype = PACKET_BROADCAST;
    dstAddr->sll_halen = HARDWARE_ADDRESS_LENGTH;
    dstAddr->sll_hatype = 0;
    DEBUG(fprintf(stderr, "Interface %s has index %u\n", interfaceName, dstAddr->sll_ifindex);)
    memset(&dstAddr->sll_addr, 0xFF, 6);
}

void setHostPart(uint8_t ip[PROTOCOL_ADDRESS_LENGTH],
                 uint64_t hostPart,
                 uint8_t hostPartBitLength) {
    for (int i = 0; i < hostPartBitLength/8; ++i) {
        ip[PROTOCOL_ADDRESS_LENGTH-i-1] = (uint8_t)hostPart;
        hostPart >>= 8;
    }
    if (hostPartBitLength % 8) {
        uint8_t mask = (0xFF >> hostPartBitLength %8) << (hostPartBitLength%8);
        ip[PROTOCOL_ADDRESS_LENGTH - hostPartBitLength/8 - 1] &= hostPart & mask;
    }
}

void setDstIP(uint8_t ip[PROTOCOL_ADDRESS_LENGTH],
              struct ArpPacket *p) {
    memcpy(&p->targetLogicAddress, ip, PROTOCOL_ADDRESS_LENGTH);
}