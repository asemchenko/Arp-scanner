//
// Created by asem on 13.04.18.
//

#ifndef ARP_SCANNER_ARPUTILS_H
#define ARP_SCANNER_ARPUTILS_H

#include <netpacket/packet.h>
#include "ArpPacket.h"

static const uint16_t HARDWARE_TYPE = 0x0001; // for Ethernet
static const uint16_t PROTOCOL_TYPE = 0x0800; // for IPv4
static const uint8_t HARDWARE_ADDRESS_LENGTH = 6; // MAC address size
static const uint8_t PROTOCOL_ADDRESS_LENGTH = 4; // IPv4 address size

int convertNetworkAddr(const char *inString,
                       uint8_t outNetAddr[PROTOCOL_ADDRESS_LENGTH],
                       uint8_t *netPrefix);

char getInterfaceHardwareAddress(uint8_t outAddr[HARDWARE_ADDRESS_LENGTH],
                                 const char *interfaceName);

unsigned int getInterfaceIndex(const char *interfaceName);

void prepareArpPacket(struct ArpPacket *dst,
                      struct sockaddr_ll *addr,
                      const char *interfaceName);

int getInterfaceIP(uint8_t dstIP[PROTOCOL_ADDRESS_LENGTH],
                   const char *interfaceName);

void prepareSockaddrll(struct sockaddr_ll *dstAddr,
                       const char *interfaceName);

void setHostPart(uint8_t ip[PROTOCOL_ADDRESS_LENGTH],
                 uint64_t hostPart,
                 uint8_t hostPartBitLength);

void setDstIP(uint8_t ip[PROTOCOL_ADDRESS_LENGTH],
              struct ArpPacket *p);

void printIP(uint8_t ip[PROTOCOL_ADDRESS_LENGTH], FILE *stream);

#endif //ARP_SCANNER_ARPUTILS_H
