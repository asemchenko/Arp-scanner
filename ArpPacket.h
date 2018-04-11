//
// Created by asem on 11.04.18.
//

#ifndef ARP_SCANNER_ARPPACKET_H
#define ARP_SCANNER_ARPPACKET_H
struct ArpPacket {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareAddressLength;
    uint8_t protocolAddressLength;
    uint16_t operation;
    uint8_t senderHardwareAddress[6];
    uint8_t senderLogicAddress[4];
    uint8_t targetHardwareAddress[6];
    uint8_t targetLogicAddress[4];

}__attribute__((packed)) ;
#endif //ARP_SCANNER_ARPPACKET_H
