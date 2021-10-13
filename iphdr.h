#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final
{
    uint8_t hdr_len : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint8_t ip_frag_offset : 5;
    uint8_t ip_more_fragment : 1;
    uint8_t ip_dont_fragment : 1;
    uint8_t ip_reserved_zero : 1;
    uint8_t ip_frag_offset1;
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint16_t ip_checksum;
    Ip sip_;
    Ip tip_;

    Ip sip() { return ntohl(sip_); }
    Ip tip() { return ntohl(tip_); }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
