/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef ANPNETSTACK_ICMP_H
#define ANPNETSTACK_ICMP_H

#include "systems_headers.h"
#include "subuff.h"

//https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

#define ICMP_V4_REPLY 0
#define ICMP_V4_ECHO  8

#define ICMP_DEBUG
#ifdef ICMP_DEBUG
#define debug_icmp(str, hdr)                                           \
    do {                                                               \
        printf("icmp "str" (type: %hhu, code: %hhu, csum: 0x%.4hx)\n", \
            hdr->type, hdr->code, hdr->csum);                          \
    } while (0)
#else  //ICMP_DEBUG
#define debug_icmp(str, hdr)
#endif //ICMP_DEBUG

// ICMP packet header https://www.researchgate.net/figure/ICMP-packet-structure_fig5_316727741
struct icmp {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t trash;
    uint8_t data[];
} __attribute__((packed));

#define ICMP_HDR_LEN sizeof(struct icmp)
#define icmp_len(ip_hdr) ip_hdr->len - ip_hdr->ihl * 4
#define ICMP_HDR_FROM_SUB(_sub) (struct icmp *)(_sub->head + ETH_HDR_LEN + IP_HDR_LEN)

void icmp_rx(struct subuff *sub);
void icmp_reply(struct subuff *sub);

#endif //ANPNETSTACK_ICMP_H
