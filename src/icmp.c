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

#include "icmp.h"
#include "ip.h"
#include "utilities.h"

void icmp_rx(struct subuff *sub)
{
    struct iphdr * iph = IP_HDR_FROM_SUB(sub);
    struct icmp * ih = ICMP_HDR_FROM_SUB(sub);
    uint16_t typecode = ih->type << 8 | ih->code; // avoid nested switching by multiplexing
    uint32_t csum = do_csum(ih, icmp_len(iph), 0);

    if (csum) {
        printf("icmp_rx: invalid checksum (0x%hx), dropping packet", ih->csum);
        goto drop_pkt;
    }

    debug_icmp("rx", ih);

    switch (typecode) {
    case ICMP_V4_ECHO << 8 | 0:
        icmp_reply(sub);
        return;
    default:
        printf("icmp_rx: unimplemented (type, code) pair: (%hhu, %hhu)\n", ih->type, ih->code);
        goto drop_pkt;
    }

drop_pkt:
    free_sub(sub);
}

void icmp_reply(struct subuff *sub)
{
    struct iphdr * iph = IP_HDR_FROM_SUB(sub);
    struct icmp * ih = ICMP_HDR_FROM_SUB(sub);

    int len = icmp_len(iph);

    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + len);
    sub_push(sub, len);

    sub->protocol = IPP_NUM_ICMP;
    ih->type = ICMP_V4_REPLY;
    ih->csum = 0; // this was a headache and a half x)
    ih->csum = do_csum(ih, len, 0);
    debug_icmp("tx", ih);

    ip_output(iph->saddr, sub);
    free_sub(sub);
}
