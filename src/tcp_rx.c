#include "tcp.h"
#include "sock.h"
#include "systems_headers.h"
#include "config.h"
#include "timer.h"
#include "cond_wait.h"

static bool tcp_check_csum(struct subuff *sub) {
    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    uint16_t rec_csum = tcph->csum;
    tcph->csum = 0;
    tcph->csum = do_tcp_csum( (uint8_t *) tcph, tcph->off, IPP_TCP, iph->saddr, iph->daddr);

    return rec_csum == tcph->csum;
}

static bool legal_segment_seq(struct sock *sock, struct subuff *sub) {
    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    uint32_t seg_len = iph->len - (iph->ihl * 4) - (tcph->off * 4);

    if (seg_len < 0) {
        printf("segment length less than 0");
        return false;
    } else if (seg_len == 0) {
        if (sock->tcb->rcv.wnd == 0) {
            if (tcph->seq != sock->tcb->rcv.nxt) {
                printf("packet sequence number is not equal to receive next when receive window is 0");
                return false;
            }
        } else {
            if (sock->tcb->rcv.nxt > tcph->seq ||
                tcph->seq >= (sock->tcb->rcv.nxt + sock->tcb->rcv.wnd)) {
                printf("segment sequence number is less than expected or larger than allowed");
                return false;
            }
        }
    } else {
        if (sock->tcb->rcv.wnd == 0) {
            printf("received segment of length >0 when receive window is 0");
            return false;
        } else {
            if (sock->tcb->rcv.nxt > tcph->seq ||
                tcph->seq >= sock->tcb->rcv.nxt + sock->tcb->rcv.wnd ||
                sock->tcb->rcv.nxt > tcph->seq + seg_len - 1 ||
                tcph->seq + seg_len - 1 >= sock->tcb->rcv.nxt + sock->tcb->rcv.wnd) {

                printf("segment does not fit in allowed receive window");
                return false;
            }
        }
    }

    return true;
}

static void tcp_rcv_synack(struct sock *sock, struct subuff *sub) {
    if (sock->tcp_state != TCP_SYN_SENT) {
        printf("received synack when state isn't syn-sent\n");
        return;
    }

    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    struct subuff *top = sub_peek(&sock->snd_queue);
    // remove syn from retransmit queue
    if (top && top->seq < tcph->ack) {
        m4_debug("removing synack from retransmit queue because ack was received");
        timer_cancel(sock->timers.retransmit);
        sock->timers.retransmit = NULL;
        sub_dequeue(&sock->snd_queue);
    }

    sock->tcb->snd.una++;
    sock->tcb->snd.wnd = tcph->wnd;
    sock->tcb->irs = tcph->ack;
    sock->tcb->rcv.nxt = tcph->seq + 1;

    #ifdef M3_DEBUG
    printf("tcp_rcv_synack: changing state of sock %d to ESTABLISHED\n", sock->fd);
    #endif

    change_state(sock, TCP_ESTABLISHED);
    // let listeners know state has changed
    broadcast_cond(&sock->conds.state_change_cond);

    tcp_send_ack(sock);
}

static void tcp_rcv_ack(struct sock *sock, struct subuff *sub) {
    if (sock->tcp_state == TCP_CLOSED || sock->tcp_state == TCP_SYN_SENT) {
        m4_debug("received ack when not in state to do so");
        return;
    }

    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    if (sock->tcb->snd.una < tcph->ack && tcph->ack <= sock->tcb->snd.nxt) {
        sock->tcb->snd.una = tcph->ack;
    }

    // remove any segment fully acknowledged
    for (int i = 0; i < sub_queue_len(&sock->snd_queue); i++) {
        struct subuff *top = sub_peek(&sock->snd_queue);
        if (top && top->end_seq <= sock->tcb->snd.una) {
            m4_debug("removing packet from retransmit queue because ack was received");
            struct subuff *rem = sub_dequeue(&sock->snd_queue);
            free_sub(rem);
        } else {
            break;
        }
    }
    // remove timer if retransmit queue is now empty
    if (sub_queue_len(&sock->snd_queue) == 0) {
        timer_cancel(sock->timers.retransmit);
        sock->timers.retransmit = NULL;
        sock->timers.rto = TCP_START_RTO;
        sock->timers.retries = 0;
    }
    // set send window
    if (sock->tcb->snd.una < tcph->seq && tcph->seq <= sock->tcb->snd.nxt) {
        if (sock->tcb->snd.wl1 < tcph->seq ||
           (sock->tcb->snd.wl1 == tcph->seq && sock->tcb->snd.wl2 <= tcph->ack)) {

            sock->tcb->snd.wnd = tcph->wnd;
            sock->tcb->snd.wl1 = tcph->seq;
            sock->tcb->snd.wl2 = tcph->ack;
            }
    }
}

static void tcp_rcv_data(struct sock *sock, struct subuff *sub) {
    if (sock->tcp_state == TCP_CLOSED || sock->tcp_state == TCP_SYN_SENT) {
        m4_debug("received data when not in state to do so");
        return;
    }

    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    if (tcph->seq != sock->tcb->rcv.nxt) {
        m4_debug("received data sequence number does not match next expected, dropping packet");
        return;
    }

    uint32_t seg_len = iph->len - (iph->ihl * 4) - (tcph->off * 4);
    sub_queue_tail(&sock->rcv_queue, sub);
    sock->tcb->rcv.nxt += seg_len;
    sock->tcb->rcv.wnd -= seg_len;
    tcp_send_ack(sock);
}

void tcp_rx(struct subuff *sub) {
    struct iphdr *iph = IP_HDR_FROM_SUB(sub);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    tcph->sport = ntohs(tcph->sport);
    tcph->dport = ntohs(tcph->dport);
    tcph->seq = ntohl(tcph->seq);
    tcph->ack = ntohl(tcph->ack);
    tcph->wnd = ntohs(tcph->wnd);
    tcph->csum = ntohs(tcph->csum);
    tcph->urgp = ntohs(tcph->urgp);

    debug_tcp_hdr("in", tcph);

    if (!tcp_check_csum) {
        #ifdef M3_DEBUG
                printf("checksum did not match\n");
        #endif

        goto drop_pkt;
    }

    struct sock *sock = get_sock_by_connection(
            tcph->dport, tcph->sport,
            iph->daddr, iph->saddr
    );


    if (!sock) {
        #ifdef M3_DEBUG
                printf("tcp_rx: no socket found for connection\n");
        #endif
        goto drop_pkt;
    }

    uint32_t seg_len = iph->len - (iph->ihl * 4) - (tcph->off * 4);

    // https://tools.ietf.org/html/rfc793#section-3.7 page 25, guideline on accepting packets

    pthread_rwlock_wrlock(&sock->rwlock);
    switch(sock->tcp_state) {
        case TCP_CLOSED:
            m4_debug("received segment when socket is closed");
            goto unlock;
        case TCP_LISTEN:
            m4_debug("received packet when in listen state - not implemented");
            goto unlock;
        case TCP_SYN_SENT:
            if (tcph->ctl.ack == 1) {
                if (tcph->ack <= sock->tcb->iss || tcph->ack > sock->tcb->snd.nxt)
                    // rst would be sent, but is unimplemented
                    goto unlock;
                else if (sock->tcb->snd.una > tcph->ack)
                    goto unlock;
            }
            // reset is unimplemented
            if (tcph->ctl.rst == 1)
                goto unlock;

            // security check unimplemented

            if (tcph->ctl.syn == 1) {
                if (tcph->ctl.ack == 1) {
                    tcp_rcv_synack(sock, sub);
                    pthread_rwlock_unlock(&sock->rwlock);
                    return;
                }
                // moving into syn_received state is unimplemented - it is always assumed we are the initiators
                else if (tcph->ctl.ack == 0) {
                    goto unlock;
                }

            }
            goto unlock;

        case TCP_SYN_RECEIVED:
            m4_debug("got packet when in syn received state - unimplemented");
            goto unlock;
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            if (legal_segment_seq(sock, sub) == false) {
                tcp_send_ack(sock);
                goto unlock;
            }


            // rst not implemented
            if (tcph->ctl.rst == 1) {
                goto unlock;
            }

            // security/precedence not implemented

            if (tcph->ctl.syn == 1) {
                m4_debug("received syn when not in state to do so");
                goto unlock;
            }

            if (tcph->ctl.ack == 0) {
                m4_debug("ack bit not set, dropping packet");
                goto unlock;
            } else if (tcph->ctl.ack == 1) {

                switch(sock->tcp_state) {
                    case TCP_CLOSE_WAIT:
                    case TCP_ESTABLISHED:
                        tcp_rcv_ack(sock, sub);
                        break;
                    case TCP_FIN_WAIT_1:
                        tcp_rcv_ack(sock, sub);
                        // if our fin has been acknowledged
                        if (sock->tcb->snd.una == sock->tcb->snd.nxt) {
                            change_state(sock, TCP_FIN_WAIT_2);
                            broadcast_cond(&sock->conds.state_change_cond);
                        }
                        break;
                    case TCP_FIN_WAIT_2:
                        tcp_rcv_ack(sock, sub);
                        break;
                    case TCP_CLOSING:
                        tcp_rcv_ack(sock, sub);
                        if (sock->tcb->snd.una == sock->tcb->snd.nxt) {
                            change_state(sock, TCP_CLOSING);
                            broadcast_cond(&sock->conds.state_change_cond);
                        }
                        goto unlock;
                    case TCP_LAST_ACK:
                        tcp_rcv_ack(sock, sub);
                        if (sock->tcb->snd.una == sock->tcb->snd.nxt) {
                            change_state(sock, TCP_CLOSED);
                            broadcast_cond(&sock->conds.state_change_cond);
                        }
                        goto unlock;
                    case TCP_TIME_WAIT:
                    default:
                        m4_debug("received ack when not in state to do so");
                        goto unlock;
                }



            }

            // urg not implemented

            // handle data
            if (seg_len > 0) {
                switch(sock->tcp_state) {
                    case TCP_ESTABLISHED:
                    case TCP_FIN_WAIT_1:
                    case TCP_FIN_WAIT_2:
                        tcp_rcv_data(sock, sub);
                        break;
                    case TCP_CLOSE_WAIT:
                    case TCP_CLOSING:
                    case TCP_LAST_ACK:
                    case TCP_TIME_WAIT:
                        m4_debug("received data after remote host called fin");
                        break;
                    default:
                        m4_debug("processing segment data when not in state to do so/unknown state");
                        break;
                }
            }

            if (tcph->ctl.fin == 1) {
                if (sock->tcp_state == TCP_CLOSED ||
                    sock->tcp_state == TCP_LISTEN ||
                    sock->tcp_state == TCP_SYN_SENT)
                    goto unlock;

                sock->tcb->rcv.nxt = tcph->seq + 1;
                pthread_rwlock_unlock(&sock->rwlock);
                tcp_send_ack(sock);
                pthread_rwlock_wrlock(&sock->rwlock);
                sock->tcb->rcv.nxt++;

                switch(sock->tcp_state) {
                    case TCP_ESTABLISHED:
                        change_state(sock, TCP_CLOSE_WAIT);
                        broadcast_cond(&sock->conds.state_change_cond);
                        break;
                    case TCP_FIN_WAIT_1:
                        if (sock->tcb->snd.una == sock->tcb->snd.nxt) {
                            change_state(sock, TCP_TIME_WAIT);
                            broadcast_cond(&sock->conds.state_change_cond);
                        }
                        break;
                    case TCP_FIN_WAIT_2:
                        change_state(sock, TCP_TIME_WAIT);
                        broadcast_cond(&sock->conds.state_change_cond);
                        break;
                    case TCP_CLOSE_WAIT:
                    case TCP_CLOSING:
                    case TCP_LAST_ACK:
                    case TCP_TIME_WAIT:
                        goto unlock;
                    default:
                        m4_debug("received fin in unknown state");
                        goto unlock;
                }
            }
            pthread_rwlock_unlock(&sock->rwlock);
            return;
        default:
            m4_debug("received packet when in unknown state");
            goto unlock;
    }

unlock:
    pthread_rwlock_unlock(&sock->rwlock);
drop_pkt:
    free_sub(sub);
}
