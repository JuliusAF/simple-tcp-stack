#include "tcp.h"
#include "systems_headers.h"
#include "config.h"
#include "sock.h"
#include "timer.h"
#include "utilities.h"

static void tcp_release_rto_timer(struct sock *sock) {
    timer_release(sock->timers.retransmit);
    sock->timers.retransmit = NULL;
}

static void tcp_reset_rto_timer(struct sock *sock) {
    tcp_release_rto_timer(sock);
    sock->timers.retransmit = timer_add(sock->timers.rto, tcp_retransmit, (void *) sock);
}

// standard here is the sub it receives is always pushed up to, but not including the tcp header
static int tcp_send_subuff(struct sock *sock, struct subuff *sub) {
    sub_push(sub, TCP_HDR_LEN);
    struct tcp_hdr *tcph = (struct tcp_hdr *) sub->data;
    sub->protocol = IPP_TCP;

    tcph->sport = sock->sport;
    tcph->dport = sock->dport;
    tcph->seq = sock->tcb->snd.nxt;
    tcph->ack = sock->tcb->rcv.nxt;
    tcph->res = 0;
    tcph->off = 5;
    tcph->wnd = sock->tcb->rcv.wnd;
    tcph->csum = 0;
    tcph->urgp = 0;

    debug_tcp_hdr("out", tcph);

    tcph->sport = htons(tcph->sport);
    tcph->dport = htons(tcph->dport);
    tcph->seq = htonl(tcph->seq);
    tcph->ack = htonl(tcph->ack);
    tcph->wnd = htons(tcph->wnd);
    tcph->csum = htons(tcph->csum);
    tcph->urgp = htons(tcph->urgp);
    tcph->csum = do_tcp_csum( (uint8_t *) tcph, TCP_HDR_LEN + sub->dlen, IPP_TCP, sock->saddr, sock->daddr);

    int ret = ip_output(sock->daddr, sub);
    if (sub_queue_empty(&sock->snd_queue)) {
        tcp_reset_rto_timer(sock);
        sock->timers.retries = 0;
        sock->timers.rto = TCP_START_RTO;
    }

    return ret;
}

// standard here is the sub it receives is always pushed up to, but not including the tcp header
static int tcp_queue_send(struct sock* sock, struct subuff *sub) {
    int ret = -1;
    // TODO: put the tcb window check here, to see if packet can be sent

    ret = tcp_send_subuff(sock, sub);

    pthread_rwlock_wrlock(&sock->rwlock);
    sub->seq = sock->tcb->snd.nxt;
    sock->tcb->snd.nxt += sub->dlen;
    sub->end_seq = sock->tcb->snd.nxt;
    pthread_rwlock_unlock(&sock->rwlock);

    sub_queue_tail(&sock->snd_queue, sub);

    return ret;
}

int tcp_send_syn(struct sock *sock) {
    // allocate subuff and reserve necessary space
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub->dlen = 0;

    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    tcph->ctl.syn = 1;

    if (sock->timers.retransmit)
        tcp_release_rto_timer(sock);

    return tcp_queue_send(sock, sub);
}

int tcp_send_data(struct sock *sock, const void *buf, size_t len, bool push) {
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + len);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + len);
    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);
    sub->dlen = len;
    sub_push(sub, len);

    memcpy(sub->data, buf, len);

    // https://serverfault.com/questions/928642/all-tcp-packets-have-the-psh-flag-set-who-what-would-be-responsible-for-that
    if (push)
        tcph->ctl.psh = 1;

    tcph->ctl.ack = 1;

    return tcp_queue_send(sock, sub);
}

int tcp_send_fin(struct sock *sock) {
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub->dlen = 0;

    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    tcph->ctl.ack = 1;
    tcph->ctl.fin = 1;

    return tcp_queue_send(sock, sub);
}

// ack goes straight to send without queuing segment as acks shouldn't be retransmitted from the queue
int tcp_send_ack(struct sock *sock) {
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub->dlen = 0;

    struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);

    tcph->ctl.ack = 1;

    return tcp_send_subuff(sock, sub);
}

// retransmit logic called from timer when it runs out
void *tcp_retransmit(void *s) {
    struct sock *sock = (struct sock *) s;

    pthread_rwlock_wrlock(&sock->rwlock);
    if (sock->tcp_state == TCP_CLOSED) {
        m4_debug("received retransmit request on closed socket");
        goto end;
    }

    struct subuff *sub = sub_peek(&sock->snd_queue);

    if (!sub) {
        sock->timers.retries = 0;
        sock->timers.rto = TCP_START_RTO;

        // TODO: reset or release, then set in transmit?
        tcp_release_rto_timer(sock);
        goto end;
    } else if (sock->tcp_state == TCP_SYN_SENT) {
        if (sock->timers.retries > TCP_CONN_RETRIES) {
            printf("failed to receive synack\n");
            sock->err = ETIMEDOUT;
            tcp_release_rto_timer(sock);
            goto end;
        } else {
            sock->timers.retries++;
            sock->timers.rto *= 2;
            sub_reset_header(sub);
            tcp_send_subuff(sock, sub);
            tcp_reset_rto_timer(sock);
            goto end;
        }
    } else {
        if (sock->timers.retries > TCP_MAX_RETRIES) {
            printf("failed to receive ack after 15 retries\n");
            sock->err = ETIMEDOUT;
            tcp_release_rto_timer(sock);
            goto end;
        } else {
            sock->timers.retries++;
            sock->timers.rto *= 2;
            sub_reset_header(sub);
            tcp_send_subuff(sock, sub);
            tcp_reset_rto_timer(sock);
            goto end;
        }
    }

end:
    pthread_rwlock_unlock(&sock->rwlock);
    return NULL;
}
