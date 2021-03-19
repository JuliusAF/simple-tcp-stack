#include "config.h"
#include "tcp.h"
#include "sock.h"
#include "systems_headers.h"
#include "utilities.h"
#include "timer.h"
#include "arp.h"
#include "cond_wait.h"

static uint16_t next_port = EPHEMERAL_PORT_MIN;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t generate_ISS() {
    return timer_get_tick() % INT_MAX;
}

static uint16_t get_next_port() {
    pthread_mutex_lock(&lock);
    uint16_t ret = next_port++;
    pthread_mutex_unlock(&lock);
    return ret;
}

void add_connect_info(struct sock *sock, const struct sockaddr *saddr, socklen_t addrlen) {
    struct sockaddr_in *addr = (struct sockaddr_in *) saddr;

    pthread_rwlock_wrlock(&sock->rwlock);
    sock->daddr = ntohl(addr->sin_addr.s_addr);
    sock->dport = ntohs(addr->sin_port);
    sock->saddr = ip_str_to_h32(ANP_IP_CLIENT_EXT); // do we have to hardcode the ip?
    sock->sport = get_next_port();
    pthread_rwlock_unlock(&sock->rwlock);
}

void change_state(struct sock *sock, int new_state) {
    pthread_mutex_lock(&sock->conds.state_change_mutex);
    sock->tcp_state = new_state;
    pthread_mutex_unlock(&sock->conds.state_change_mutex);
}

// connect call called from anp_wrapper
int tcp_connect(struct sock *sock) {
    int ret = -1;

    pthread_rwlock_wrlock(&sock->rwlock);
    switch (sock->tcp_state) {
        case TCP_CLOSED:
            break;
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            printf("error: connection already exists\n");
            sock->err = EISCONN;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        default:
            printf("unknown tcp state\n");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;

    }

    sock->timers.rto = TCP_START_RTO;
    sock->tcb->iss = generate_ISS();
    sock->tcb->snd.una = sock->tcb->iss;
    sock->tcb->snd.nxt = sock->tcb->iss;
    sock->tcb->snd.wnd = 0;
    sock->tcb->snd.up = 0;
    sock->tcb->snd.wl1 = 0;
    sock->tcb->snd.wl2 = 0;
    sock->tcb->irs = 0;
    sock->tcb->rcv.nxt = 0;
    sock->tcb->rcv.wnd = TCP_START_WINDOW;
    sock->tcb->rcv.up = 0;
    pthread_rwlock_unlock(&sock->rwlock);

    ret = tcp_send_syn(sock);
    int count = 0;
    while (ret < 0 && count < TCP_CONN_RETRIES) {
        printf("failed to send tcp packet in connect, retried %d times\n", count);
        timed_wait_cond(&arp_entry_cond, &arp_entry_mutex, 200000000);
        pthread_rwlock_wrlock(&sock->rwlock);
        sub_queue_free(&sock->snd_queue);
        pthread_rwlock_unlock(&sock->rwlock);
        ret = tcp_send_syn(sock);
        count++;
    }
    pthread_rwlock_wrlock(&sock->rwlock);
    if (ret >= 0) {
        sock->tcb->snd.nxt++;
        change_state(sock, TCP_SYN_SENT);
    } else {
        ret = -1;
        sock->err = ECONNREFUSED;
    }
    pthread_rwlock_unlock(&sock->rwlock);
    return ret;
}

// tcp send function called from anp_wrapper
int tcp_send(struct sock *sock, const void *buf, size_t len) {
    if (len < 0 || !buf) {
        pthread_rwlock_wrlock(&sock->rwlock);
        sock->err = EINVAL;
        pthread_rwlock_unlock(&sock->rwlock);
        return -1;
    }

    pthread_rwlock_wrlock(&sock->rwlock);
    switch(sock->tcp_state) {
        case TCP_CLOSED:
            printf("error: connection does not exist\n");
            sock->err = ENOTCONN;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            printf("send queue on none established socket not implemented\n");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
            break;
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            printf("error: connection closing\n");
            sock->err = EPIPE;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        default:
            printf("unknown tcp state\n");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
    }

    int bytes_sent = 0;
    int ret = 0;

    int snd_wnd = TCP_SND_WINDOW(sock->tcb);
    pthread_rwlock_unlock(&sock->rwlock);

    if (snd_wnd == 0) {
        pthread_mutex_lock(&sock->conds.ack_mutex);
        while (snd_wnd == 0) {
            pthread_cond_wait(&sock->conds.ack_cond, &sock->conds.ack_mutex);
            pthread_rwlock_rdlock(&sock->rwlock);
            snd_wnd = TCP_SND_WINDOW(sock->tcb);
            pthread_rwlock_unlock(&sock->rwlock);
        }
        pthread_mutex_unlock(&sock->conds.ack_mutex);
    }

    while (bytes_sent < len && snd_wnd > 0) {
        int to_send = (TCP_SAFE_MTU > len - bytes_sent) ? len - bytes_sent : TCP_SAFE_MTU;
        to_send = (to_send > snd_wnd) ? snd_wnd : to_send;
        assert(to_send + bytes_sent <= len);
        bool push = (to_send + bytes_sent == len) ? true : false;
        ret = tcp_send_data(sock, buf+bytes_sent, to_send, push);
        if (ret < 0)
            m4_debug("failed to send data");
        bytes_sent += to_send;
        pthread_rwlock_rdlock(&sock->rwlock);
        int snd_wnd = TCP_SND_WINDOW(sock->tcb);
        pthread_rwlock_unlock(&sock->rwlock);
    }

    return bytes_sent;
}

int tcp_receive(struct sock *sock, void *buf, size_t len) {

    pthread_rwlock_wrlock(&sock->rwlock);
    switch(sock->tcp_state) {
        case TCP_CLOSED:
            printf("error: connection does not exist\n");
            sock->err = ENOTCONN;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            m4_debug("send queue on none established socket not implemented");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
            break;
        case TCP_CLOSE_WAIT:
            if (sub_queue_len(&sock->rcv_queue) > 0)
                break;
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            printf("error: connection closing\n");
            sock->err = EPIPE;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        default:
            printf("unknown tcp state\n");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
    }
    pthread_rwlock_unlock(&sock->rwlock);

    int bytes_received = 0;

    // wait until data comes in
    while (sub_queue_len(&sock->rcv_queue) == 0) {
    }

    pthread_rwlock_wrlock(&sock->rwlock);
    for (int i = 0; i < sub_queue_len(&sock->rcv_queue); i++) {
        struct subuff *sub = sub_peek(&sock->rcv_queue);

        if (!sub)
            continue;

        struct iphdr *iph = IP_HDR_FROM_SUB(sub);
        struct tcp_hdr *tcph = TCP_HDR_FROM_SUB(sub);
        uint32_t seg_len = iph->len - (iph->ihl * 4) - (tcph->off * 4);

        if (bytes_received + seg_len > len)
            break;

        uint8_t *data = TCP_DATA_FROM_SUB(sub);
        memcpy(buf + bytes_received, data, seg_len);
        bytes_received += seg_len;
        sock->tcb->rcv.wnd += seg_len;
        sub = sub_dequeue(&sock->rcv_queue);
        free_sub(sub);
    }
    pthread_rwlock_unlock(&sock->rwlock);
    return bytes_received;
}

int tcp_close(struct sock *sock) {
    int ret = 0;

    pthread_rwlock_wrlock(&sock->rwlock);
    switch(sock->tcp_state) {
        case TCP_CLOSED:
            printf("error: connection does not exist\n");
            sock->err = ENOTCONN;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        case TCP_LISTEN:
        case TCP_SYN_SENT:
            change_state(sock, TCP_CLOSED);
            pthread_rwlock_unlock(&sock->rwlock);
            return 0;
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
            break;
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
            pthread_rwlock_unlock(&sock->rwlock);
            return 0;
        case TCP_CLOSE_WAIT:
            break;
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            printf("error: connection closing\n");
            sock->err = EPIPE;
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
        default:
            printf("unknown tcp state\n");
            pthread_rwlock_unlock(&sock->rwlock);
            return -1;
    }
    pthread_rwlock_unlock(&sock->rwlock);

    tcp_send_fin(sock);
    pthread_rwlock_wrlock(&sock->rwlock);
    change_state(sock, TCP_FIN_WAIT_1);
    sock->tcb->snd.nxt++;
    pthread_rwlock_unlock(&sock->rwlock);

    // wait until state changes to TIME-WAIT
    pthread_mutex_lock(&sock->conds.state_change_mutex);

    pthread_rwlock_rdlock(&sock->rwlock);
    int state = sock->tcp_state;
    pthread_rwlock_unlock(&sock->rwlock);
    while (state != TCP_TIME_WAIT) {
        pthread_cond_wait(&sock->conds.state_change_cond, &sock->conds.state_change_mutex);
        pthread_rwlock_rdlock(&sock->rwlock);
        state = sock->tcp_state;
        pthread_rwlock_unlock(&sock->rwlock);
    }

    pthread_mutex_unlock(&sock->conds.state_change_mutex);


    return ret;
}
