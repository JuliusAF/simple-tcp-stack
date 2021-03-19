#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H



#include "utilities.h"
#include "systems_headers.h"
#include "ip.h"
#include "sock.h"



// define ephemeral port range
#define EPHEMERAL_PORT_MIN 49152
#define EPHEMERAL_PORT_MAX 65535

#define TCP_START_WINDOW 64240
#define TCP_SAFE_MTU 1400

#define TCP_START_RTO 10000
//https://stackoverflow.com/questions/5227520/how-many-times-will-tcp-retransmit#:~:text=tcp_retries2%20(integer%3B%20default%3A%2015,depending%20on%20the%20retransmission%20timeout.
#define TCP_CONN_RETRIES 4
#define TCP_CONN_WAIT 200000
#define TCP_MAX_RETRIES 15

enum tcp_states {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
};

enum tcp_flags {
    TCP_F_FIN = 0x1,
    TCP_F_SYN = 0x2,
    TCP_F_RST = 0x4,
    TCP_F_PSH = 0x8,
    TCP_F_ACK = 0x10,
    TCP_F_URG = 0x20
};

/**
 * RFC 793 section 3.1
**/
struct tcp_hdr {
    uint16_t sport;         // source port
    uint16_t dport;         // destination port
    uint32_t seq;           // sequence number
    uint32_t ack;           // acknowledgement number
    uint8_t res : 4;        // reserved, must be 0
    uint8_t off : 4;        // data offset / header length in 32-bit words
    struct {
        uint8_t fin : 1;
        uint8_t syn : 1;
        uint8_t rst : 1;
        uint8_t psh : 1;
        uint8_t ack : 1;
        uint8_t urg : 1;
        uint8_t ece : 1;
        uint8_t cwr : 1;
    } ctl;
    uint16_t wnd;           // window, nr of data octets beginning at where ack field points
    uint16_t csum;          // tcp checksum
    uint16_t urgp;          // urgent pointer (I don't think we have to use this?)
    uint8_t data[];         // payload
} __attribute__((packed));

/**
 * RFC 793 section 3.2
**/
struct tcb {
    uint32_t iss;     // initial send sequence number
    struct {          // send
        uint32_t una; // unacknowledged
        uint32_t nxt; // next
        uint32_t wnd; // window
        uint32_t up;  // urgent pointer
        uint32_t wl1; // segment sequence number used for last window update
        uint32_t wl2; // segment acknowledgment number used for last window update
    } snd;

    uint32_t irs;     // initial receive sequence number
    struct {          // receive
        uint32_t nxt; // next
        uint32_t wnd; // window
        uint32_t up;  // urgent pointer
    } rcv;
};

#define TCP_HDR_LEN 20
#define TCP_HDR_FROM_SUB(_sub) (struct tcp_hdr *) (_sub->head + ETH_HDR_LEN + IP_HDR_LEN)
#define TCP_DATA_FROM_SUB(_sub) (uint8_t *) (_sub->head + ETH_HDR_LEN + IP_HDR_LEN + (TCP_HDR_FROM_SUB(_sub))->off * 4)

#define TCP_SND_WINDOW(_tcb) ((_tcb->snd.una + _tcb->snd.wnd) - _tcb->snd.nxt)
#define TCP_RCV_WINDOW(_tcb) ((_tcb->rcv.nxt + _tcb->rcv.wnd) - _tcb->rcv.nxt)

#define DEBUG_TCP 1
#ifdef DEBUG_TCP
#define debug_tcp_hdr(msg, hdr)                                                 \
    do {                                                                        \
        printf("TCP "msg" (sport: %hu dport: %hu seq: %u "               \
                    "ack: %u len: %hhu syn_flag: %u ack_flag: %u "              \
                    "wnd: %hu csum: %hu) \n",                                   \
                    hdr->sport, hdr->dport, hdr->seq, hdr->ack,                 \
                    hdr->off, hdr->ctl.syn, hdr->ctl.ack, hdr->wnd, hdr->csum); \
    } while (0)

#else
#define debug_tcp_hdr(msg, hdr)
#endif


// tcp.c definitions
uint32_t generate_ISS();
void add_connect_info(struct sock *sock, const struct sockaddr *addr, socklen_t addrlen);
void change_state(struct sock *sock, int new_state);

int tcp_connect(struct sock *sock);
int tcp_send(struct sock *sock, const void *buf, size_t len);
int tcp_receive(struct sock *sock, void *buf, size_t len);
int tcp_close(struct sock *sock);

// tcp_rx.c definitions
void tcp_rx(struct subuff *sub);


// tcp_tx.c definitions
int tcp_send_syn(struct sock *sock);
int tcp_send_data(struct sock *sock, const void *buf, size_t len, bool push);
int tcp_send_ack(struct sock *sock);
int tcp_send_fin(struct sock *sock);
void *tcp_retransmit(void *s);

#endif //ANPNETSTACK_TCP_H
