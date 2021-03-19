#ifndef ANPNETSTACK_SOCK_H
#define ANPNETSTACK_SOCK_H



#include "linklist.h"
#include "systems_headers.h"
#include "subuff.h"



#define SOCK_FD_START 500000



struct sock_conds {
    pthread_mutex_t state_change_mutex;
    pthread_cond_t state_change_cond;
    pthread_mutex_t ack_mutex;
    pthread_cond_t ack_cond;
};

// https://www.geeksforgeeks.org/tcp-timers/
struct tcp_timers {
    uint32_t rto;
    uint32_t srtt;
    uint32_t rttvar;
    //https://stackoverflow.com/questions/5227520/how-many-times-will-tcp-retransmit#:~:text=tcp_retries2%20(integer%3B%20default%3A%2015,depending%20on%20the%20retransmission%20timeout.
    uint32_t retries;
    struct timer *retransmit;
    // timers for m4
    struct timer *persistent;
    struct timer *keep_alive;
    struct timer *time_wait;
};

struct sock {
    struct list_head list;
    int fd;
    int tcp_state;
    int err;
    struct tcb *tcb;
    uint16_t sport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
    pthread_rwlock_t rwlock;
    struct sock_conds conds;
    struct tcp_timers timers;
    struct subuff_head rcv_queue;
    struct subuff_head snd_queue;
    // TODO: add ring buffer for receiving/sending data here?
};

struct sock *alloc_sock();
void reset_sock(struct sock *sock);
struct sock *get_sock_by_fd(int fd);
struct sock *get_sock_by_connection(uint16_t sport, uint16_t dport, uint32_t saddr, uint32_t daddr);
void remove_sock(int fd);




#endif //ANPNETSTACK_SOCK_H
