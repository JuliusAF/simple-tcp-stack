#include "sock.h"
#include "config.h"
#include "timer.h"
#include "tcp.h"



static LIST_HEAD(active_socks);
static int next_fd = SOCK_FD_START;
static pthread_rwlock_t socks_lock = PTHREAD_RWLOCK_INITIALIZER;

static void free_sock(struct sock *s) {
	if (!s)
		return;

	if (s->tcb)
		free(s->tcb);

    pthread_mutex_destroy(&s->conds.state_change_mutex);
    pthread_cond_destroy(&s->conds.state_change_cond);
	pthread_mutex_destroy(&s->conds.ack_mutex);
	pthread_cond_destroy(&s->conds.ack_cond);
    pthread_rwlock_destroy(&s->rwlock);

	timer_cancel(s->timers.retransmit);
	timer_cancel(s->timers.persistent);
	timer_cancel(s->timers.keep_alive);
	timer_cancel(s->timers.time_wait);

	free(s);
}

struct sock *alloc_sock() {
    struct sock *sock = calloc(sizeof *sock, 1);

	if (!sock)
		goto end;

	pthread_rwlock_wrlock(&socks_lock);
    sock->fd = next_fd++;
    change_state(sock, TCP_CLOSED);
	sock->err = 0;
    sock->tcb = calloc(sizeof *sock->tcb, 1);
    if (!sock->tcb) {
        free_sock(sock);
        sock = NULL;
        goto end;
    }
    pthread_mutex_init(&sock->conds.state_change_mutex, NULL);
    pthread_cond_init(&sock->conds.state_change_cond, NULL);
	pthread_mutex_init(&sock->conds.ack_mutex, NULL);
	pthread_cond_init(&sock->conds.ack_cond, NULL);
    pthread_rwlock_init(&sock->rwlock, NULL);
	sock->timers.retransmit = NULL;
	sock->timers.persistent = NULL;
	sock->timers.keep_alive = NULL;
	sock->timers.time_wait = NULL;
	sub_queue_init(&sock->snd_queue);
	sub_queue_init(&sock->rcv_queue);
    list_init(&sock->list);
    list_add_tail(&sock->list, &active_socks);

end:
    pthread_rwlock_unlock(&socks_lock);
    return sock;
}

void reset_sock(struct sock *sock) {
	if (!sock)
		return;

	pthread_rwlock_wrlock(&sock->rwlock);

    change_state(sock, TCP_CLOSED);
	sock->err = 0;
	if (sock->tcb)
		free(sock->tcb);

	sock->tcb = calloc(sizeof *sock->tcb, 1);
	sock->sport = 0;
	sock->dport = 0;
	sock->saddr = 0;
	sock->daddr = 0;
	timer_cancel(sock->timers.retransmit);
	sock->timers.retransmit = NULL;
	timer_cancel(sock->timers.persistent);
	sock->timers.persistent = NULL;
	timer_cancel(sock->timers.keep_alive);
	sock->timers.keep_alive = NULL;
	timer_cancel(sock->timers.time_wait);
	sock->timers.time_wait = NULL;
	sub_queue_free(&sock->rcv_queue);
	sub_queue_free(&sock->snd_queue);

	pthread_rwlock_unlock(&sock->rwlock);
}

struct sock *get_sock_by_fd(int fd) {
    struct list_head *item;
    struct sock *entry;

    pthread_rwlock_rdlock(&socks_lock);
    list_for_each(item, &active_socks) {
        entry = list_entry(item, struct sock, list);
        if (entry->fd == fd) {
            printf("found socket: %d\n", fd);
            goto end;
        }
    }
    // if we reach here we didn't find the socket linked to the fd;
    entry = NULL;

end:
    pthread_rwlock_unlock(&socks_lock);
    return entry;
}

struct sock *get_sock_by_connection(uint16_t sport, uint16_t dport, uint32_t saddr, uint32_t daddr) {
    struct list_head *item;
    struct sock *entry;

    pthread_rwlock_rdlock(&socks_lock);
    list_for_each(item, &active_socks) {
        entry = list_entry(item, struct sock, list);
        if (sport == entry->sport && dport == entry->dport &&
            saddr == entry->saddr && daddr == entry->daddr) {
            printf("found socket for sport: %d and dport: %d\n", entry->sport, entry->dport);
            goto end;
        }
    }
    // if we reach here we didn't find the socket linked to the fd;
    entry = NULL;

end:
    pthread_rwlock_unlock(&socks_lock);
    return entry;
}

void remove_sock(int fd) {
	struct list_head *item;
    struct sock *entry;
    int rc;

    pthread_rwlock_wrlock(&socks_lock);
    list_for_each(item, &active_socks) {
        entry = list_entry(item, struct sock, list);
        if (entry->fd == fd) {
            if ((rc = pthread_rwlock_trywrlock(&entry->rwlock)) == EBUSY) {
                printf("Cannot remove socket with fd: %d. Lock is held elsewhere\n", fd);
                return;
            }
        #ifdef M3_DEBUG
        printf("removing socket attached to: %d\n", fd);
        #endif
			list_del(&entry->list);
            pthread_rwlock_unlock(&entry->rwlock);
			free_sock(entry);
            goto end;
        }
    }

end:
    pthread_rwlock_unlock(&socks_lock);
}
