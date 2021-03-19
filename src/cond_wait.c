#include "cond_wait.h"
#include "systems_headers.h"

int signal_cond(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    int ret = 0;

    pthread_mutex_lock(mutex);
    ret = pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);

    return ret;
}

int broadcast_cond(pthread_cond_t *cond) {
    return pthread_cond_broadcast(cond);
}

int wait_cond(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    int ret = 0;

    pthread_mutex_lock(mutex);
    ret = pthread_cond_wait(cond, mutex);
    pthread_mutex_unlock(mutex);

    return ret;
}

int timed_wait_cond(pthread_cond_t *cond, pthread_mutex_t *mutex, size_t time) {
    struct timeval now;

    gettimeofday(&now, NULL);
    long int abstime_ns = now.tv_usec*1000 + time;
    struct timespec abstime = { now.tv_sec + (abstime_ns / 1000000000), abstime_ns % 1000000000 };

    return pthread_cond_timedwait(cond, mutex, &abstime);
}
