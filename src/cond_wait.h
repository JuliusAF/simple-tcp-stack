#ifndef ANPNETSTACK_COND_WAIT_H
#define ANPNETSTACK_COND_WAIT_H

#include "systems_headers.h"

int signal_cond(pthread_cond_t *cond, pthread_mutex_t *mutex);
int broadcast_cond(pthread_cond_t *cond);
int wait_cond(pthread_cond_t *cond, pthread_mutex_t *mutex);
int timed_wait_cond(pthread_cond_t *cond, pthread_mutex_t *mutex, size_t time);


#endif
