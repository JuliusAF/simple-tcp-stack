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

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "sock.h"
#include "tcp.h"
#include "config.h"
#include "cond_wait.h"



static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }

#ifdef M3_DEBUG
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
#endif

    return 1;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) {
        struct sock *socket = alloc_sock();

        if (socket == NULL) {
            errno = ENOMEM;
            return -1;
        }

        #ifdef M3_DEBUG
                printf("assigned socket fd: %d\n", socket->fd);
        #endif

        return socket->fd;
    }

    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct sock *socket = get_sock_by_fd(sockfd);

    if (socket) {
        int ret;
        add_connect_info(socket, addr, addrlen);
        // call connect, maybe make new thread? no need prob
        ret = tcp_connect(socket);
        if (ret < 0) {
            printf("failed to send syn\n");
            errno = socket->err;
            reset_sock(socket);
            goto end;
        }

        // wait certain amount of time for reply synack
        pthread_mutex_lock(&socket->conds.state_change_mutex);
        timed_wait_cond(&socket->conds.state_change_cond, &socket->conds.state_change_mutex, 2000000000);

        pthread_rwlock_rdlock(&socket->rwlock);
        if (socket->tcp_state != TCP_ESTABLISHED) {
            errno = (socket->err == 0) ? ECONNREFUSED : socket->err;
            ret = -1;
            pthread_rwlock_unlock(&socket->rwlock);
            reset_sock(socket);
        } else {
            ret = 0;
            pthread_rwlock_unlock(&socket->rwlock);
        }
        pthread_mutex_unlock(&socket->conds.state_change_mutex);

    end:
        return ret;
    }

    // the default path
    return _connect(sockfd, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    struct sock *socket = get_sock_by_fd(sockfd);
    if(socket) {
        int ret = tcp_send(socket, buf, len);
        if (ret < 0) {
            errno = socket->err;
        }

        return ret;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    struct sock *socket = get_sock_by_fd(sockfd);
    if(socket) {
        int ret = tcp_receive(socket, buf, len);
        if (ret < 0) {
            errno = socket->err;
        }

        return ret;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    struct sock *socket = get_sock_by_fd(sockfd);
    if(socket) {
        int ret = tcp_close(socket);
        if (ret < 0) {
            errno = socket->err;
        }
        remove_sock(socket->fd);
        //TODO: implement your logic here
        return ret;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}
