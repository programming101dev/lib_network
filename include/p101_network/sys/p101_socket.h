#ifndef LIBP101_NETWORK_SYS_P101_SOCKET_H
#define LIBP101_NETWORK_SYS_P101_SOCKET_H

/*
 * Copyright 2026 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBP101_NETWORK_SHARED_DECLARATIONS
    #define LIBP101_NETWORK_SHARED_DECLARATIONS
    #include <arpa/inet.h>
    #include <ifaddrs.h>
    #include <inttypes.h>
    #include <net/if.h>
    #include <netdb.h>
    #include <p101_env/env.h>
    #include <p101_error/attributes.h>
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/types.h>

struct ether_addr;
#endif    // LIBP101_NETWORK_SHARED_DECLARATIONS

#ifdef __cplusplus
extern "C"
{
#endif

    int     p101_accept(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int     p101_bind(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len);
    int     p101_connect(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len);
    int     p101_getpeername(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int     p101_getsockname(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int     p101_getsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len);
    int     p101_listen(const struct p101_env *env, struct p101_error *err, int socket, int backlog);
    ssize_t p101_recv(const struct p101_env *env, struct p101_error *err, int socket, void *buffer, size_t length, int flags);
    ssize_t p101_recvfrom(const struct p101_env *env, struct p101_error *err, int socket, void *restrict buffer, size_t length, int flags, struct sockaddr *restrict address, socklen_t *restrict address_len);
    ssize_t p101_recvmsg(const struct p101_env *env, struct p101_error *err, int socket, struct msghdr *message, int flags);
    ssize_t p101_send(const struct p101_env *env, struct p101_error *err, int socket, const void *buffer, size_t length, int flags);
    ssize_t p101_sendmsg(const struct p101_env *env, struct p101_error *err, int socket, const struct msghdr *message, int flags);
    ssize_t p101_sendto(const struct p101_env *env, struct p101_error *err, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
    int     p101_setsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, const void *option_value, socklen_t option_len);
    int     p101_shutdown(const struct p101_env *env, struct p101_error *err, int socket, int how);
    int     p101_sockatmark(const struct p101_env *env, struct p101_error *err, int s);
    int     p101_socket(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol);
    int     p101_socketpair(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol, int socket_vector[2]);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_NETWORK_SYS_P101_SOCKET_H
