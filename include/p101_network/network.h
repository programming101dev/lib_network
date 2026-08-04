#ifndef LIBP101_NETWORK_NETWORK_H
#define LIBP101_NETWORK_NETWORK_H

/*
 * Copyright 2026 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 */

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

#ifdef __cplusplus
extern "C"
{
#endif

    int                  p101_accept(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int                  p101_bind(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len);
    int                  p101_connect(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len);
    void                 p101_endhostent(const struct p101_env *env);
    void                 p101_endnetent(const struct p101_env *env);
    void                 p101_endprotoent(const struct p101_env *env);
    void                 p101_endservent(const struct p101_env *env);
    struct ether_addr   *p101_ether_aton(const struct p101_env *env, struct p101_error *err, const char *asc);
    int                  p101_ether_hostton(const struct p101_env *env, struct p101_error *err, const char *hostname, struct ether_addr *addr);
    int                  p101_ether_line(const struct p101_env *env, struct p101_error *err, const char *line, struct ether_addr *addr, char *hostname);
    char                *p101_ether_ntoa(const struct p101_env *env, const struct ether_addr *addr);
    int                  p101_ether_ntohost(const struct p101_env *env, struct p101_error *err, char *hostname, const struct ether_addr *addr);
    void                 p101_freeaddrinfo(const struct p101_env *env, struct addrinfo *ai);
    void                 p101_freeifaddrs(const struct p101_env *env, struct ifaddrs *ifp);
    const char          *p101_gai_strerror(const struct p101_env *env, int ecode);
    int                  p101_getaddrinfo(const struct p101_env *env, struct p101_error *err, const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res);
    int                  p101_getifaddrs(const struct p101_env *env, struct p101_error *err, struct ifaddrs **ifap);
    int                  p101_getnameinfo(const struct p101_env *env, struct p101_error *err, const struct sockaddr *restrict sa, socklen_t salen, char *restrict node, socklen_t nodelen, char *restrict service, socklen_t servicelen, int flags);
    int                  p101_getpeername(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int                  p101_getsockname(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    int                  p101_getsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len);
    uint32_t             p101_htonl(const struct p101_env *env, uint32_t hostlong);
    uint16_t             p101_htons(const struct p101_env *env, uint16_t hostshort);
    void                 p101_if_freenameindex(const struct p101_env *env, struct if_nameindex *ptr);
    char                *p101_if_indextoname(const struct p101_env *env, struct p101_error *err, unsigned ifindex, char *ifname);
    struct if_nameindex *p101_if_nameindex(const struct p101_env *env, struct p101_error *err);
    unsigned             p101_if_nametoindex(const struct p101_env *env, struct p101_error *err, const char *ifname);
    in_addr_t            p101_inet_addr(const struct p101_env *env, struct p101_error *err, const char *cp);
    int                  p101_inet_aton(const struct p101_env *env, struct p101_error *err, const char *cp, struct in_addr *inp);
    in_addr_t            p101_inet_lnaof(const struct p101_env *env, struct in_addr in);
    int                  p101_inet_makeaddr(const struct p101_env *env, struct p101_error *err, in_addr_t net, in_addr_t lna, struct in_addr *addr);
    char                *p101_inet_net_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *src, int bits, char *dst, size_t size);
    int                  p101_inet_net_pton(const struct p101_env *env, struct p101_error *err, int af, const char *src, void *dst, size_t size);
    in_addr_t            p101_inet_netof(const struct p101_env *env, struct in_addr in);
    in_addr_t            p101_inet_network(const struct p101_env *env, struct p101_error *err, const char *cp);
    char                *p101_inet_ntoa(const struct p101_env *env, struct in_addr in);
    const char          *p101_inet_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *restrict src, char *restrict dst, socklen_t size);
    int                  p101_inet_pton(const struct p101_env *env, struct p101_error *err, int af, const char *restrict src, void *restrict dst);
    int                  p101_listen(const struct p101_env *env, struct p101_error *err, int socket, int backlog);
    uint32_t             p101_ntohl(const struct p101_env *env, uint32_t netlong);
    uint16_t             p101_ntohs(const struct p101_env *env, uint16_t netshort);
    ssize_t              p101_recv(const struct p101_env *env, struct p101_error *err, int socket, void *buffer, size_t length, int flags);
    ssize_t              p101_recvfrom(const struct p101_env *env, struct p101_error *err, int socket, void *restrict buffer, size_t length, int flags, struct sockaddr *restrict address, socklen_t *restrict address_len);
    ssize_t              p101_recvmsg(const struct p101_env *env, struct p101_error *err, int socket, struct msghdr *message, int flags);
    ssize_t              p101_send(const struct p101_env *env, struct p101_error *err, int socket, const void *buffer, size_t length, int flags);
    ssize_t              p101_sendmsg(const struct p101_env *env, struct p101_error *err, int socket, const struct msghdr *message, int flags);
    ssize_t              p101_sendto(const struct p101_env *env, struct p101_error *err, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
    void                 p101_sethostent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void                 p101_setnetent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void                 p101_setprotoent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void                 p101_setservent(const struct p101_env *env, struct p101_error *err, int stayopen);
    int                  p101_setsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, const void *option_value, socklen_t option_len);
    int                  p101_shutdown(const struct p101_env *env, struct p101_error *err, int socket, int how);
    int                  p101_sockatmark(const struct p101_env *env, struct p101_error *err, int s);
    int                  p101_socket(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol);
    int                  p101_socketpair(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol, int socket_vector[2]);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_NETWORK_NETWORK_H
