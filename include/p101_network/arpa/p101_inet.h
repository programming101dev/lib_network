#ifndef LIBP101_NETWORK_ARPA_P101_INET_H
#define LIBP101_NETWORK_ARPA_P101_INET_H

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

    uint32_t    p101_htonl(const struct p101_env *env, uint32_t hostlong);
    uint16_t    p101_htons(const struct p101_env *env, uint16_t hostshort);
    in_addr_t   p101_inet_addr(const struct p101_env *env, struct p101_error *err, const char *cp);
    int         p101_inet_aton(const struct p101_env *env, struct p101_error *err, const char *cp, struct in_addr *inp);
    in_addr_t   p101_inet_lnaof(const struct p101_env *env, struct in_addr in);
    int         p101_inet_makeaddr(const struct p101_env *env, struct p101_error *err, in_addr_t net, in_addr_t lna, struct in_addr *addr);
    char       *p101_inet_net_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *src, int bits, char *dst, size_t size);
    int         p101_inet_net_pton(const struct p101_env *env, struct p101_error *err, int af, const char *src, void *dst, size_t size);
    in_addr_t   p101_inet_netof(const struct p101_env *env, struct in_addr in);
    in_addr_t   p101_inet_network(const struct p101_env *env, struct p101_error *err, const char *cp);
    char       *p101_inet_ntoa(const struct p101_env *env, struct in_addr in);
    const char *p101_inet_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *restrict src, char *restrict dst, socklen_t size);
    int         p101_inet_pton(const struct p101_env *env, struct p101_error *err, int af, const char *restrict src, void *restrict dst);
    uint32_t    p101_ntohl(const struct p101_env *env, uint32_t netlong);
    uint16_t    p101_ntohs(const struct p101_env *env, uint16_t netshort);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_NETWORK_ARPA_P101_INET_H
