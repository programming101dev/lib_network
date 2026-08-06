#ifndef LIBP101_NETWORK_P101_NETDB_H
#define LIBP101_NETWORK_P101_NETDB_H

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

    void        p101_endhostent(const struct p101_env *env);
    void        p101_endnetent(const struct p101_env *env);
    void        p101_endprotoent(const struct p101_env *env);
    void        p101_endservent(const struct p101_env *env);
    void        p101_freeaddrinfo(const struct p101_env *env, struct addrinfo *ai);
    const char *p101_gai_strerror(const struct p101_env *env, int ecode);
    int         p101_getaddrinfo(const struct p101_env *env, struct p101_error *err, const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res);
    int         p101_getnameinfo(const struct p101_env *env, struct p101_error *err, const struct sockaddr *restrict sa, socklen_t salen, char *restrict node, socklen_t nodelen, char *restrict service, socklen_t servicelen, int flags);
    void        p101_sethostent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void        p101_setnetent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void        p101_setprotoent(const struct p101_env *env, struct p101_error *err, int stayopen);
    void        p101_setservent(const struct p101_env *env, struct p101_error *err, int stayopen);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_NETWORK_P101_NETDB_H
