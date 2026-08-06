#ifndef LIBP101_NETWORK_P101_IFADDRS_H
#define LIBP101_NETWORK_P101_IFADDRS_H

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

    void p101_freeifaddrs(const struct p101_env *env, struct ifaddrs *ifp);
    int  p101_getifaddrs(const struct p101_env *env, struct p101_error *err, struct ifaddrs **ifap);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_NETWORK_P101_IFADDRS_H
