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

#include "p101_network/arpa/p101_inet.h"
#include "p101_network/net/p101_ethernet.h"
#include "p101_network/net/p101_if.h"
#include "p101_network/p101_ifaddrs.h"
#include "p101_network/p101_netdb.h"
#include "p101_network/sys/p101_socket.h"
#include <p101_env/wrapper.h>

/*
 * Copyright 2022-2024 D'Arcy Smith.
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

int p101_getifaddrs(const struct p101_env *env, struct p101_error *err, struct ifaddrs **ifap)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    ret_val = getifaddrs(ifap);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else if(ifap != NULL && *ifap != NULL)
    {
        P101_TRACK_ALLOC(env, *ifap, 0);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

void p101_freeifaddrs(const struct p101_env *env, struct ifaddrs *ifp)
{
    P101_TRACE(env);
    if(ifp != NULL)
    {
        P101_TRACK_FREE(env, ifp);
    }
    freeifaddrs(ifp);
    P101_TRACE_EXIT(env);
}
