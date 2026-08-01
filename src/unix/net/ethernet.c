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

#include "p101_network/network.h"
#include <net/ethernet.h>
#include <p101_env/wrapper.h>

#ifdef __linux__
    #include <netinet/ether.h>
#endif

struct ether_addr *p101_ether_aton(const struct p101_env *env, struct p101_error *err, const char *asc)
{
    struct ether_addr *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, NULL);
    ret_val = ether_aton(asc);

    if(ret_val == NULL)
    {
        // ether_aton() does not set errno on a bad address string.
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_ether_hostton(const struct p101_env *env, struct p101_error *err, const char *hostname, struct ether_addr *addr)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    caller_errno = errno;
    errno        = 0;
    ret_val      = ether_hostton(hostname, addr);
    actual_errno = errno;

    if(ret_val != 0)
    {
        // Failure means the host was not found in ethers(5); errno may be 0.
        P101_ERROR_RAISE_ERRNO(err, actual_errno == 0 ? ENOENT : actual_errno);
    }
    else
    {
        errno = caller_errno;
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_ether_line(const struct p101_env *env, struct p101_error *err, const char *line, struct ether_addr *addr, char *hostname)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    caller_errno = errno;
    errno        = 0;
    ret_val      = ether_line(line, addr, hostname);
    actual_errno = errno;

    if(ret_val != 0)
    {
        // Failure means the line was not a valid ethers(5) entry; errno may be 0.
        P101_ERROR_RAISE_ERRNO(err, actual_errno == 0 ? EINVAL : actual_errno);
    }
    else
    {
        errno = caller_errno;
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

char *p101_ether_ntoa(const struct p101_env *env, const struct ether_addr *addr)
{
    char *ret_val;

    P101_TRACE(env);
    ret_val = ether_ntoa(addr);

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_ether_ntohost(const struct p101_env *env, struct p101_error *err, char *hostname, const struct ether_addr *addr)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    caller_errno = errno;
    errno        = 0;
    ret_val      = ether_ntohost(hostname, addr);
    actual_errno = errno;

    if(ret_val != 0)
    {
        // Failure means the address was not found in ethers(5); errno may be 0.
        P101_ERROR_RAISE_ERRNO(err, actual_errno == 0 ? ENOENT : actual_errno);
    }
    else
    {
        errno = caller_errno;
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}
