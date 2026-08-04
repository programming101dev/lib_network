/*
 * Copyright 2021-2024 D'Arcy Smith.
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
#include <p101_env/wrapper.h>

void p101_if_freenameindex(const struct p101_env *env, struct if_nameindex *ptr)
{
    P101_TRACE(env);
    errno = 0;
    P101_TRACK_POINTER_RESOURCE_RELEASE(env, "interface-name-index", ptr, NULL);
    if_freenameindex(ptr);
    P101_TRACE_EXIT(env);
}

char *p101_if_indextoname(const struct p101_env *env, struct p101_error *err, unsigned ifindex, char *ifname)
{
    char *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    errno   = 0;
    ret_val = if_indextoname(ifindex, ifname);

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    P101_WRAPPER_DONE(env);
    return ret_val;
}

struct if_nameindex *p101_if_nameindex(const struct p101_env *env, struct p101_error *err)
{
    struct if_nameindex *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    errno   = 0;
    ret_val = if_nameindex();

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        P101_TRACK_POINTER_RESOURCE_ACQUIRE(env, "interface-name-index", ret_val, 0U, NULL);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

unsigned p101_if_nametoindex(const struct p101_env *env, struct p101_error *err, const char *ifname)
{
    unsigned ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, 0);
    errno   = 0;
    ret_val = if_nametoindex(ifname);

    if(ret_val == 0U)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENXIO : errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}
