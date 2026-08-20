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

#include "p101_network/p101_netdb.h"
#include <p101_env/resource_classes.h>
#include <p101_env/wrapper.h>

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

void p101_endhostent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    endhostent();
    P101_TRACE_EXIT(env);
}

void p101_endnetent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    endnetent();
    P101_TRACE_EXIT(env);
}

void p101_endprotoent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    endprotoent();
    P101_TRACE_EXIT(env);
}

void p101_endservent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    endservent();
    P101_TRACE_EXIT(env);
}

void p101_freeaddrinfo(const struct p101_env *env, struct addrinfo *ai)
{
    P101_TRACE(env);
    errno = 0;
    P101_TRACK_POINTER_RESOURCE_RELEASE(env, P101_RESOURCE_CLASS_ADDRESS_INFO, ai, NULL);
    freeaddrinfo(ai);
    P101_TRACE_EXIT(env);
}

const char *p101_gai_strerror(const struct p101_env *env, int ecode)
{
    const char *ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = gai_strerror(ecode);

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_getaddrinfo(const struct p101_env *env, struct p101_error *err, const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_SYSTEM_CODE(env, err, ret_val);
    P101_WRAPPER_BLOCKING(env);
    errno   = 0;
    ret_val = getaddrinfo(nodename, servname, hints, res);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_SYSTEM(err, p101_gai_strerror(env, ret_val), ret_val);
    }
    else if(res != NULL && *res != NULL)
    {
        P101_TRACK_POINTER_RESOURCE_ACQUIRE(env, P101_RESOURCE_CLASS_ADDRESS_INFO, *res, 0U, NULL);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getnameinfo(const struct p101_env *env, struct p101_error *err, const struct sockaddr *restrict sa, socklen_t salen, char *restrict node, socklen_t nodelen, char *restrict service, socklen_t servicelen, int flags)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_SYSTEM_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getnameinfo(sa, salen, node, nodelen, service, servicelen, flags);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_SYSTEM(err, p101_gai_strerror(env, ret_val), ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

void p101_sethostent(const struct p101_env *env, struct p101_error *err, int stayopen)
{
    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_VOID(env, err);
    errno = 0;
    sethostent(stayopen);
    if(errno != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    P101_WRAPPER_DONE(env);
}

void p101_setnetent(const struct p101_env *env, struct p101_error *err, int stayopen)
{
    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_VOID(env, err);
    errno = 0;
    setnetent(stayopen);
    if(errno != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    P101_WRAPPER_DONE(env);
}

void p101_setprotoent(const struct p101_env *env, struct p101_error *err, int stayopen)
{
    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_VOID(env, err);
    errno = 0;
    setprotoent(stayopen);
    if(errno != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    P101_WRAPPER_DONE(env);
}

void p101_setservent(const struct p101_env *env, struct p101_error *err, int stayopen)
{
    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_VOID(env, err);
    errno = 0;
    setservent(stayopen);
    if(errno != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    P101_WRAPPER_DONE(env);
}
