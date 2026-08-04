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
#include <limits.h>
#include <p101_c/p101_ctype.h>
#include <p101_c/p101_stdlib.h>
#include <p101_env/wrapper.h>
#include <stdlib.h>

enum
{
    P101_INET_CLASS_A_HOST   = 0x00ffffffU,
    P101_INET_CLASS_A_LIMIT  = 128U,
    P101_INET_CLASS_A_NSHIFT = 24,
    P101_INET_CLASS_B_HOST   = 0x0000ffffU,
    P101_INET_CLASS_B_LIMIT  = 65536U,
    P101_INET_CLASS_B_NSHIFT = 16,
    P101_INET_CLASS_C_HOST   = 0x000000ffU,
    P101_INET_CLASS_C_LIMIT  = 16777216U,
    P101_INET_CLASS_C_NSHIFT = 8,
    P101_INET_OCTET_MAX      = 255U,
    P101_INET_ADDR_PARTS     = 4
};

static const unsigned long P101_INET_ADDR_NONE_VALUE = 0xffffffffUL;
static const unsigned long P101_INET_TWO_BYTE_MAX    = 0xffffUL;
static const unsigned long P101_INET_THREE_BYTE_MAX  = 0xffffffUL;

/*
 * inet_network() accepts the historic one-, two-, three-, and four-component
 * IPv4 grammar, with C integer radices. INADDR_NONE is both its failure value
 * and a valid result, so recognize every valid spelling of 0xffffffff.
 */
static int is_inet_addr_none_string(const struct p101_env *env, const char *cp)
{
    int           p101_single_result_;
    unsigned long parts[P101_INET_ADDR_PARTS];
    const char   *p;
    int           count;
    int           bytes;

    count = 0;
    p     = cp;

    while(1)
    {
        char *end;

        if(!p101_isdigit(env, (unsigned char)*p) || count >= P101_INET_ADDR_PARTS)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }

        errno = 0;
        /* P101_ERROR_CONTRACT_ALLOW_NO_ERROR: parser treats conversion failure as an invalid address */
        parts[count] = p101_strtoul(env, NULL, p, &end, 0);
        if(end == p || errno != 0)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
        count++;

        if(*end == '\0')
        {
            break;
        }

        if(*end != '.')
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }

        p = end + 1;
    }

    bytes = 0;
    for(int index = 0; index < count; index++)
    {
        if(parts[index] == P101_INET_OCTET_MAX)
        {
            bytes += 1;
        }
        else if(parts[index] == P101_INET_TWO_BYTE_MAX)
        {
            bytes += 2;
        }
        else if(parts[index] == P101_INET_THREE_BYTE_MAX)
        {
            bytes += 3;
        }
        else if(parts[index] == P101_INET_ADDR_NONE_VALUE)
        {
            bytes += 4;
        }
        else
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
    }

    p101_single_result_ = bytes == 4;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_inet_aton(const struct p101_env *env, struct p101_error *err, const char *cp, struct in_addr *inp)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, 0);
    ret_val = inet_aton(cp, inp);

    if(ret_val == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

in_addr_t p101_inet_lnaof(const struct p101_env *env, struct in_addr in)
{
    in_addr_t ret_val;

    P101_TRACE(env);
    ret_val = inet_lnaof(in);

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_inet_makeaddr(const struct p101_env *env, struct p101_error *err, in_addr_t net, in_addr_t lna, struct in_addr *addr)
{
    in_addr_t value;
    int       ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    ret_val = -1;

    if(addr == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        goto done;
    }

    if(net < P101_INET_CLASS_A_LIMIT)
    {
        value = (net << P101_INET_CLASS_A_NSHIFT) | (lna & P101_INET_CLASS_A_HOST);
    }
    else if(net < P101_INET_CLASS_B_LIMIT)
    {
        value = (net << P101_INET_CLASS_B_NSHIFT) | (lna & P101_INET_CLASS_B_HOST);
    }
    else if(net < P101_INET_CLASS_C_LIMIT)
    {
        value = (net << P101_INET_CLASS_C_NSHIFT) | (lna & P101_INET_CLASS_C_HOST);
    }
    else
    {
        value = net | lna;
    }

    addr->s_addr = p101_htonl(env, value);
    ret_val      = 0;

done:
    P101_WRAPPER_DONE(env);
    return ret_val;
}

char *p101_inet_net_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *src, int bits, char *dst, size_t size)
{
    int   actual_errno;
    int   caller_errno;
    char *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    caller_errno = errno;
    errno        = 0;
    ret_val      = inet_net_ntop(af, src, bits, dst, size);
    actual_errno = errno;

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, (actual_errno == 0) ? EIO : actual_errno);
    }
    else
    {
        errno = caller_errno;
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_inet_net_pton(const struct p101_env *env, struct p101_error *err, int af, const char *src, void *dst, size_t size)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    caller_errno = errno;
    errno        = 0;
    ret_val      = inet_net_pton(af, src, dst, size);
    actual_errno = errno;

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, (actual_errno == 0) ? EINVAL : actual_errno);
    }
    else
    {
        errno = caller_errno;
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

in_addr_t p101_inet_netof(const struct p101_env *env, struct in_addr in)
{
    in_addr_t ret_val;

    P101_TRACE(env);
    ret_val = inet_netof(in);

    P101_TRACE_EXIT(env);
    return ret_val;
}

in_addr_t p101_inet_network(const struct p101_env *env, struct p101_error *err, const char *cp)
{
    int       native_errno;
    in_addr_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (in_addr_t)P101_INET_ADDR_NONE_VALUE);
    ret_val      = inet_network(cp);
    native_errno = errno;

    // INADDR_NONE is ambiguous: it is both the error return and the correct
    // parse of "255.255.255.255". Only raise when it really was a failure, so
    // callers can rely on the p101 error instead of comparing the value.
    if(ret_val == (in_addr_t)P101_INET_ADDR_NONE_VALUE)
    {
        int valid;

        valid = is_inet_addr_none_string(env, cp);
        errno = native_errno;
        if(!valid)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
        }
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}
