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
#include <limits.h>
#include <p101_c/p101_ctype.h>
#include <p101_c/p101_stdlib.h>
#include <p101_env/wrapper.h>
#include <stdlib.h>

enum
{
    P101_INET_ADDR_PARTS    = 4,
    P101_INET_BYTE_BITS     = 8U,
    P101_INET_CLASS_A_SHIFT = 24U,
    P101_INET_CLASS_B_SHIFT = 16U,
    P101_INET_CLASS_C_SHIFT = 8U,
};

static const unsigned long P101_INET_ADDR_NONE_VALUE = 0xffffffffUL;
static const unsigned long P101_INET_CLASS_A_REST    = 0xffffffUL;
static const unsigned long P101_INET_CLASS_B_REST    = 0xffffUL;
static const unsigned long P101_INET_OCTET_MAX       = 0xffUL;

static int is_inet_addr_none_string(const struct p101_env *env, const char *cp);

static int is_inet_addr_none_string(const struct p101_env *env, const char *cp)
{
    unsigned long parts[P101_INET_ADDR_PARTS];
    unsigned long value;
    const char   *p;
    int           count;

    p     = cp;
    count = 0;

    while(1)
    {
        char *end;

        if(!p101_isdigit(env, (unsigned char)*p) || count >= P101_INET_ADDR_PARTS)
        {
            return 0;
        }

        errno = 0;
        /* P101_ERROR_CONTRACT_ALLOW_NO_ERROR: parser treats conversion failure as an invalid address */
        parts[count] = p101_strtoul(env, NULL, p, &end, 0);
        if(end == p || errno != 0)
        {
            return 0;
        }
        count++;

        if(*end == '\0')
        {
            break;
        }
        if(*end != '.')
        {
            return 0;
        }
        p = end + 1;
    }

    switch(count)
    {
        case 1:
            value = parts[0];
            break;
        case 2:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_CLASS_A_REST)
            {
                return 0;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | parts[1];
            break;
        case 3:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_OCTET_MAX || parts[2] > P101_INET_CLASS_B_REST)
            {
                return 0;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | (parts[1] << P101_INET_CLASS_B_SHIFT) | parts[2];
            break;
        case 4:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_OCTET_MAX || parts[2] > P101_INET_OCTET_MAX || parts[3] > P101_INET_OCTET_MAX)
            {
                return 0;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | (parts[1] << P101_INET_CLASS_B_SHIFT) | (parts[2] << P101_INET_CLASS_C_SHIFT) | parts[3];
            break;
        default:
            return 0;
    }

    return value == P101_INET_ADDR_NONE_VALUE;
}

uint32_t p101_htonl(const struct p101_env *env, uint32_t hostlong)
{
    uint32_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = htonl(hostlong);

    P101_TRACE_EXIT(env);
    return ret_val;
}

uint16_t p101_htons(const struct p101_env *env, uint16_t hostshort)
{
    uint16_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = htons(hostshort);

    P101_TRACE_EXIT(env);
    return ret_val;
}

uint32_t p101_ntohl(const struct p101_env *env, uint32_t netlong)
{
    uint32_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = ntohl(netlong);

    P101_TRACE_EXIT(env);
    return ret_val;
}

uint16_t p101_ntohs(const struct p101_env *env, uint16_t netshort)
{
    uint16_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = ntohs(netshort);

    P101_TRACE_EXIT(env);
    return ret_val;
}

in_addr_t p101_inet_addr(const struct p101_env *env, struct p101_error *err, const char *cp)
{
    in_addr_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, INADDR_NONE);
    errno   = 0;
    ret_val = inet_addr(cp);

    if(ret_val == (in_addr_t)-1 && !is_inet_addr_none_string(env, cp))
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

char *p101_inet_ntoa(const struct p101_env *env, struct in_addr in)
{
    char *ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = inet_ntoa(in);

    P101_TRACE_EXIT(env);
    return ret_val;
}

const char *p101_inet_ntop(const struct p101_env *env, struct p101_error *err, int af, const void *restrict src, char *restrict dst, socklen_t size)
{
    const char *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, NULL);
    errno   = 0;
    ret_val = inet_ntop(af, src, dst, size);

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_inet_pton(const struct p101_env *env, struct p101_error *err, int af, const char *restrict src, void *restrict dst)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    errno   = 0;
    ret_val = inet_pton(af, src, dst);

    if(ret_val != 1)
    {
        if(ret_val == 0)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
        }
        else
        {
            P101_ERROR_RAISE_ERRNO(err, errno);
        }
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}
