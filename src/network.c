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
    int           p101_single_result_;
    unsigned long parts[P101_INET_ADDR_PARTS];
    unsigned long value;
    const char   *p;
    int           count;

    p     = cp;
    count = 0;

    while(1)
    {
        char *end;
        int   digit;

        digit = p101_isdigit(env, (unsigned char)*p);
        if(!digit || count >= P101_INET_ADDR_PARTS)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }

        errno = 0;
        /* P101_ERROR_OPTIONAL rationale: parser treats conversion failure as an invalid address */
        parts[count] = p101_strtoul(env, P101_ERROR_OPTIONAL, p, &end, 0);
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

    switch(count)
    {
        case 1:
            value = parts[0];
            break;
        case 2:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_CLASS_A_REST)
            {
                p101_single_result_ = 0;
                goto p101_single_exit_;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | parts[1];
            break;
        case 3:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_OCTET_MAX || parts[2] > P101_INET_CLASS_B_REST)
            {
                p101_single_result_ = 0;
                goto p101_single_exit_;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | (parts[1] << P101_INET_CLASS_B_SHIFT) | parts[2];
            break;
        case 4:
            if(parts[0] > P101_INET_OCTET_MAX || parts[1] > P101_INET_OCTET_MAX || parts[2] > P101_INET_OCTET_MAX || parts[3] > P101_INET_OCTET_MAX)
            {
                p101_single_result_ = 0;
                goto p101_single_exit_;
            }
            value = (parts[0] << P101_INET_CLASS_A_SHIFT) | (parts[1] << P101_INET_CLASS_B_SHIFT) | (parts[2] << P101_INET_CLASS_C_SHIFT) | parts[3];
            break;
        default:
            p101_single_result_ = 0;
            goto p101_single_exit_;
    }

    p101_single_result_ = value == P101_INET_ADDR_NONE_VALUE;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
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
    int       none_string;
    in_addr_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (in_addr_t)P101_INET_ADDR_NONE_VALUE);
    errno   = 0;
    ret_val = inet_addr(cp);

    none_string = 0;
    if(ret_val == (in_addr_t)-1)
    {
        none_string = is_inet_addr_none_string(env, cp);
    }
    if(ret_val == (in_addr_t)-1 && !none_string)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
    }

    P101_WRAPPER_DONE(env);
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
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    errno   = 0;
    ret_val = inet_ntop(af, src, dst, size);

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_inet_pton(const struct p101_env *env, struct p101_error *err, int af, const char *restrict src, void *restrict dst)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
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

    P101_WRAPPER_DONE(env);
    return ret_val;
}

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
    P101_TRACK_POINTER_RESOURCE_RELEASE(env, "address-info", ai, NULL);
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
    errno   = 0;
    ret_val = getaddrinfo(nodename, servname, hints, res);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_SYSTEM(err, p101_gai_strerror(env, ret_val), ret_val);
    }
    else if(res != NULL && *res != NULL)
    {
        P101_TRACK_POINTER_RESOURCE_ACQUIRE(env, "address-info", *res, 0U, NULL);
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

int p101_accept(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
{
    int p101_single_result_;
    int ret_val;
    int fault;

    P101_TRACE(env);
    fault = p101_env_check_fault(env, __func__);

    if(fault != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, fault);
        P101_TRACE_EXIT(env);

        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    errno   = 0;
    ret_val = accept(socket, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        /* The accepted connection is a NEW descriptor, distinct from the
         * listening socket. Forgetting to close it is the classic server fd
         * leak, so it goes in the ledger. */
        P101_TRACK_OPEN(env, ret_val);
    }

    P101_TRACE_EXIT(env);

    p101_single_result_ = ret_val;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_bind(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = bind(socket, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_connect(const struct p101_env *env, struct p101_error *err, int socket, const struct sockaddr *address, socklen_t address_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = connect(socket, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getpeername(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = getpeername(socket, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getsockname(const struct p101_env *env, struct p101_error *err, int socket, struct sockaddr *restrict address, socklen_t *restrict address_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = getsockname(socket, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = getsockopt(socket, level, option_name, option_value, option_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_listen(const struct p101_env *env, struct p101_error *err, int socket, int backlog)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = listen(socket, backlog);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_recv(const struct p101_env *env, struct p101_error *err, int socket, void *buffer, size_t length, int flags)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = recv(socket, buffer, length, flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_recvfrom(const struct p101_env *env, struct p101_error *err, int socket, void *restrict buffer, size_t length, int flags, struct sockaddr *restrict address, socklen_t *restrict address_len)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = recvfrom(socket, buffer, length, flags, address, address_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_recvmsg(const struct p101_env *env, struct p101_error *err, int socket, struct msghdr *message, int flags)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = recvmsg(socket, message, flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_send(const struct p101_env *env, struct p101_error *err, int socket, const void *buffer, size_t length, int flags)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = send(socket, buffer, length, flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_sendmsg(const struct p101_env *env, struct p101_error *err, int socket, const struct msghdr *message, int flags)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = sendmsg(socket, message, flags);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

ssize_t p101_sendto(const struct p101_env *env, struct p101_error *err, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    ssize_t ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, (ssize_t)-1);
    errno   = 0;
    ret_val = sendto(socket, message, length, flags, dest_addr, dest_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_setsockopt(const struct p101_env *env, struct p101_error *err, int socket, int level, int option_name, const void *option_value, socklen_t option_len)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setsockopt(socket, level, option_name, option_value, option_len);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_shutdown(const struct p101_env *env, struct p101_error *err, int socket, int how)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = shutdown(socket, how);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_sockatmark(const struct p101_env *env, struct p101_error *err, int s)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = sockatmark(s);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_socket(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol)
{
    int p101_single_result_;
    int ret_val;
    int fault;

    P101_TRACE(env);
    fault = p101_env_check_fault(env, __func__);

    if(fault != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, fault);
        P101_TRACE_EXIT(env);

        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    errno   = 0;
    ret_val = socket(domain, type, protocol);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        P101_TRACK_OPEN(env, ret_val);
    }

    P101_TRACE_EXIT(env);

    p101_single_result_ = ret_val;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_socketpair(const struct p101_env *env, struct p101_error *err, int domain, int type, int protocol, int socket_vector[2])
{
    int p101_single_result_;
    int ret_val;
    int fault;

    P101_TRACE(env);
    fault = p101_env_check_fault(env, __func__);

    if(fault != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, fault);
        P101_TRACE_EXIT(env);

        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    errno   = 0;
    ret_val = socketpair(domain, type, protocol, socket_vector);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        /* Two descriptors come back, and both have to be closed. */
        P101_TRACK_OPEN(env, socket_vector[0]);
        P101_TRACK_OPEN(env, socket_vector[1]);
    }

    P101_TRACE_EXIT(env);

    p101_single_result_ = ret_val;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

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

enum
{
    P101_INET_CLASS_A_HOST      = 0x00ffffffU,
    P101_INET_CLASS_A_LIMIT     = 128U,
    P101_INET_CLASS_A_NSHIFT    = 24,
    P101_INET_CLASS_B_HOST      = 0x0000ffffU,
    P101_INET_CLASS_B_LIMIT     = 65536U,
    P101_INET_CLASS_B_NSHIFT    = 16,
    P101_INET_CLASS_C_HOST      = 0x000000ffU,
    P101_INET_CLASS_C_LIMIT     = 16777216U,
    P101_INET_CLASS_C_NSHIFT    = 8,
    P101_INET_LEGACY_OCTET_MAX  = 255U,
    P101_INET_LEGACY_ADDR_PARTS = 4
};

static const unsigned long P101_INET_LEGACY_ADDR_NONE_VALUE = 0xffffffffUL;
static const unsigned long P101_INET_LEGACY_TWO_BYTE_MAX    = 0xffffUL;
static const unsigned long P101_INET_LEGACY_THREE_BYTE_MAX  = 0xffffffUL;

/*
 * inet_network() accepts the historic one-, two-, three-, and four-component
 * IPv4 grammar, with C integer radices. INADDR_NONE is both its failure value
 * and a valid result, so recognize every valid spelling of 0xffffffff.
 */
static int is_legacy_inet_addr_none_string(const struct p101_env *env, const char *cp)
{
    int           p101_single_result_;
    unsigned long parts[P101_INET_LEGACY_ADDR_PARTS];
    const char   *p;
    int           count;
    int           bytes;

    count = 0;
    p     = cp;

    while(1)
    {
        char *end;
        int   digit;

        digit = p101_isdigit(env, (unsigned char)*p);
        if(!digit || count >= P101_INET_LEGACY_ADDR_PARTS)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }

        errno = 0;
        /* P101_ERROR_OPTIONAL rationale: parser treats conversion failure as an invalid address */
        parts[count] = p101_strtoul(env, P101_ERROR_OPTIONAL, p, &end, 0);
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
        if(parts[index] == P101_INET_LEGACY_OCTET_MAX)
        {
            bytes += 1;
        }
        else if(parts[index] == P101_INET_LEGACY_TWO_BYTE_MAX)
        {
            bytes += 2;
        }
        else if(parts[index] == P101_INET_LEGACY_THREE_BYTE_MAX)
        {
            bytes += 3;
        }
        else if(parts[index] == P101_INET_LEGACY_ADDR_NONE_VALUE)
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
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, ~(in_addr_t)0);
    ret_val      = inet_network(cp);
    native_errno = errno;

    // INADDR_NONE is ambiguous: it is both the error return and the correct
    // parse of "255.255.255.255". Only raise when it really was a failure, so
    // callers can rely on the p101 error instead of comparing the value.
    if(ret_val == ~(in_addr_t)0)
    {
        int valid;

        valid = is_legacy_inet_addr_none_string(env, cp);
        errno = native_errno;
        if(!valid)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
        }
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

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

#include <net/ethernet.h>

#ifdef __linux__
    #include <netinet/ether.h>
#endif

struct ether_addr *p101_ether_aton(const struct p101_env *env, struct p101_error *err, const char *asc)
{
    struct ether_addr *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    ret_val = ether_aton(asc);

    if(ret_val == NULL)
    {
        // ether_aton() does not set errno on a bad address string.
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_ether_hostton(const struct p101_env *env, struct p101_error *err, const char *hostname, struct ether_addr *addr)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
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

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_ether_line(const struct p101_env *env, struct p101_error *err, const char *line, struct ether_addr *addr, char *hostname)
{
    int actual_errno;
    int caller_errno;
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
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

    P101_WRAPPER_DONE(env);
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
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
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

    P101_WRAPPER_DONE(env);
    return ret_val;
}
