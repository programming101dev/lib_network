#include <errno.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_network/network.h>
#include <stdio.h>
#include <stdlib.h>

static int failures;

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                                   \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

struct fault_state
{
    int checks;
    int errnum;
};

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return state->errnum;
}

/* P101_TEST_CASE(p101_accept) */
static void test_p101_accept(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EBADF, ECONNABORTED, EFAULT, EINTR, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOTSOCK, EOPNOTSUPP, EPERM, EPROTO, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, ECONNABORTED, EFAULT, EINTR, EINVAL, EMFILE, ENFILE, ENOMEM, ENOTSOCK, EOPNOTSUPP, EWOULDBLOCK};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAGAIN, EBADF, ECONNABORTED, EFAULT, EINTR, EINVAL, EMFILE, ENFILE, ENOTSOCK, EWOULDBLOCK};
#else
    static const int errors[] = {EAGAIN, EBADF, ECONNABORTED, EINTR, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, ENOTSOCK, EOPNOTSUPP, EPROTO, EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_accept(env, err, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_bind) */
static void test_p101_bind(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EBADF, EFAULT, EINVAL, ELOOP, ENAMETOOLONG, ENOENT, ENOMEM, ENOTDIR, ENOTSOCK, EROFS};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EBADF, EDESTADDRREQ, EEXIST, EFAULT, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTSOCK, EOPNOTSUPP, EROFS};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EBADF, EFAULT, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTSOCK, EROFS};
#else
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY, EBADF, EDESTADDRREQ, EILSEQ, EINPROGRESS, EINVAL, EIO, EISCONN, EISDIR, ELOOP, ENAMETOOLONG, ENOBUFS, ENOENT, ENOTDIR, ENOTSOCK, EOPNOTSUPP, EROFS};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_bind(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_connect) */
static void test_p101_connect(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK, EPROTOTYPE, ETIMEDOUT};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY, EBADF,       ECONNREFUSED, ECONNRESET, EFAULT,  EHOSTUNREACH, EINPROGRESS, EINTR,      EINVAL,
                                 EIO,    EISCONN,    ELOOP,         ENAMETOOLONG, ENETDOWN, ENETUNREACH, ENOBUFS,      ENOENT,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP,  EPROTOTYPE, ETIMEDOUT};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,       EALREADY,    EBADF,  ECONNREFUSED, ECONNRESET, EFAULT, EHOSTUNREACH, EINPROGRESS,
                                 EINTR,  EINVAL,     EISCONN,       ELOOP,        ENAMETOOLONG, ENETUNREACH, ENOENT, ENOTDIR,      ENOTSOCK,   EPERM,  ETIMEDOUT};
#else
    static const int errors[] = {EACCES,  EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY,    EBADF,   ECONNREFUSED, ECONNRESET, EHOSTUNREACH, EINPROGRESS, EINTR,      EINVAL,   EIO,
                                 EISCONN, ELOOP,      ENAMETOOLONG,  ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,       ENOTDIR,    ENOTSOCK,     EOPNOTSUPP,  EPROTOTYPE, ETIMEDOUT};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_connect(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_aton) */
static void test_p101_ether_aton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct ether_addr *result = p101_ether_aton(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_hostton) */
static void test_p101_ether_hostton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_hostton(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_line) */
static void test_p101_ether_line(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_line(env, err, NULL, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_ntohost) */
static void test_p101_ether_ntohost(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_ntohost(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getaddrinfo) */
static void test_p101_getaddrinfo(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getaddrinfo(env, err, NULL, NULL, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getifaddrs) */
static void test_p101_getifaddrs(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EALREADY, EBADF,  ECONNREFUSED, ECONNRESET, EDESTADDRREQ, EFAULT,     EINTR, EINVAL,          EISCONN, ELOOP,
                                 EMFILE, EMSGSIZE,   ENAMETOOLONG,  ENFILE,       ENOBUFS, ENOENT,   ENOMEM, ENOTCONN,     ENOTDIR,    ENOTSOCK,     EOPNOTSUPP, EPIPE, EPROTONOSUPPORT, EROFS,   EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, EPERM, EPROTONOSUPPORT, EPROTOTYPE};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getifaddrs(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getnameinfo) */
static void test_p101_getnameinfo(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getnameinfo(env, err, NULL, 0, NULL, 0, NULL, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpeername) */
static void test_p101_getpeername(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, ECONNRESET, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
#else
    static const int errors[] = {EBADF, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpeername(env, err, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getsockname) */
static void test_p101_getsockname(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTSOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, ECONNRESET, EFAULT, EINVAL, ENOBUFS, ENOTSOCK};
#else
    static const int errors[] = {EBADF, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getsockname(env, err, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getsockopt) */
static void test_p101_getsockopt(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOPROTOOPT, ENOTSOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, EDOM, EFAULT, EINVAL, EISCONN, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
#else
    static const int errors[] = {EACCES, EBADF, EINVAL, ENOBUFS, ENOPROTOOPT, ENOTSOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getsockopt(env, err, 0, 0, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_indextoname) */
static void test_p101_if_indextoname(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENODEV, ENOMEM, ENXIO, EPROTONOSUPPORT};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {ENXIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_if_indextoname(env, err, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_nameindex) */
static void test_p101_if_nameindex(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EALREADY, EBADF,  ECONNREFUSED, ECONNRESET, EDESTADDRREQ, EFAULT,     EINTR, EINVAL,          EISCONN, ELOOP,
                                 EMFILE, EMSGSIZE,   ENAMETOOLONG,  ENFILE,       ENOBUFS, ENOENT,   ENOMEM, ENOTCONN,     ENOTDIR,    ENOTSOCK,     EOPNOTSUPP, EPIPE, EPROTONOSUPPORT, EROFS,   EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {ENOBUFS};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct if_nameindex *result = p101_if_nameindex(env, err);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_nametoindex) */
static void test_p101_if_nametoindex(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENODEV, ENOMEM, ENXIO, EPROTONOSUPPORT};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        unsigned int result = p101_if_nametoindex(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_addr) */
static void test_p101_inet_addr(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        in_addr_t result = p101_inet_addr(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_aton) */
static void test_p101_inet_aton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_aton(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_makeaddr) */
static void test_p101_inet_makeaddr(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_makeaddr(env, err, 0, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_net_ntop) */
static void test_p101_inet_net_ntop(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAFNOSUPPORT, EMSGSIZE, ENOENT};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_inet_net_ntop(env, err, 0, NULL, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_net_pton) */
static void test_p101_inet_net_pton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAFNOSUPPORT, EMSGSIZE, ENOENT};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_net_pton(env, err, 0, NULL, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_network) */
static void test_p101_inet_network(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EIO};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        in_addr_t result = p101_inet_network(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_ntop) */
static void test_p101_inet_ntop(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        const char *result = p101_inet_ntop(env, err, 0, NULL, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_pton) */
static void test_p101_inet_pton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#else
    static const int errors[] = {EAFNOSUPPORT, ENOSPC};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_pton(env, err, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_listen) */
static void test_p101_listen(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EADDRINUSE, EBADF, ENOTSOCK, EOPNOTSUPP};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EBADF, EDESTADDRREQ, EINVAL, ENOTSOCK, EOPNOTSUPP};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, EDESTADDRREQ, EINVAL, ENOTSOCK, EOPNOTSUPP};
#else
    static const int errors[] = {EACCES, EBADF, EDESTADDRREQ, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_listen(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recv) */
static void test_p101_recv(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOMEM, ENOTCONN, ENOTSOCK, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EMFILE, EMSGSIZE, ENOTCONN, ENOTSOCK};
#else
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recv(env, err, 0, NULL, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recvfrom) */
static void test_p101_recvfrom(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOMEM, ENOTCONN, ENOTSOCK, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EMFILE, EMSGSIZE, ENOTCONN, ENOTSOCK};
#else
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recvfrom(env, err, 0, NULL, 0, 0, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recvmsg) */
static void test_p101_recvmsg(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOMEM, ENOTCONN, ENOTSOCK, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EMFILE, EMSGSIZE, ENOTCONN, ENOTSOCK};
#else
    static const int errors[] = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recvmsg(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_send) */
static void test_p101_send(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES,   EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EBADF,  ECONNRESET, EDESTADDRREQ, EFAULT,  EHOSTUNREACH, EINTR,      EINVAL, EISCONN,
                                 EMSGSIZE, ENETDOWN,      ENETUNREACH,  ENOBUFS, ENOENT, ENOMEM,     ENOTCONN,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP, EPIPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
#else
    static const int errors[] = {EACCES, EAGAIN, EBADF, ECONNRESET, EDESTADDRREQ, EINTR, EIO, EMSGSIZE, ENETDOWN, ENETUNREACH, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_send(env, err, 0, NULL, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sendmsg) */
static void test_p101_sendmsg(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES,   EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EBADF,  ECONNRESET, EDESTADDRREQ, EFAULT,  EHOSTUNREACH, EINTR,      EINVAL, EISCONN,
                                 EMSGSIZE, ENETDOWN,      ENETUNREACH,  ENOBUFS, ENOENT, ENOMEM,     ENOTCONN,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP, EPIPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
#else
    static const int errors[] = {EACCES,       EAFNOSUPPORT, EAGAIN,      EBADF,   ECONNRESET, EDESTADDRREQ, EHOSTUNREACH, EINTR,   EINVAL,   EIO,        EISCONN, ELOOP,      EMSGSIZE,
                                 ENAMETOOLONG, ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,     ENOMEM,       ENOTCONN,     ENOTDIR, ENOTSOCK, EOPNOTSUPP, EPIPE,   EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_sendmsg(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sendto) */
static void test_p101_sendto(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES,   EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EBADF,  ECONNRESET, EDESTADDRREQ, EFAULT,  EHOSTUNREACH, EINTR,      EINVAL, EISCONN,
                                 EMSGSIZE, ENETDOWN,      ENETUNREACH,  ENOBUFS, ENOENT, ENOMEM,     ENOTCONN,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP, EPIPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
#else
    static const int errors[] = {EACCES,       EAFNOSUPPORT, EAGAIN,      EBADF,   ECONNRESET, EDESTADDRREQ, EHOSTUNREACH, EINTR,   EINVAL,   EIO,        EISCONN, ELOOP,      EMSGSIZE,
                                 ENAMETOOLONG, ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,     ENOMEM,       ENOTCONN,     ENOTDIR, ENOTSOCK, EOPNOTSUPP, EPIPE,   EWOULDBLOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_sendto(env, err, 0, NULL, 0, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setsockopt) */
static void test_p101_setsockopt(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOPROTOOPT, ENOTSOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, EDOM, EFAULT, EINVAL, EISCONN, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
#else
    static const int errors[] = {EBADF, EDOM, EINVAL, EISCONN, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setsockopt(env, err, 0, 0, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_shutdown) */
static void test_p101_shutdown(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
#else
    static const int errors[] = {EBADF, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_shutdown(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sockatmark) */
static void test_p101_sockatmark(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINVAL};
#elif defined(__APPLE__)
    static const int errors[] = {EBADF, ENOTTY};
#elif defined(__FreeBSD__)
    static const int errors[] = {EBADF, ENOTTY};
#else
    static const int errors[] = {EBADF, ENOTTY};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_sockatmark(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_socket) */
static void test_p101_socket(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, EPERM, EPROTONOSUPPORT, EPROTOTYPE};
#else
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE, ESOCKTNOSUPPORT};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_socket(env, err, 0, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_socketpair) */
static void test_p101_socketpair(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAFNOSUPPORT, EFAULT, EMFILE, ENFILE, EOPNOTSUPP, EPROTONOSUPPORT};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EAFNOSUPPORT, EFAULT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EOPNOTSUPP, EPROTONOSUPPORT, EPROTOTYPE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EAFNOSUPPORT, EFAULT, EMFILE, EOPNOTSUPP, EPROTONOSUPPORT};
#else
    static const int errors[] = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EOPNOTSUPP, EPROTONOSUPPORT, EPROTOTYPE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_socketpair(env, err, 0, 0, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

int main(void)
{
    struct p101_error *err;
    struct p101_env   *env;

    err = p101_error_create(false);
    if(err == NULL)
    {
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        return EXIT_FAILURE;
    }
    test_p101_accept(env, err);
    test_p101_bind(env, err);
    test_p101_connect(env, err);
    test_p101_ether_aton(env, err);
    test_p101_ether_hostton(env, err);
    test_p101_ether_line(env, err);
    test_p101_ether_ntohost(env, err);
    test_p101_getaddrinfo(env, err);
    test_p101_getifaddrs(env, err);
    test_p101_getnameinfo(env, err);
    test_p101_getpeername(env, err);
    test_p101_getsockname(env, err);
    test_p101_getsockopt(env, err);
    test_p101_if_indextoname(env, err);
    test_p101_if_nameindex(env, err);
    test_p101_if_nametoindex(env, err);
    test_p101_inet_addr(env, err);
    test_p101_inet_aton(env, err);
    test_p101_inet_makeaddr(env, err);
    test_p101_inet_net_ntop(env, err);
    test_p101_inet_net_pton(env, err);
    test_p101_inet_network(env, err);
    test_p101_inet_ntop(env, err);
    test_p101_inet_pton(env, err);
    test_p101_listen(env, err);
    test_p101_recv(env, err);
    test_p101_recvfrom(env, err);
    test_p101_recvmsg(env, err);
    test_p101_send(env, err);
    test_p101_sendmsg(env, err);
    test_p101_sendto(env, err);
    test_p101_setsockopt(env, err);
    test_p101_shutdown(env, err);
    test_p101_sockatmark(env, err);
    test_p101_socket(env, err);
    test_p101_socketpair(env, err);
    p101_env_destroy(env);
    p101_error_destroy(err);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
