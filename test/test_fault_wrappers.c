#include <arpa/inet.h>
#include <errno.h>
#include <fmtmsg.h>
#include <fnmatch.h>
#include <math.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_network/network.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int    failures;
static size_t fault_resource_events;
static FILE  *outcome_stream;

#define P101_TEST_ERRNO_SENTINEL 0x5A5A

#ifdef __linux__
    #define P101_TEST_PLATFORM "linux"
#elif defined(__APPLE__)
    #define P101_TEST_PLATFORM "macos"
#elif defined(__FreeBSD__)
    #define P101_TEST_PLATFORM "freebsd"
#else
    #define P101_TEST_PLATFORM "posix"
#endif

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
    int code;
};

static void write_outcome(const char *wrapper, const char *domain, const char *symbol, int code, int passed)
{
    int written;

    if(outcome_stream == NULL)
    {
        return;
    }
    written = fprintf(outcome_stream, "P101WRAPPER\t1\tFAULT\t%s\tlib_network\t%s\t%s\t%s\t%d\t%s\n", P101_TEST_PLATFORM, wrapper, domain, symbol, code, passed ? "PASS" : "FAIL");
    if(written < 0 || fflush(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot write wrapper outcome receipt\n");
        failures++;
    }
}

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return state->code;
}

static void count_fd_event(const struct p101_env *env, p101_env_fd_event event, int fd, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)fd;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_alloc_event(const struct p101_env *env, p101_env_alloc_event event, const void *ptr, const void *new_ptr, size_t size, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)ptr;
    (void)new_ptr;
    (void)size;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_resource_event(const struct p101_env *env, p101_env_resource_kind event, const char *resource_class, const char *resource_id, const char *related_id, size_t size, const char *metadata, const char *file_name, const char *function_name,
                                 int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)resource_class;
    (void)resource_id;
    (void)related_id;
    (void)size;
    (void)metadata;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

/* P101_TEST_CASE(p101_accept) */
static void test_p101_accept(struct p101_env *env, struct p101_error *err)
{
    socklen_t     argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EBADF, ECONNABORTED, EINTR, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, ENOTSOCK, EOPNOTSUPP, EPROTO, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNABORTED", "EINTR", "EINVAL", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "ENOTSOCK", "EOPNOTSUPP", "EPROTO", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, ECONNABORTED, EFAULT, EINTR, EINVAL, EMFILE, ENFILE, ENOMEM, ENOTSOCK, EOPNOTSUPP, EWOULDBLOCK};
    static const char *const error_names[] = {"EBADF", "ECONNABORTED", "EFAULT", "EINTR", "EINVAL", "EMFILE", "ENFILE", "ENOMEM", "ENOTSOCK", "EOPNOTSUPP", "EWOULDBLOCK"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNABORTED, EFAULT, EINTR, EINVAL, EMFILE, ENFILE, ENOTSOCK, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNABORTED", "EFAULT", "EINTR", "EINVAL", "EMFILE", "ENFILE", "ENOTSOCK", "EWOULDBLOCK"};
#else
    static const int         errors[]      = {EAGAIN, EBADF, ECONNABORTED, EINTR, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, ENOTSOCK, EOPNOTSUPP, EPROTO, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNABORTED", "EINTR", "EINVAL", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "ENOTSOCK", "EOPNOTSUPP", "EPROTO", "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_accept(env, err, 0, NULL, argument_4);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_accept", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_bind) */
static void test_p101_bind(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EBADF, EFAULT, EINVAL, ELOOP, ENAMETOOLONG, ENOENT, ENOMEM, ENOTDIR, ENOTSOCK, EROFS};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EBADF", "EFAULT", "EINVAL", "ELOOP", "ENAMETOOLONG", "ENOENT", "ENOMEM", "ENOTDIR", "ENOTSOCK", "EROFS"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EBADF, EDESTADDRREQ, EEXIST, EFAULT, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTSOCK, EOPNOTSUPP, EROFS};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EBADF", "EDESTADDRREQ", "EEXIST", "EFAULT", "EINVAL", "EIO", "EISDIR", "ELOOP", "ENAMETOOLONG", "ENOENT", "ENOTDIR", "ENOTSOCK", "EOPNOTSUPP", "EROFS"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EBADF, EFAULT, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, ENOTSOCK, EROFS};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN", "EBADF", "EFAULT", "EINVAL", "EIO", "EISDIR", "ELOOP", "ENAMETOOLONG", "ENOENT", "ENOTDIR", "ENOTSOCK", "EROFS"};
#else
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY, EBADF, EDESTADDRREQ, EILSEQ, EINPROGRESS, EINVAL, EIO, EISCONN, EISDIR, ELOOP, ENAMETOOLONG, ENOBUFS, ENOENT, ENOTDIR, ENOTSOCK, EOPNOTSUPP, EROFS};
    static const char *const error_names[] = {"EACCES",  "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EALREADY", "EBADF",  "EDESTADDRREQ", "EILSEQ",   "EINPROGRESS", "EINVAL", "EIO",
                                              "EISCONN", "EISDIR",     "ELOOP",         "ENAMETOOLONG", "ENOBUFS",  "ENOENT", "ENOTDIR",      "ENOTSOCK", "EOPNOTSUPP",  "EROFS"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_bind(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_bind", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_connect) */
static void test_p101_connect(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK, EPROTOTYPE, ETIMEDOUT};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN", "EALREADY", "EBADF", "ECONNREFUSED", "EFAULT", "EINPROGRESS", "EINTR", "EISCONN", "ENETUNREACH", "ENOTSOCK", "EPROTOTYPE", "ETIMEDOUT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY, EBADF,       ECONNREFUSED, ECONNRESET, EFAULT,  EHOSTUNREACH, EINPROGRESS, EINTR,      EINVAL,
                                              EIO,    EISCONN,    ELOOP,         ENAMETOOLONG, ENETDOWN, ENETUNREACH, ENOBUFS,      ENOENT,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP,  EPROTOTYPE, ETIMEDOUT};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EALREADY", "EBADF",       "ECONNREFUSED", "ECONNRESET", "EFAULT",  "EHOSTUNREACH", "EINPROGRESS", "EINTR",      "EINVAL",
                                              "EIO",    "EISCONN",    "ELOOP",         "ENAMETOOLONG", "ENETDOWN", "ENETUNREACH", "ENOBUFS",      "ENOENT",     "ENOTDIR", "ENOTSOCK",     "EOPNOTSUPP",  "EPROTOTYPE", "ETIMEDOUT"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,       EALREADY,    EBADF,  ECONNREFUSED, ECONNRESET, EFAULT, EHOSTUNREACH, EINPROGRESS,
                                              EINTR,  EINVAL,     EISCONN,       ELOOP,        ENAMETOOLONG, ENETUNREACH, ENOENT, ENOTDIR,      ENOTSOCK,   EPERM,  ETIMEDOUT};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN",       "EALREADY",    "EBADF",  "ECONNREFUSED", "ECONNRESET", "EFAULT", "EHOSTUNREACH", "EINPROGRESS",
                                              "EINTR",  "EINVAL",     "EISCONN",       "ELOOP",        "ENAMETOOLONG", "ENETUNREACH", "ENOENT", "ENOTDIR",      "ENOTSOCK",   "EPERM",  "ETIMEDOUT"};
#else
    static const int         errors[]      = {EACCES,  EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EALREADY,    EBADF,   ECONNREFUSED, ECONNRESET, EHOSTUNREACH, EINPROGRESS, EINTR,      EINVAL,   EIO,
                                              EISCONN, ELOOP,      ENAMETOOLONG,  ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,       ENOTDIR,    ENOTSOCK,     EOPNOTSUPP,  EPROTOTYPE, ETIMEDOUT};
    static const char *const error_names[] = {"EACCES",  "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EALREADY",    "EBADF",   "ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "EINPROGRESS", "EINTR",      "EINVAL",   "EIO",
                                              "EISCONN", "ELOOP",      "ENAMETOOLONG",  "ENETDOWN",     "ENETUNREACH", "ENOBUFS", "ENOENT",       "ENOTDIR",    "ENOTSOCK",     "EOPNOTSUPP",  "EPROTOTYPE", "ETIMEDOUT"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_connect(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_connect", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_aton) */
static void test_p101_ether_aton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct ether_addr *result = p101_ether_aton(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_ether_aton", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_hostton) */
static void test_p101_ether_hostton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_hostton(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_ether_hostton", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_line) */
static void test_p101_ether_line(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_line(env, err, NULL, NULL, argument_4);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_ether_line", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_ether_ntohost) */
static void test_p101_ether_ntohost(struct p101_env *env, struct p101_error *err)
{
    char          argument_2[4];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_ether_ntohost(env, err, argument_2, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_ether_ntohost", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getaddrinfo) */
static void test_p101_getaddrinfo(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_BADHINTS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_OVERFLOW, EAI_PROTOCOL, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_BADHINTS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_OVERFLOW", "EAI_PROTOCOL", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_BADHINTS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_OVERFLOW, EAI_PROTOCOL, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_BADHINTS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_OVERFLOW", "EAI_PROTOCOL", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#else
    static const int         errors[]      = {EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NONAME, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_AGAIN", "EAI_BADFLAGS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NONAME", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getaddrinfo(env, err, NULL, NULL, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_error(err, P101_ERROR_SYSTEM, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getaddrinfo", "system", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getifaddrs) */
static void test_p101_getifaddrs(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EALREADY, EBADF,  ECONNREFUSED, ECONNRESET, EDESTADDRREQ, EFAULT,     EINTR, EINVAL,          EISCONN, ELOOP,
                                              EMFILE, EMSGSIZE,   ENAMETOOLONG,  ENFILE,       ENOBUFS, ENOENT,   ENOMEM, ENOTCONN,     ENOTDIR,    ENOTSOCK,     EOPNOTSUPP, EPIPE, EPROTONOSUPPORT, EROFS,   EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN",  "EALREADY", "EBADF",  "ECONNREFUSED", "ECONNRESET", "EDESTADDRREQ", "EFAULT",     "EINTR", "EINVAL",          "EISCONN", "ELOOP",
                                              "EMFILE", "EMSGSIZE",   "ENAMETOOLONG",  "ENFILE",       "ENOBUFS", "ENOENT",   "ENOMEM", "ENOTCONN",     "ENOTDIR",    "ENOTSOCK",     "EOPNOTSUPP", "EPIPE", "EPROTONOSUPPORT", "EROFS",   "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EPROTONOSUPPORT", "EPROTOTYPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, EPERM, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "EPERM", "EPROTONOSUPPORT", "EPROTOTYPE"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getifaddrs(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getifaddrs", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getnameinfo) */
static void test_p101_getnameinfo(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
    char          argument_6[4];
    unsigned char argument_6_before[sizeof(argument_6)];
    memset(argument_6, 0xA5, sizeof(argument_6));
    memcpy(argument_6_before, argument_6, sizeof(argument_6));
#ifdef __linux__
    static const int         errors[]      = {EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NONAME, EAI_OVERFLOW, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_AGAIN", "EAI_BADFLAGS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NONAME", "EAI_OVERFLOW", "EAI_SYSTEM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_BADHINTS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_OVERFLOW, EAI_PROTOCOL, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_BADHINTS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_OVERFLOW", "EAI_PROTOCOL", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_BADHINTS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_OVERFLOW, EAI_PROTOCOL, EAI_SERVICE, EAI_SOCKTYPE, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_BADHINTS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_OVERFLOW", "EAI_PROTOCOL", "EAI_SERVICE", "EAI_SOCKTYPE", "EAI_SYSTEM"};
#else
    static const int         errors[]      = {EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, EAI_MEMORY, EAI_NONAME, EAI_OVERFLOW, EAI_SYSTEM};
    static const char *const error_names[] = {"EAI_AGAIN", "EAI_BADFLAGS", "EAI_FAIL", "EAI_FAMILY", "EAI_MEMORY", "EAI_NONAME", "EAI_OVERFLOW", "EAI_SYSTEM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getnameinfo(env, err, NULL, 0, argument_4, 0, argument_6, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_error(err, P101_ERROR_SYSTEM, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(memcmp(argument_6, argument_6_before, sizeof(argument_6)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getnameinfo", "system", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpeername) */
static void test_p101_getpeername(struct p101_env *env, struct p101_error *err)
{
    socklen_t     argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, ECONNRESET, EFAULT, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "ECONNRESET", "EFAULT", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK"};
#else
    static const int         errors[]      = {EBADF, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpeername(env, err, 0, NULL, argument_4);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getpeername", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getsockname) */
static void test_p101_getsockname(struct p101_env *env, struct p101_error *err)
{
    socklen_t     argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOBUFS", "ENOTSOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOBUFS", "ENOTSOCK", "EOPNOTSUPP"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, ECONNRESET, EFAULT, EINVAL, ENOBUFS, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "ECONNRESET", "EFAULT", "EINVAL", "ENOBUFS", "ENOTSOCK"};
#else
    static const int         errors[]      = {EBADF, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOBUFS", "ENOTSOCK", "EOPNOTSUPP"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getsockname(env, err, 0, NULL, argument_4);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getsockname", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getsockopt) */
static void test_p101_getsockopt(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_5[64];
    unsigned char argument_5_before[sizeof(argument_5)];
    memset(argument_5, 0xA5, sizeof(argument_5));
    memcpy(argument_5_before, argument_5, sizeof(argument_5));
    socklen_t     argument_6[4];
    unsigned char argument_6_before[sizeof(argument_6)];
    memset(argument_6, 0xA5, sizeof(argument_6));
    memcpy(argument_6_before, argument_6, sizeof(argument_6));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EFAULT, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EFAULT", "ENOPROTOOPT", "ENOTSOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOBUFS", "ENOMEM", "ENOPROTOOPT", "ENOTSOCK"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, EFAULT, EINVAL, ENOMEM, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EFAULT", "EINVAL", "ENOMEM", "ENOPROTOOPT", "ENOTSOCK"};
#else
    static const int         errors[]      = {EACCES, EBADF, EINVAL, ENOBUFS, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EACCES", "EBADF", "EINVAL", "ENOBUFS", "ENOPROTOOPT", "ENOTSOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getsockopt(env, err, 0, 0, 0, argument_5, argument_6);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_5, argument_5_before, sizeof(argument_5)) == 0);
        EXPECT(memcmp(argument_6, argument_6_before, sizeof(argument_6)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getsockopt", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_indextoname) */
static void test_p101_if_indextoname(struct p101_env *env, struct p101_error *err)
{
    char          argument_3[4];
    unsigned char argument_3_before[sizeof(argument_3)];
    memset(argument_3, 0xA5, sizeof(argument_3));
    memcpy(argument_3_before, argument_3, sizeof(argument_3));
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, ENXIO, EPROTONOSUPPORT};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EINVAL", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "ENXIO", "EPROTONOSUPPORT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {ENXIO};
    static const char *const error_names[] = {"ENXIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {ENXIO};
    static const char *const error_names[] = {"ENXIO"};
#else
    static const int         errors[]      = {ENXIO};
    static const char *const error_names[] = {"ENXIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_if_indextoname(env, err, 0, argument_3);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(memcmp(argument_3, argument_3_before, sizeof(argument_3)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_if_indextoname", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_nameindex) */
static void test_p101_if_nameindex(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EALREADY, EBADF,  ECONNREFUSED, ECONNRESET, EDESTADDRREQ, EFAULT,     EINTR, EINVAL,          EISCONN, ELOOP,
                                              EMFILE, EMSGSIZE,   ENAMETOOLONG,  ENFILE,       ENOBUFS, ENOENT,   ENOMEM, ENOTCONN,     ENOTDIR,    ENOTSOCK,     EOPNOTSUPP, EPIPE, EPROTONOSUPPORT, EROFS,   EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN",  "EALREADY", "EBADF",  "ECONNREFUSED", "ECONNRESET", "EDESTADDRREQ", "EFAULT",     "EINTR", "EINVAL",          "EISCONN", "ELOOP",
                                              "EMFILE", "EMSGSIZE",   "ENAMETOOLONG",  "ENFILE",       "ENOBUFS", "ENOENT",   "ENOMEM", "ENOTCONN",     "ENOTDIR",    "ENOTSOCK",     "EOPNOTSUPP", "EPIPE", "EPROTONOSUPPORT", "EROFS",   "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {ENOBUFS};
    static const char *const error_names[] = {"ENOBUFS"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {ENOBUFS};
    static const char *const error_names[] = {"ENOBUFS"};
#else
    static const int         errors[]      = {ENOBUFS};
    static const char *const error_names[] = {"ENOBUFS"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct if_nameindex *result = p101_if_nameindex(env, err);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_if_nameindex", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_if_nametoindex) */
static void test_p101_if_nametoindex(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENODEV, ENOMEM, EPROTONOSUPPORT};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EINVAL", "EMFILE", "ENFILE", "ENOBUFS", "ENODEV", "ENOMEM", "EPROTONOSUPPORT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        unsigned int result = p101_if_nametoindex(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (0));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_if_nametoindex", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_addr) */
static void test_p101_inet_addr(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        in_addr_t result = p101_inet_addr(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((in_addr_t)INADDR_NONE));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_addr", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_aton) */
static void test_p101_inet_aton(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_aton(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (0));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_aton", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_makeaddr) */
static void test_p101_inet_makeaddr(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_makeaddr(env, err, 0, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_makeaddr", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_net_ntop) */
static void test_p101_inet_net_ntop(struct p101_env *env, struct p101_error *err)
{
    char          argument_5[4];
    unsigned char argument_5_before[sizeof(argument_5)];
    memset(argument_5, 0xA5, sizeof(argument_5));
    memcpy(argument_5_before, argument_5, sizeof(argument_5));
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_inet_net_ntop(env, err, 0, NULL, 0, argument_5, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(memcmp(argument_5, argument_5_before, sizeof(argument_5)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_net_ntop", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_net_pton) */
static void test_p101_inet_net_pton(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_4[64];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EAFNOSUPPORT, EMSGSIZE, ENOENT};
    static const char *const error_names[] = {"EAFNOSUPPORT", "EMSGSIZE", "ENOENT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_net_pton(env, err, 0, NULL, argument_4, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_net_pton", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_network) */
static void test_p101_inet_network(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        in_addr_t result = p101_inet_network(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((in_addr_t)INADDR_NONE));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_network", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_ntop) */
static void test_p101_inet_ntop(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#else
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        const char *result = p101_inet_ntop(env, err, 0, NULL, argument_4, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_ntop", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_inet_pton) */
static void test_p101_inet_pton(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_4[64];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#else
    static const int         errors[]      = {EAFNOSUPPORT, ENOSPC};
    static const char *const error_names[] = {"EAFNOSUPPORT", "ENOSPC"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_inet_pton(env, err, 0, NULL, argument_4);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_inet_pton", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_listen) */
static void test_p101_listen(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EADDRINUSE, EBADF, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EADDRINUSE", "EBADF", "ENOTSOCK", "EOPNOTSUPP"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EBADF, EDESTADDRREQ, EINVAL, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EACCES", "EBADF", "EDESTADDRREQ", "EINVAL", "ENOTSOCK", "EOPNOTSUPP"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, EDESTADDRREQ, EINVAL, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EBADF", "EDESTADDRREQ", "EINVAL", "ENOTSOCK", "EOPNOTSUPP"};
#else
    static const int         errors[]      = {EACCES, EBADF, EDESTADDRREQ, EINVAL, ENOBUFS, ENOTSOCK, EOPNOTSUPP};
    static const char *const error_names[] = {"EACCES", "EBADF", "EDESTADDRREQ", "EINVAL", "ENOBUFS", "ENOTSOCK", "EOPNOTSUPP"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_listen(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_listen", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recv) */
static void test_p101_recv(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_3[64];
    unsigned char argument_3_before[sizeof(argument_3)];
    memset(argument_3, 0xA5, sizeof(argument_3));
    memcpy(argument_3_before, argument_3, sizeof(argument_3));
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#else
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recv(env, err, 0, argument_3, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(memcmp(argument_3, argument_3_before, sizeof(argument_3)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_recv", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recvfrom) */
static void test_p101_recvfrom(struct p101_env *env, struct p101_error *err)
{
    unsigned char argument_3[64];
    unsigned char argument_3_before[sizeof(argument_3)];
    memset(argument_3, 0xA5, sizeof(argument_3));
    memcpy(argument_3_before, argument_3, sizeof(argument_3));
    socklen_t     argument_7[4];
    unsigned char argument_7_before[sizeof(argument_7)];
    memset(argument_7, 0xA5, sizeof(argument_7));
    memcpy(argument_7_before, argument_7, sizeof(argument_7));
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOTCONN, ENOTSOCK, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNREFUSED", "EFAULT", "EINTR", "EINVAL", "ENOTCONN", "ENOTSOCK", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EFAULT", "EINTR", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#else
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recvfrom(env, err, 0, argument_3, 0, 0, NULL, argument_7);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(memcmp(argument_3, argument_3_before, sizeof(argument_3)) == 0);
        EXPECT(memcmp(argument_7, argument_7_before, sizeof(argument_7)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_recvfrom", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_recvmsg) */
static void test_p101_recvmsg(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOMEM, ENOTCONN, ENOTSOCK, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNREFUSED", "EFAULT", "EINTR", "EINVAL", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EFAULT", "EINTR", "EINVAL", "EMSGSIZE", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EMFILE, EMSGSIZE, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EFAULT", "EINTR", "EMFILE", "EMSGSIZE", "ENOTCONN", "ENOTSOCK"};
#else
    static const int         errors[]      = {EAGAIN, EBADF, ECONNRESET, EINTR, EINVAL, EIO, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, ETIMEDOUT, EWOULDBLOCK};
    static const char *const error_names[] = {"EAGAIN", "EBADF", "ECONNRESET", "EINTR", "EINVAL", "EIO", "EMSGSIZE", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "ETIMEDOUT", "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_recvmsg(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_recvmsg", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_send) */
static void test_p101_send(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EALREADY", "EBADF", "ECONNRESET", "EDESTADDRREQ", "EFAULT", "EINTR", "EINVAL", "EISCONN", "EMSGSIZE", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "EPIPE", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EHOSTUNREACH, EINTR, EMSGSIZE, ENETDOWN, ENETUNREACH, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE};
    static const char *const error_names[] = {"EACCES", "EADDRNOTAVAIL", "EAGAIN", "EBADF", "ECONNRESET", "EDESTADDRREQ", "EFAULT", "EHOSTUNREACH", "EINTR", "EMSGSIZE", "ENETDOWN", "ENETUNREACH", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "EPIPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
    static const char *const error_names[] = {"EACCES", "EADDRNOTAVAIL", "EAGAIN", "EBADF", "ECONNREFUSED", "EFAULT", "EHOSTUNREACH", "EISCONN", "EMSGSIZE", "ENETDOWN", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EPIPE"};
#else
    static const int         errors[]      = {EACCES, EAGAIN, EBADF, ECONNRESET, EDESTADDRREQ, EINTR, EIO, EMSGSIZE, ENETDOWN, ENETUNREACH, ENOBUFS, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EBADF", "ECONNRESET", "EDESTADDRREQ", "EINTR", "EIO", "EMSGSIZE", "ENETDOWN", "ENETUNREACH", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "EPIPE", "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_send(env, err, 0, NULL, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_send", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sendmsg) */
static void test_p101_sendmsg(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EALREADY", "EBADF", "ECONNRESET", "EDESTADDRREQ", "EFAULT", "EINTR", "EINVAL", "EISCONN", "EMSGSIZE", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "EPIPE", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES,   EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,  EBADF,  ECONNRESET, EDESTADDRREQ, EFAULT,  EHOSTUNREACH, EINTR,      EINVAL, EISCONN,
                                              EMSGSIZE, ENETDOWN,      ENETUNREACH,  ENOBUFS, ENOENT, ENOMEM,     ENOTCONN,     ENOTDIR, ENOTSOCK,     EOPNOTSUPP, EPIPE};
    static const char *const error_names[] = {"EACCES",   "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN",  "EBADF",  "ECONNRESET", "EDESTADDRREQ", "EFAULT",  "EHOSTUNREACH", "EINTR",      "EINVAL", "EISCONN",
                                              "EMSGSIZE", "ENETDOWN",      "ENETUNREACH",  "ENOBUFS", "ENOENT", "ENOMEM",     "ENOTCONN",     "ENOTDIR", "ENOTSOCK",     "EOPNOTSUPP", "EPIPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
    static const char *const error_names[] = {"EACCES", "EADDRNOTAVAIL", "EAGAIN", "EBADF", "ECONNREFUSED", "EFAULT", "EHOSTUNREACH", "EISCONN", "EMSGSIZE", "ENETDOWN", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EPIPE"};
#else
    static const int         errors[]      = {EACCES,       EAFNOSUPPORT, EAGAIN,      EBADF,   ECONNRESET, EDESTADDRREQ, EHOSTUNREACH, EINTR,   EINVAL,   EIO,        EISCONN, ELOOP,      EMSGSIZE,
                                              ENAMETOOLONG, ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,     ENOMEM,       ENOTCONN,     ENOTDIR, ENOTSOCK, EOPNOTSUPP, EPIPE,   EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES",       "EAFNOSUPPORT", "EAGAIN",      "EBADF",   "ECONNRESET", "EDESTADDRREQ", "EHOSTUNREACH", "EINTR",   "EINVAL",   "EIO",        "EISCONN", "ELOOP",      "EMSGSIZE",
                                              "ENAMETOOLONG", "ENETDOWN",     "ENETUNREACH", "ENOBUFS", "ENOENT",     "ENOMEM",       "ENOTCONN",     "ENOTDIR", "ENOTSOCK", "EOPNOTSUPP", "EPIPE",   "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_sendmsg(env, err, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_sendmsg", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sendto) */
static void test_p101_sendto(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAGAIN, EALREADY, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EINTR, EINVAL, EISCONN, EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, ENOTSOCK, EOPNOTSUPP, EPIPE, EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES", "EAGAIN", "EALREADY", "EBADF", "ECONNRESET", "EDESTADDRREQ", "EFAULT", "EINTR", "EINVAL", "EISCONN", "EMSGSIZE", "ENOBUFS", "ENOMEM", "ENOTCONN", "ENOTSOCK", "EOPNOTSUPP", "EPIPE", "EWOULDBLOCK"};
#elif defined(__APPLE__)
    static const int errors[] = {EACCES, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN, EBADF, ECONNRESET, EDESTADDRREQ, EFAULT, EHOSTUNREACH, EINTR, EISCONN, EMSGSIZE, ENETDOWN, ENETUNREACH, ENOBUFS, ENOENT, ENOMEM, ENOTCONN, ENOTDIR, ENOTSOCK, EOPNOTSUPP, EPIPE};
    static const char *const error_names[] = {"EACCES",   "EADDRNOTAVAIL", "EAFNOSUPPORT", "EAGAIN",  "EBADF",  "ECONNRESET", "EDESTADDRREQ", "EFAULT",  "EHOSTUNREACH", "EINTR",      "EISCONN",
                                              "EMSGSIZE", "ENETDOWN",      "ENETUNREACH",  "ENOBUFS", "ENOENT", "ENOMEM",     "ENOTCONN",     "ENOTDIR", "ENOTSOCK",     "EOPNOTSUPP", "EPIPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EADDRNOTAVAIL, EAGAIN, EBADF, ECONNREFUSED, EFAULT, EHOSTUNREACH, EISCONN, EMSGSIZE, ENETDOWN, ENOBUFS, ENOTCONN, ENOTSOCK, EPIPE};
    static const char *const error_names[] = {"EACCES", "EADDRNOTAVAIL", "EAGAIN", "EBADF", "ECONNREFUSED", "EFAULT", "EHOSTUNREACH", "EISCONN", "EMSGSIZE", "ENETDOWN", "ENOBUFS", "ENOTCONN", "ENOTSOCK", "EPIPE"};
#else
    static const int         errors[]      = {EACCES,       EAFNOSUPPORT, EAGAIN,      EBADF,   ECONNRESET, EDESTADDRREQ, EHOSTUNREACH, EINTR,   EINVAL,   EIO,        EISCONN, ELOOP,      EMSGSIZE,
                                              ENAMETOOLONG, ENETDOWN,     ENETUNREACH, ENOBUFS, ENOENT,     ENOMEM,       ENOTCONN,     ENOTDIR, ENOTSOCK, EOPNOTSUPP, EPIPE,   EWOULDBLOCK};
    static const char *const error_names[] = {"EACCES",       "EAFNOSUPPORT", "EAGAIN",      "EBADF",   "ECONNRESET", "EDESTADDRREQ", "EHOSTUNREACH", "EINTR",   "EINVAL",   "EIO",        "EISCONN", "ELOOP",      "EMSGSIZE",
                                              "ENAMETOOLONG", "ENETDOWN",     "ENETUNREACH", "ENOBUFS", "ENOENT",     "ENOMEM",       "ENOTCONN",     "ENOTDIR", "ENOTSOCK", "EOPNOTSUPP", "EPIPE",   "EWOULDBLOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        ssize_t result = p101_sendto(env, err, 0, NULL, 0, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == ((ssize_t)-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_sendto", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sethostent) */
static void test_p101_sethostent(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#else
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        p101_sethostent(env, err, 0);
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_sethostent", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setnetent) */
static void test_p101_setnetent(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#else
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        p101_setnetent(env, err, 0);
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setnetent", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setprotoent) */
static void test_p101_setprotoent(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#else
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        p101_setprotoent(env, err, 0);
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setprotoent", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setservent) */
static void test_p101_setservent(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#else
    static const int         errors[]      = {EMFILE, ENFILE};
    static const char *const error_names[] = {"EMFILE", "ENFILE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        p101_setservent(env, err, 0);
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setservent", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setsockopt) */
static void test_p101_setsockopt(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINVAL, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOPROTOOPT", "ENOTSOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, EDOM, EINVAL, EISCONN, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EDOM", "EINVAL", "EISCONN", "ENOBUFS", "ENOMEM", "ENOPROTOOPT", "ENOTSOCK"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, EINVAL, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOBUFS", "ENOMEM", "ENOPROTOOPT", "ENOTSOCK"};
#else
    static const int         errors[]      = {EBADF, EDOM, EINVAL, EISCONN, ENOBUFS, ENOMEM, ENOPROTOOPT, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EDOM", "EINVAL", "EISCONN", "ENOBUFS", "ENOMEM", "ENOPROTOOPT", "ENOTSOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setsockopt(env, err, 0, 0, 0, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setsockopt", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_shutdown) */
static void test_p101_shutdown(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOTCONN", "ENOTSOCK"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOTCONN", "ENOTSOCK"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, EINVAL, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOTCONN", "ENOTSOCK"};
#else
    static const int         errors[]      = {EBADF, EINVAL, ENOBUFS, ENOTCONN, ENOTSOCK};
    static const char *const error_names[] = {"EBADF", "EINVAL", "ENOBUFS", "ENOTCONN", "ENOTSOCK"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_shutdown(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_shutdown", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_sockatmark) */
static void test_p101_sockatmark(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINVAL};
    static const char *const error_names[] = {"EBADF", "EINVAL"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EBADF, ENOTTY};
    static const char *const error_names[] = {"EBADF", "ENOTTY"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EBADF, ENOTTY};
    static const char *const error_names[] = {"EBADF", "ENOTTY"};
#else
    static const int         errors[]      = {EBADF, ENOTTY};
    static const char *const error_names[] = {"EBADF", "ENOTTY"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_sockatmark(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_sockatmark", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_socket) */
static void test_p101_socket(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EINVAL", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EPROTONOSUPPORT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EPROTONOSUPPORT", "EPROTOTYPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, EPERM, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "EPERM", "EPROTONOSUPPORT", "EPROTOTYPE"};
#else
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EPROTONOSUPPORT, EPROTOTYPE, ESOCKTNOSUPPORT};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EPROTONOSUPPORT", "EPROTOTYPE", "ESOCKTNOSUPPORT"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_socket(env, err, 0, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_socket", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_socketpair) */
static void test_p101_socketpair(struct p101_env *env, struct p101_error *err)
{
    int           argument_5[4];
    unsigned char argument_5_before[sizeof(argument_5)];
    memset(argument_5, 0xA5, sizeof(argument_5));
    memcpy(argument_5_before, argument_5, sizeof(argument_5));
#ifdef __linux__
    static const int         errors[]      = {EAFNOSUPPORT, EFAULT, EMFILE, ENFILE, EOPNOTSUPP, EPROTONOSUPPORT};
    static const char *const error_names[] = {"EAFNOSUPPORT", "EFAULT", "EMFILE", "ENFILE", "EOPNOTSUPP", "EPROTONOSUPPORT"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EFAULT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EOPNOTSUPP, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EFAULT", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EOPNOTSUPP", "EPROTONOSUPPORT", "EPROTOTYPE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EAFNOSUPPORT, EFAULT, EMFILE, EOPNOTSUPP, EPROTONOSUPPORT};
    static const char *const error_names[] = {"EAFNOSUPPORT", "EFAULT", "EMFILE", "EOPNOTSUPP", "EPROTONOSUPPORT"};
#else
    static const int         errors[]      = {EACCES, EAFNOSUPPORT, EMFILE, ENFILE, ENOBUFS, ENOMEM, EOPNOTSUPP, EPROTONOSUPPORT, EPROTOTYPE};
    static const char *const error_names[] = {"EACCES", "EAFNOSUPPORT", "EMFILE", "ENFILE", "ENOBUFS", "ENOMEM", "EOPNOTSUPP", "EPROTONOSUPPORT", "EPROTOTYPE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_socketpair(env, err, 0, 0, 0, argument_5);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_5, argument_5_before, sizeof(argument_5)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_socketpair", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

int main(void)
{
    const char        *outcome_path;
    struct p101_error *err;
    struct p101_env   *env;

    outcome_path = getenv("P101_WRAPPER_OUTCOME_LOG");
    if(outcome_path != NULL && outcome_path[0] != '\0')
    {
        outcome_stream = fopen(outcome_path, "a");
        if(outcome_stream == NULL)
        {
            fprintf(stderr, "FAIL: cannot open wrapper outcome receipt\n");
            return EXIT_FAILURE;
        }
    }
    err = p101_error_create(false);
    if(err == NULL)
    {
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    p101_env_set_fd_observer(env, count_fd_event, NULL);
    p101_env_set_alloc_observer(env, count_alloc_event, NULL);
    p101_env_set_resource_observer(env, count_resource_event, NULL);
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
    test_p101_sethostent(env, err);
    test_p101_setnetent(env, err);
    test_p101_setprotoent(env, err);
    test_p101_setservent(env, err);
    test_p101_setsockopt(env, err);
    test_p101_shutdown(env, err);
    test_p101_sockatmark(env, err);
    test_p101_socket(env, err);
    test_p101_socketpair(env, err);
    p101_env_destroy(env);
    p101_error_destroy(err);
    if(outcome_stream != NULL && fclose(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot close wrapper outcome receipt\n");
        failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
