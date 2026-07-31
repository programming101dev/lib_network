#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_network/network.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void test_byte_order(const struct p101_env *env)
{
    uint32_t value32 = UINT32_C(0x01020304);
    uint16_t value16 = UINT16_C(0x0102);

    /* P101_TEST_CASE(p101_htonl) */
    EXPECT(p101_htonl(env, value32) == htonl(value32));
    /* P101_TEST_CASE(p101_ntohl) */
    EXPECT(p101_ntohl(env, htonl(value32)) == value32);
    /* P101_TEST_CASE(p101_htons) */
    EXPECT(p101_htons(env, value16) == htons(value16));
    /* P101_TEST_CASE(p101_ntohs) */
    EXPECT(p101_ntohs(env, htons(value16)) == value16);
}

static void test_inet_helpers(const struct p101_env *env)
{
    struct in_addr address;
    char          *text;

    EXPECT(inet_pton(AF_INET, "10.1.2.3", &address) == 1);
    /* P101_TEST_CASE(p101_inet_ntoa) */
    text = p101_inet_ntoa(env, address);
    EXPECT(text != NULL && strcmp(text, "10.1.2.3") == 0);
    /* P101_TEST_CASE(p101_inet_lnaof) */
    EXPECT(p101_inet_lnaof(env, address) == inet_lnaof(address));
    /* P101_TEST_CASE(p101_inet_netof) */
    EXPECT(p101_inet_netof(env, address) == inet_netof(address));
}

static void test_database_controls(const struct p101_env *env)
{
    /* P101_TEST_CASE(p101_sethostent) */
    p101_sethostent(env, 0);
    /* P101_TEST_CASE(p101_endhostent) */
    p101_endhostent(env);
    /* P101_TEST_CASE(p101_setnetent) */
    p101_setnetent(env, 0);
    /* P101_TEST_CASE(p101_endnetent) */
    p101_endnetent(env);
    /* P101_TEST_CASE(p101_setprotoent) */
    p101_setprotoent(env, 0);
    /* P101_TEST_CASE(p101_endprotoent) */
    p101_endprotoent(env);
    /* P101_TEST_CASE(p101_setservent) */
    p101_setservent(env, 0);
    /* P101_TEST_CASE(p101_endservent) */
    p101_endservent(env);
}

static void test_owned_results(const struct p101_env *env)
{
    struct addrinfo      hints = {0};
    struct addrinfo     *addresses;
    struct ifaddrs      *interfaces;
    struct if_nameindex *names;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addresses         = NULL;
    EXPECT(getaddrinfo("localhost", "80", &hints, &addresses) == 0);
    if(addresses != NULL)
    {
        /* P101_TEST_CASE(p101_freeaddrinfo) */
        p101_freeaddrinfo(env, addresses);
    }

    interfaces = NULL;
    EXPECT(getifaddrs(&interfaces) == 0);
    if(interfaces != NULL)
    {
        /* P101_TEST_CASE(p101_freeifaddrs) */
        p101_freeifaddrs(env, interfaces);
    }

    names = if_nameindex();
    EXPECT(names != NULL);
    if(names != NULL)
    {
        /* P101_TEST_CASE(p101_if_freenameindex) */
        p101_if_freenameindex(env, names);
    }
}

static void test_messages_and_ethernet(const struct p101_env *env)
{
    struct ether_addr address = {0};
    const char       *message;
    char             *ethernet;

    /* P101_TEST_CASE(p101_gai_strerror) */
    message = p101_gai_strerror(env, EAI_NONAME);
    EXPECT(message != NULL);
    /* P101_TEST_CASE(p101_ether_ntoa) */
    ethernet = p101_ether_ntoa(env, &address);
    EXPECT(ethernet != NULL);
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
    test_byte_order(env);
    test_inet_helpers(env);
    test_database_controls(env);
    test_owned_results(env);
    test_messages_and_ethernet(env);
    p101_env_destroy(env);
    p101_error_destroy(err);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
