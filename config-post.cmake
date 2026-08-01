# Platform detection is available only after project() has run.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # glibc exposes inet_net_ntop() and inet_net_pton() through libresolv.
    list(APPEND p101_network_LINK_LIBRARIES resolv)
endif()
