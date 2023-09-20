/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef _NFTOP_UTIL_H
#define _NFTOP_UTIL_H
#define _GNU_SOURCE
#include <netdb.h>  // NI_NAMEREQD

struct Address {
    char ip[INET6_ADDRSTRLEN];
    char netmask[INET6_ADDRSTRLEN];
    struct sockaddr_storage s_addr;
    struct sockaddr_storage s_mask;
    int64_t bps_rx;
    int64_t bps_tx;
    int64_t bps_sum;
    struct Address *next;
};

struct DNSCache {
    char ip[INET6_ADDRSTRLEN];
    char hostname[NI_MAXHOST];
    struct DNSCache *next;
};

void set_conio_terminal_mode();
void reset_terminal_mode();

char* getSortIndicator(int);
char* getProtocolName(uint8_t);
char* getIPProtocolName(uint8_t, uint8_t);
char* formatUOM(uint64_t);
void freeConnectionTrackingList(struct Connection*);
void freeDeviceList(struct Interface*);
void free_interfaces(struct Interface **);
bool isLocalAddress(char *, struct Interface **);
void enumerateNetworkDevices(struct Interface **);
void addr2host(struct Connection *ct_info);
int is_redirected();
void add_ct(struct Connection **head, struct Connection *curr_ct);
bool is_dns_cached(char *ip);
void add_dns_cache(char *ip, char *hostname);
void free_dns_cache();
char *get_cached_dns(char *);
struct Interface *getIfaceForRoute(int, struct sockaddr_storage *, struct sockaddr_storage *, int, struct Interface **);

#endif