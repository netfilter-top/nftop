/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef _NFTOP_H
#define _NFTOP_H
#define _GNU_SOURCE

#define VERSION "1.1.1"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>  // NI_NAMEREQD, NI_MAXHOST, NI_MAXSERV


#ifdef ENABLE_NCURSES
#include <ncurses.h>
#else
#include <sys/ioctl.h> // TIOCGWINSZ, winsize
#endif

#ifndef NSEC_PER_SEC
// from libnetfilter_conntrack/include/internal/internal.h
#define NSEC_PER_SEC 1000000000L
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000
#endif

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0x8
#endif

#define bps     1
#define Kbps    1000
#define Mbps    1000000         // Megabit
#define Gbps    1000000000L     // Gigabit
#define Tbps    1000000000000L  // Terabit

#define NFTOP_MAX_DNS 4096

enum nftop_sort_fields {
    NFTOP_SORT_NONE,
    NFTOP_SORT_ID,
    NFTOP_SORT_IN,
    NFTOP_SORT_OUT,
    NFTOP_SORT_SPORT,
    NFTOP_SORT_DPORT,
    NFTOP_SORT_RX,
    NFTOP_SORT_TX,
    NFTOP_SORT_SUM,
    NFTOP_SORT_AGE,
    NFTOP_SORT_PROTO
};

// User options
extern int     NFTOP_U_INTERVAL;
extern int     NFTOP_U_DISPLAY_AGE;
extern int     NFTOP_U_SI;
extern int     NFTOP_U_BYTES;
extern int64_t NFTOP_U_THRESH;
extern char*   NFTOP_U_IN_IFACE;
extern int     NFTOP_U_IN_IFACE_FUZZY;
extern char*   NFTOP_U_OUT_IFACE;
extern int     NFTOP_U_OUT_IFACE_FUZZY;
extern int     NFTOP_U_SORT_FIELD;
extern int     NFTOP_U_SORT_ASC;
extern int     NFTOP_U_NO_LOOPBACK;
extern int     NFTOP_U_IPV4;
extern int     NFTOP_U_IPV6;
extern int     NFTOP_U_REPORT_WIDE;
extern int     NFTOP_U_DISPLAY_ID;
extern int     NFTOP_U_DISPLAY_STATUS;
extern int     NFTOP_U_DNS;
extern int     NFTOP_U_REDACT_SRC;
extern int     NFTOP_U_REDACT_DST;
extern int     NFTOP_U_NUMERIC_SRC;
extern int     NFTOP_U_NUMERIC_DST;
extern int     NFTOP_U_NUMERIC_PORT;
extern int     NFTOP_U_BPS;
extern int     NFTOP_U_CONTINUOUS;

// Runtime flags
extern int     NFTOP_FLAGS_TIMESTAMP; // runtime flag to indicate if nf_conntrack_timestamp was detected
extern int     NFTOP_FLAGS_EXIT;
extern int     NFTOP_U_MACHINE;

extern int     NFTOP_FLAGS_PAUSE;
extern int     NFTOP_FLAGS_DEV_ONLY;
extern int     NFTOP_FLAGS_COLUMNS;
extern int     NFTOP_FLAGS_DEBUG;

// Global counters/objects
extern uint64_t NFTOP_RX_ALL;
extern uint64_t NFTOP_TX_ALL;
extern int NFTOP_CT_COUNT;
extern int NFTOP_CT_ITER;
extern int NFTOP_DNS_ITER;
extern size_t NFTOP_MAX_HOSTNAME;
extern int NFTOP_MAX_SERVICE;
extern struct DNSCache *dns_cache_head;
extern struct DNSCache *dns_cache;


#ifdef ENABLE_NCURSES
extern SCREEN *screen;
extern WINDOW *w;
#else
extern struct winsize w;
#endif

struct Network {
    char src[INET6_ADDRSTRLEN];
    uint16_t sport;
    char sport_str[NI_MAXSERV];
    char dst[INET6_ADDRSTRLEN];
    uint16_t dport;
    char dport_str[NI_MAXSERV];
    char hostname_src[NI_MAXHOST];
    char hostname_dst[NI_MAXHOST];
    struct sockaddr_storage src_ip;
    struct sockaddr_storage dst_ip;
};

struct Interface {
    char name[IFNAMSIZ];
    int flags;
    int n_addresses;
    int64_t bps_rx;
    int64_t bps_tx;
    int64_t bps_sum;
    struct Address *addresses;
    struct Interface *next;
};

struct Connection {
	uint32_t id;
    struct Interface net_in_dev;
    struct Interface net_out_dev;
    char *status_str;
	uint64_t bytes_orig;
	uint64_t bytes_repl;
    uint64_t bytes_sum;
    int64_t bps_rx;
    int64_t bps_tx;
    int64_t bps_sum;
	time_t delta;
    time_t time_start;
	uint8_t proto_l3;
	uint8_t proto_l4;
	struct Network local;
	struct Network remote;
	uint32_t status;
    uint32_t status_l4;
    bool is_src_nat;
    bool is_dst_nat;
    uint32_t mark;
    struct Connection *next;
};

int is_redirected();
void interactiveHelp();
int compare(const void *, const void *);
int compare_addresses(const void *, const void *);

#endif