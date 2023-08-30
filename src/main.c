/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>  /* isalpha/isprint */
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h> /* SIOCGIFFLAGS */
#include <unistd.h>

#include <libmnl/libmnl.h>

#include "nftop.h"
#include "display.h"
#include "util.h"

#define USAGE_STRING "nftop: Display connection information from netfilter conntrack entries (including at-the-time throughput values for transmit, receive and sum)\n\n\
Usage:\n\
nftop [-46dbnNPrRS] [-a \033[4mage_format\033[0m] [-i in interface] [-o out interface] [-s sort column] [-t threshold] [-u update interval]  [-w]\n\
  -4                    output only IPv4 connections\n\
  -6                    output only IPv6 connections\n\
  -d|--dev              output device table instead of connections\n\
  -b|--bytes		output bytes insted of default bits\n\
  -B|--bps          output the connection/interface only in bits-per-second, without scaling to Kbps, Mpbs, etc.\n\
  -I|--id               output connection tracking ID\n\
  -L|--loopback		include connections on loopback interfaces (IFF_LOOPBACK)\n\
  -n|--numeric-local	numeric local IP address\n\
  -N|--numeric-remote	numeric remote IP address\n\
  -P|--numeric-port	numeric port\n\
  -r|--redact-local	obfuscate the local connection address\n\
  -R|--redact-remote	obfuscate the remote connection address\n\
  -S|--si		output Standards International nomenclature (Ki, Mi, Gi, ...)\n\
  -a|--age  \033[4m0-2\033[0m		format of age column 0: do not display, 1: seconds, 2: DD HH MM SS format (default is do not display)\n\
                        (only availble if \"net.netfilter.nf_conntrack_timestamp\" kernel option is enabled)\n\
  -t|--threshold  \033[4mbits\033[0m	minimum SUM value to display (in bits)\n\
  -u|--update  \033[4mseconds\033[0m	update interval in seconds\n\
  -i|--in    \033[4minterface\033[0m	interface name to filter as input interface\n\
  -o|--out   \033[4minterface\033[0m	interface name to filter as output interface\n\
  -s|--sort  \033[4m[+]column\033[0m	column to sort by -- one of [id, in, out, sport, dport, rx, tx, sum]\n\
                        the default is \033[1mDESCENDING\033[0m order; use +\033[4mcolumn\033[0m to sort in \033[1mASCENDING\033[0m order\n\
  -v|--version          version\n\
  -V|--verbose          Enable the TCP state field\n\
  -w|--wide             output report in wide format (single row for both SRC and DST)\n\
\n\
Examples:\n\
  nftop -o wwan0	only output connections that egress out interface \"wwan0\"\n\
  nftop -t 1000000	only output connections that are at least 1Mbps (sum)\n\
  nftop -i vlan+	only output connections that match ingress interface \"vlan*\"\n\
  nftop -s +id		sort output by \033[1mID\033[0m column in \033[1mASCENDING\033[0m order\n\
\n\
Notes:\n\
  The assotiation of the in/out interface/device is derived via comparison of the connection local source/destination address against the assigned\n\
  addresses of configured interfaces. This could result in false reporting in certain cases (e.g.: policy routing, traffic queues, etc.)\n\
\n\
Requirements:\n\
  netfilter connection tracking\n\
  netfilter connection accounting (net.netfilter.nf_conntrack_acct)\n\
  root or cap_net_admin+eip permissions\n"

// User option defaults
int     NFTOP_U_INTERVAL 		= 2;				// time between updates in seconds
int     NFTOP_U_DISPLAY_AGE 	= 0; 				// 0 = no display, 1 = numeric (seconds), 2 = string (i.e.: 1d 14h 18m 24s)
int     NFTOP_U_DISPLAY_STATUS  = 0;                // enable display of the status field (CONFIRMED, ASSURED, CLOSING, etc.)
int     NFTOP_U_SI 		    	= 0;				// use Standards International format (default: false)
int     NFTOP_U_BYTES 	    	= 0;				// use Bytes format (default: false)
int64_t NFTOP_U_THRESH	  		= 1;				// minimum threshold of throughput to display (-1 for all connections)
char*	NFTOP_U_IN_IFACE		= NULL;				// ingress interface filter
int     NFTOP_U_IN_IFACE_FUZZY 	= 0;				// ingress interface fuzzy matching flag
char*	NFTOP_U_OUT_IFACE		= NULL;				// egress interface filter
int     NFTOP_U_OUT_IFACE_FUZZY = 0;				// egress interface fuzzy matching flag
int     NFTOP_U_SORT_FIELD  	= NFTOP_SORT_SUM;	// sort field
int		NFTOP_U_SORT_ASC    	= 0;				// sort order
int     NFTOP_U_NO_LOOPBACK		= 1;				// output connnections on loopback interfaces
int     NFTOP_U_IPV4    		= 1;				// include IPv4 connections
int     NFTOP_U_IPV6    		= 1;				// include IPv6 connections
int     NFTOP_U_REPORT_WIDE     = 0;                // 2-line vs 1 long line output
int     NFTOP_U_DISPLAY_ID      = 0;                // display the ID column
int     NFTOP_U_DNS             = 1;                // perform DNS lookups
int     NFTOP_U_REDACT_SRC      = 0;                // obfuscation/redaction of SRC field
int     NFTOP_U_REDACT_DST      = 0;                // obfuscation/redaction of DEST field
int     NFTOP_U_NUMERIC_SRC     = 0;                // numeric/non-dns display of the SRC field
int     NFTOP_U_NUMERIC_DST     = 0;                // numeric/non-dns display of the DEST field
int     NFTOP_U_BPS             = 0;                // use bps only (no scaling of units)
int     NFTOP_U_CONTINUOUS      = 0;                // output continously without displaying header or screen reset
int     NFTOP_U_MACHINE         = 0;                // enables -c, -B and -w

// Runtime flags
int		NFTOP_FLAGS_TIMESTAMP	= 1;				// flag for conntrack_timestamp detection
int     NFTOP_FLAGS_EXIT        = 0;                // stop application, cleanup/free/etc
int     NFTOP_FLAGS_PAUSE       = 0;                // display is paused
int     NFTOP_FLAGS_DEV_ONLY    = 0;                // display device list only (with bandwidth reporting)

// global size values
int     NFTOP_DISPLAY_COUNT     = 1024;             // maximum lines of connections to display

// global counters/objects
uint64_t NFTOP_TX_ALL = 0;
uint64_t NFTOP_RX_ALL = 0;
int NFTOP_CT_COUNT = 0;
int NFTOP_CT_ITER = 0;
int NFTOP_DNS_ITER = 0;
struct DNSCache *dns_cache;
struct DNSCache *dns_cache_head;

struct sigaction action;

#ifdef ENABLE_NCURSES
WINDOW *w;
#else
struct winsize w;
#endif

void term(int signum) {
    /* we need to close the display and restore the cursor, even if killed */
    signum = signum; // get compiler to ignore that we don't use this param
    displayClose();
    NFTOP_FLAGS_EXIT = 1;
}

static int data_cb(enum nf_conntrack_msg_type type,
                   struct nf_conntrack *ct,
                   void *data)
{
    struct Connection **curr_ct = (struct Connection **) data;
    struct Connection *new_ct = NULL;

    type = type; // get compiler to ignore that we don't use this param

    if (ct == NULL || data == NULL)
        return MNL_CB_OK;

    NFTOP_CT_COUNT++;

    uint8_t l3proto = nfct_get_attr_u8(ct, ATTR_L3PROTO);
    uint8_t l4proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);

    if (l3proto != AF_INET && l3proto != AF_INET6)
        return MNL_CB_OK;

    if (!(*curr_ct)) {
        new_ct = *curr_ct;
    } else {
        // allocate a new ct to add to the list
        if (!(new_ct = malloc(sizeof(struct Connection)))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(new_ct, 0, sizeof(struct Connection));
    }

    switch(l4proto) {
        case IPPROTO_TCP:
            new_ct->status_l4 = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
            break;
        case IPPROTO_UDP:
            break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            break;
        case IPPROTO_IGMP:
            break;
        default:
            printf("unknown l4proto (%d); discarding.\n", l4proto);
            return MNL_CB_OK;
    }

    new_ct->id = nfct_get_attr_u32(ct, ATTR_ID);
    time_t start = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
    time_t stop = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);

    time_t delta_time;

    if (stop == 0) {
        time(&stop);
    }

    if (!start) {
        delta_time = NFTOP_U_INTERVAL;
        NFTOP_FLAGS_TIMESTAMP = 0;
        NFTOP_U_DISPLAY_AGE = 0;
    } else {
        delta_time = stop - (time_t)(start / NSEC_PER_SEC);
    }

    new_ct->delta = delta_time;
    new_ct->time_start = start;

    new_ct->bytes_orig = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
    if (!new_ct->bytes_orig) {
        new_ct->bytes_orig = 0;
    }

    new_ct->bytes_repl = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
    if (!new_ct->bytes_repl) {
        new_ct->bytes_repl = 0;
    }

    new_ct->bytes_sum = new_ct->bytes_orig + new_ct->bytes_repl;

    new_ct->proto_l3 = nfct_get_attr_u8(ct, ATTR_L3PROTO);
    new_ct->proto_l4 = nfct_get_attr_u8(ct, ATTR_L4PROTO);

    // TODO: probably better to use nfct_get_attr_grp and acquire ATTR_{ORIG,REPL}_{SRC,DST} to be protocol agnostic
    if (new_ct->proto_l3 == AF_INET) {
        inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), new_ct->local.src, sizeof(new_ct->local.src));       
        inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), new_ct->local.dst, sizeof(new_ct->local.dst));
        inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_REPL_IPV4_SRC), new_ct->remote.src, sizeof(new_ct->remote.src));
        inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_REPL_IPV4_DST), new_ct->remote.dst, sizeof(new_ct->remote.dst));
    } else if (new_ct->proto_l3 == AF_INET6) {
        inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), new_ct->local.src, sizeof(new_ct->local.src));
        inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), new_ct->local.dst, sizeof(new_ct->local.dst));
        inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_REPL_IPV6_SRC), new_ct->remote.src, sizeof(new_ct->remote.src));
        inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_REPL_IPV6_DST), new_ct->remote.dst, sizeof(new_ct->remote.dst));
    }

    new_ct->local.sport = ntohl(nfct_get_attr_u32(ct, ATTR_REPL_PORT_SRC));
    new_ct->local.dport = ntohl(nfct_get_attr_u32(ct, ATTR_ORIG_PORT_SRC));

    new_ct->status = nfct_get_attr_u32(ct, ATTR_STATUS);

    new_ct->is_dst_nat = (new_ct->status & IPS_DST_NAT) == IPS_DST_NAT;
    new_ct->is_src_nat = (new_ct->status & IPS_SRC_NAT) == IPS_SRC_NAT;

    (*curr_ct)->next = new_ct;
    new_ct->next = NULL;
    *curr_ct = new_ct;

    return MNL_CB_OK;
}

/* sends a DUMP query to NFCT and registers a callback to process the entries */
int queryNFCT(struct Connection* curr_ct) {
    int ret;
    uint32_t family = AF_UNSPEC;
    struct nfct_handle *nfcthandle;

    nfcthandle = nfct_open(CONNTRACK, 0);
    if (!nfcthandle) {
        perror("nfct_open");
        return -1;
    }

    nfct_callback_unregister(nfcthandle);
    nfct_callback_register(nfcthandle, NFCT_T_ALL, data_cb, &curr_ct);
    ret = nfct_query(nfcthandle, NFCT_Q_DUMP, &family);

    if (ret == -1) {
        displayClose();
        printf("error: (%d)(%s)\n", ret, strerror(errno));
        exit(EXIT_FAILURE);
    }

    nfct_callback_unregister(nfcthandle);
    nfct_close(nfcthandle);

    return ret;
}

void sortAddresses(struct Address **head) {
    // Convert linked list to array
    int count = 0;
    struct Address *current = *head;

    while (current != NULL) {
        count++;
        current = current->next;
    }

    struct Address **addressArray = (struct Address **)malloc(count * sizeof(struct Address *));
    if (!addressArray) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    current = *head;
    for (int i = 0; i < count; i++) {
        addressArray[i] = current;
        current = current->next;
    }

    // Sort the array using qsort
    qsort(addressArray, count, sizeof(struct Address *), compare_addresses);

    // Reconstruct the linked list
    *head = addressArray[0];
    for (int i = 0; i < count - 1; i++) {
        addressArray[i]->next = addressArray[i + 1];
    }
    addressArray[count - 1]->next = NULL;

    free(addressArray);
}

void sortInterfaces(struct Interface **head) {
    // Convert linked list to array
    int count = 0;
    struct Interface *current = *head;

    while (current != NULL) {
        count++;
        current = current->next;
    }

    struct Interface **interfaceArray = (struct Interface **)malloc(count * sizeof(struct Interface *));
    if (!interfaceArray) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    current = *head;
    for (int i = 0; i < count; i++) {
        interfaceArray[i] = current;
        sortAddresses(&interfaceArray[i]->addresses);
        current = current->next;
    }

    // Sort the array using qsort
    qsort(interfaceArray, count, sizeof(struct Interface *), compare);

    // Reconstruct the linked list
    *head = interfaceArray[0];
    for (int i = 0; i < count - 1; i++) {
        interfaceArray[i]->next = interfaceArray[i + 1];
    }
    interfaceArray[count - 1]->next = NULL;

    free(interfaceArray);
}

void sortConnections(struct Connection **head) {
    int count = 0;
    struct Connection *current = *head;

    while (current != NULL) {
        count++;
        current = current->next;
    }

    // Convert linked list to array
    struct Connection **connectionArray = (struct Connection **)malloc(count * sizeof(struct Connection *));
    if (!connectionArray) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    current = *head;
    for (int i = 0; i < count; i++) {
        connectionArray[i] = current;
        current = current->next;
    }

    // Sort the array using qsort
    qsort(connectionArray, count, sizeof(struct Connection *), compare);

    // Reconstruct the linked list
    *head = connectionArray[0];
    for (int i = 0; i < count - 1; i++) {
        connectionArray[i]->next = connectionArray[i + 1];
    }
    connectionArray[count - 1]->next = NULL;

    free(connectionArray);
}

int compare_addresses(const void *a, const void *b) {
    const struct Address *addra = *(const struct Address **)a;
    const struct Address *addrb = *(const struct Address **)b;

    return strcmp(addra->ip, addrb->ip);
}

int compare(const void *a, const void *b) {
    uint32_t v1 = 0, v2 = 0;

    if (a == NULL || b == NULL) {
        return 0;
    }

    if (NFTOP_FLAGS_DEV_ONLY) {
        // sorting of netdevices
        const struct Interface *deva = *(const struct Interface **)a;
        const struct Interface *devb = *(const struct Interface **)b;

        switch (NFTOP_U_SORT_FIELD) {
            default:
                if (NFTOP_U_SORT_ASC == 1) {
                    return strcmp(devb->name, deva->name);
                } else {
                    return strcmp(deva->name, devb->name);
                }
                return 0;
        }
    } else {
        const struct Connection *conn_a = *(const struct Connection **)a;
        const struct Connection *conn_b = *(const struct Connection **)b;

        if (conn_a == NULL || conn_b == NULL) {
            return 0;
        }

        switch (NFTOP_U_SORT_FIELD) {
            case NFTOP_SORT_SUM:
                v1 = conn_a->bps_sum;
                v2 = conn_b->bps_sum;
                break;
            case NFTOP_SORT_AGE:
                v1 = conn_a->delta;
                v2 = conn_b->delta;
                break;
            case NFTOP_SORT_ID:
                v1 = conn_a->id;
                v2 = conn_b->id;
                break;
            case NFTOP_SORT_RX:
                v1 = conn_a->bps_rx;
                v2 = conn_b->bps_rx;
                break;
            case NFTOP_SORT_TX:
                v1 = conn_a->bps_tx;
                v2 = conn_b->bps_tx;
                break;
            case NFTOP_SORT_SPORT:
                v1 = conn_a->local.sport;
                v2 = conn_b->local.sport;
                break;
            case NFTOP_SORT_DPORT:
                v1 = conn_a->local.dport;
                v2 = conn_b->local.dport;
                break;
            case NFTOP_SORT_PROTO:
                v1 = conn_a->proto_l4;
                v2 = conn_b->proto_l4;
                break;
            case NFTOP_SORT_IN:
                if (NFTOP_U_SORT_ASC == 1) {
                    return strcmp(conn_b->net_in_dev.name, conn_a->net_in_dev.name);
                }
                return strcmp(conn_a->net_in_dev.name, conn_b->net_in_dev.name);
                break;
            case NFTOP_SORT_OUT:
                if (NFTOP_U_SORT_ASC == 1) {
                    return strcmp(conn_b->net_out_dev.name, conn_a->net_out_dev.name);
                }
                return strcmp(conn_a->net_out_dev.name, conn_b->net_out_dev.name);
                break;
            default:
                return 0;
        }
    }

    if (!v1 || !v2)
        return 0;

    if (v1 > v2) {
        return (NFTOP_U_SORT_ASC == 1) ? 1 : -1;
    } else if (v1 < v2) {
        return (NFTOP_U_SORT_ASC == 1) ? -1 : 1;
    } else {
        return 0;
    }
}

/* get an integer from user via prompt, constrained between min and max */
int getUserInteger(int min, long int max) {
#ifndef ENABLE_NCURSES
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK); // remove the non-blocking flag, if set
    displayWrite("\033[?25h"); // show cursor
#endif

    char c = 0;
    char val[1024] = "";
    char t_val[2] = ""; // temp char[2] to hold the current char
    int i = 0;
    int length = snprintf(NULL, 0, "%ld", max); // get length of digits in variable "max"

    while ((c = getchar()) != '\n' && c != EOF) {
        if(c >= '0' && c <= '9') {
            if (i < length) { // prevent overflow
                i++;
                strncat(val, &c, 1);
                strncpy(t_val, &c, 1);
                displayWrite(t_val);
            }
        } else if (c == 0x7f) { // backspace
            if (i > 0) {
                val[i-1] = '\0'; // kludgy delete. I'm lazy
                displayWrite("\b \b"); // erase char
            }
            i--;
        } else if (c == 27 || c == 'q') {
            return -127;
        }
    }

    int value = atoi(val);

#ifndef ENABLE_NCURSES
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK | O_NDELAY);
    displayWrite("\033[?25l"); // hide cursor
#endif
    if (value > min && value < max)
        return value;

    return -127;
}

int wait_char(int t) {
#ifdef ENABLE_NCURSES
    int c;
#else
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK | O_NDELAY); // make our terminal non-blocking
    char c;
#endif
    int i = 0;
    int usec_div = 50000;

    while (i < (t * (USEC_PER_SEC/usec_div)) && !NFTOP_FLAGS_EXIT) {
        if (!is_redirected() || NFTOP_U_MACHINE) {
#ifdef ENABLE_NCURSES
            c = wgetch(w);
#else
            c = getchar();
#endif

            if (c != -1) {
                switch (c) {
                    case 'q':
                        NFTOP_FLAGS_EXIT = 1;
                        return 0;
                    case 'p':
                        if (!NFTOP_FLAGS_PAUSE) {
                            NFTOP_FLAGS_PAUSE = 1;
#ifdef ENABLE_NCURSES
                            wmove(w, 0, 0);
                            displayHeader();
                            break;
#else
                            displayWrite("\033[0;0H");
                            displayHeader();
                            return 2;
#endif

                        } else {
                            NFTOP_FLAGS_PAUSE = 0;
                            return 0;
                        }
                        break;
                    case 'h':
                        if (!NFTOP_FLAGS_PAUSE) {
                            NFTOP_FLAGS_PAUSE = 1;
                        } else {
                            NFTOP_FLAGS_PAUSE = 0;
                            return 0;
                        }
                        interactiveHelp();
                        break;
                    // the following options reset NFTOP_FLAGS_PAUSE on return (unpauses when pressed)
                    case 'n':
                        NFTOP_U_NUMERIC_SRC = NFTOP_U_NUMERIC_SRC ? 0 : 1;
                        return 0;
                    case 'N':
                        NFTOP_U_NUMERIC_DST = NFTOP_U_NUMERIC_DST ? 0 : 1;
                        return 0;
                    case 'u':
                        NFTOP_FLAGS_PAUSE = 1;
                        displayClear();
                        displayWrite("Enter an update interval in seconds: ");

                        int interval = getUserInteger(-1, 999);

                        if (interval > -1)
                            NFTOP_U_INTERVAL = interval;

                        return 0;
                   case 't':
                        NFTOP_FLAGS_PAUSE = 1;
                        displayClear();
                        displayWrite("Enter minimum threshold in bits: ");

                        int threshold = getUserInteger(-1, 9999999999999);

                        if (threshold > -1)
                            NFTOP_U_THRESH = threshold;

                        return 0;
                    case 'a':
                        NFTOP_U_DISPLAY_AGE = NFTOP_U_DISPLAY_AGE ? 0 : 2;
                        return 0;
                    case 'w':
                        NFTOP_U_REPORT_WIDE = NFTOP_U_REPORT_WIDE ? 0 : 1;
                        return 0;
                    case 'r':
                        NFTOP_U_REDACT_SRC = NFTOP_U_REDACT_SRC ? 0 : 1;
                        return 0;
                    case 'R':
                        NFTOP_U_REDACT_DST = NFTOP_U_REDACT_DST ? 0 : 1;
                        return 0;
                    case 'S':
                        NFTOP_U_SI = NFTOP_U_SI ? 0 : 1;
                        return 0;
                    case 'V':
                        NFTOP_U_DISPLAY_STATUS = NFTOP_U_DISPLAY_STATUS ? 0 : 1;
                        return 0;
                    case 'I':
                        NFTOP_U_DISPLAY_ID = NFTOP_U_DISPLAY_ID ? 0 : 1;
                        return 0;
                    case 'b':
                        NFTOP_U_BYTES = NFTOP_U_BYTES ? 0 : 1;
                        return 0;
                    case 'B':
                        NFTOP_U_BPS = NFTOP_U_BPS ? 0 : 1;
                        return 0;
                    case 'c':
                        NFTOP_U_CONTINUOUS = NFTOP_U_CONTINUOUS ? 0 : 1;
                        return 0;
                    case 'l':
                        NFTOP_U_NO_LOOPBACK = NFTOP_U_NO_LOOPBACK ? 0 : 1;
                        return 0;
                    case '0':
                        NFTOP_U_IPV4 = 1;
                        NFTOP_U_IPV6 = 1;
                        return 0;
                    case '4':
                        NFTOP_U_IPV4 = 1;
                        NFTOP_U_IPV6 = NFTOP_U_IPV6 ? 0 : 1;
                        return 0;
                    case '6':
                        NFTOP_U_IPV6 = 1;
                        NFTOP_U_IPV4 = NFTOP_U_IPV4 ? 0 : 1;
                        return 0;
                    case 'd':
                        NFTOP_FLAGS_DEV_ONLY = NFTOP_FLAGS_DEV_ONLY ? 0 : 1;
                        return 0;
                    default:
                        return 0;
                }
            }
        }

        if (!NFTOP_FLAGS_PAUSE)
            i += 1;

        usleep(usec_div);
    }

    return 0;
}

void interactiveHelp() {
    displayClear();

    char *status_on = "on";
    char *status_off = "off";
    char *timestamp_avail_str = "\n\tAge field unavailable; enable net.netfilter.nf_conntrack_timestamp in kernel";

    displayWrite("Help for interactive commands - NFTOP v%s\n\
(Press any key to leave this help screen; \"q\" to exit)\n\
\n\
    p\tToggle pause/resume output\n\
    d\tToggle interface list mode\n\
    a\tToggle connection age field (%s)%s\n\
    u\tChange update interval (currently: %ds)\n\
    t\tChange threshold (currently: %d)\n\
    w\tToggle wide display format (%s)\n\
    b\tToggle report bytes, not bits (%s)\n\
    S\tToggle International System of Units (SI) nomenclature (Ki, Mi, Gi, ...) (%s)\n\
    4\tToggle IPv4 output (%s)\n\
    6\tToggle IPv6 output (%s)\n\
    l\tToggle output of loopback interfaces (%s)\n\
    V\tToggle TCP state field (%s)\n\
    I\tToggle connection tracking ID field (%s)\n\
    r\tToggle obfuscation of the SRC IP address (%s)\n\
    R\tToggle obfuscation of the DEST IP address (%s)\n\
    n\tToggle name resolution of the SRC field (%s)\n\
    N\tToggle name resolution of the DEST field (%s)\n\
    q\tQuit/Exit\n",
        VERSION, NFTOP_U_DISPLAY_AGE ? status_on : status_off, NFTOP_FLAGS_TIMESTAMP ? "" : timestamp_avail_str,
        NFTOP_U_INTERVAL, NFTOP_U_THRESH, NFTOP_U_REPORT_WIDE ? status_on : status_off, NFTOP_U_BYTES ? status_on : status_off,
        NFTOP_U_SI ? status_on : status_off, NFTOP_U_IPV4 ? status_on : status_off,
        NFTOP_U_IPV6 ? status_on : status_off, NFTOP_U_NO_LOOPBACK ? status_off : status_on,
        NFTOP_U_DISPLAY_STATUS ? status_on : status_off, NFTOP_U_DISPLAY_ID ? status_on : status_off,
        NFTOP_U_REDACT_SRC ? status_on : status_off, NFTOP_U_REDACT_DST ? status_on : status_off,
        NFTOP_U_NUMERIC_SRC ? status_off : status_on, NFTOP_U_NUMERIC_DST ? status_off : status_on);
}

int main(int argc, char **argv) {
    struct Connection *current_head_ct = NULL;
    struct Connection *history_head_ct = NULL;
    struct Connection *curr_ct = NULL;
    struct Connection *hist_ct = NULL;
    uint32_t delta_delta;

    int c, option_index = 0;
    opterr = 0;

    signal(SIGINT, term);

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);

    static struct option long_options[] = {
        {"help",			no_argument,	   0, 'h'},
        {"numeric-local",	no_argument, 	   0, 'n'}, // numeric local IP
        {"numeric-remote",  no_argument, 	   0, 'N'}, // numeric remote IP
        {"dev",             no_argument,       0, 'd'}, // devices only
        {"numeric-port", 	no_argument,       0, 'P'}, // numeric port
        {"redact-local", 	no_argument,       0, 'r'}, // replace the local address/hostname with "REDACTED"
        {"redact-remote", 	no_argument,       0, 'R'}, // replace the destination address/hostname with "REDACTED"
        {"age", 			required_argument, 0, 'a'}, // format of AGE column
        {"si",  			no_argument, 	   0, 'S'}, // International System of Units nomenclature
        {"bytes",			no_argument, 	   0, 'b'}, // Output bytes instead of bits
        {"bps", 			no_argument, 	   0, 'B'}, // Output bps (no scaling of units)
        {"continuous",		no_argument, 	   0, 'c'}, // Output continously without header
        {"threshold",  		no_argument, 	   0, 't'}, // minimum threshold of throughput to display
        {"update-interval", required_argument, 0, 'u'}, // interval for update
        {"in",				required_argument, 0, 'i'}, // input interface to filter on
        {"out",				required_argument, 0, 'o'}, // output interface to filter on
        {"sort",			required_argument, 0, 's'}, // sort column
        {"loopback",		required_argument, 0, 'L'}, // include connections on loopback interfaces
        {"wide",    		required_argument, 0, 'w'}, // format output in wide report format
        {"verbose",    		no_argument,       0, 'V'}, // include TCP connection state [assured, closed, etc]
        {"version",    		no_argument,       0, 'v'}, // version
        {"id",         		no_argument,       0, 'I'}, // display connection tracking ID
        {"machine",         no_argument,       0, 'm'}, // enable options --continous, --bps and --wide for machine reading
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "46bBcdhILnNmprRSwvVa:s:t:u:i:o:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                printf(USAGE_STRING);
                exit(EXIT_SUCCESS);
            case 'd':
                NFTOP_FLAGS_DEV_ONLY = 1;
                break;
            case 'a':
                if (isalpha(*optarg) || atoi(optarg) > 2) {
                    printf("Option -%c requires a numeric value of 0, 1 or 2\n", c);
                    exit(EXIT_FAILURE);
                }
                NFTOP_U_DISPLAY_AGE = atoi(optarg);
                break;
            case 'b':
                NFTOP_U_BYTES = 1;
                break;
            case 'B':
                NFTOP_U_BPS = 1;
                break;
            case 'c':
                NFTOP_U_CONTINUOUS = 1;
                break;
            case 'S':
                NFTOP_U_SI = 1;
                break;
            case 't':
                if (isalpha(*optarg)) {
                    printf("Option -t requires a number from -1 to %lu\n", (int64_t)~0);
                    exit(EXIT_FAILURE);
                }
                NFTOP_U_THRESH = atoll(optarg);
                break;
            case 'u':
                if (isalpha(*optarg) || atoi(optarg) < 1) {
                    printf("Option -%c requires a number\n", optopt);
                    exit(EXIT_FAILURE);
                }
                NFTOP_U_INTERVAL = atoi(optarg);
                break;
            case 'i':
                printf("parsing option i (%s)\n", optarg);
                NFTOP_U_IN_IFACE = optarg;
                if (strlen(optarg) > 1) {
                    char *opt_tail = &optarg[strlen(optarg)-1];
                    if (strcmp(opt_tail, "+") == 0) {
                        NFTOP_U_IN_IFACE_FUZZY = 1;
                        optarg[strlen(optarg) - 1] = '\0';
                    }
                }
                break;
            case 'I':
                NFTOP_U_DISPLAY_ID = NFTOP_U_DISPLAY_ID ? 0 : 1;
                break;
            case 'n':
                NFTOP_U_NUMERIC_SRC = NFTOP_U_NUMERIC_SRC ? 0 : 1;
                break;
            case 'N':
                NFTOP_U_NUMERIC_DST = NFTOP_U_NUMERIC_DST ? 0 : 1;
                break;
            case 'o':
                if (strlen(optarg) > 1) {
                    char *opt_tail = &optarg[strlen(optarg)-1];
                    if (strcmp(opt_tail, "+") == 0) {
                        NFTOP_U_OUT_IFACE_FUZZY = 1;
                        optarg[strlen(optarg) - 1] = '\0';
                    }
                }
                NFTOP_U_OUT_IFACE = optarg;
                break;
            case 's':
                if (strncmp(optarg, "+", 1) == 0) {
                    NFTOP_U_SORT_ASC = 1;
                    // strip the leading '+' from the optarg
                    memmove(optarg, optarg + 1, strlen(optarg));
                }

                if (strcmp(optarg, "id") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_ID;
                } else if (strcmp(optarg, "in") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_IN;
                } else if (strcmp(optarg, "out") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_OUT;
                } else if (strcmp(optarg, "sport") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_SPORT;
                } else if (strcmp(optarg, "dport") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_DPORT;
                } else if (strcmp(optarg, "rx") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_RX;
                } else if (strcmp(optarg, "tx") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_TX;
                } else if (strcmp(optarg, "sum") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_SUM;
                } else if (strcmp(optarg, "age") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_AGE;
                } else if (strcmp(optarg, "proto") == 0) {
                    NFTOP_U_SORT_FIELD = NFTOP_SORT_PROTO;
                } else {
                    printf("Option -s|--sort column must be one of [+]id [+]in [+]out [+]sport [+]dport [+]rx [+]tx [+]sum [+]age [+]proto\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'L':
                NFTOP_U_NO_LOOPBACK = NFTOP_U_NO_LOOPBACK ? 0 : 1;
                break;
            case 'w':
                NFTOP_U_REPORT_WIDE = 1;
                break;
            case '4':
                NFTOP_U_IPV4 = 1;
                NFTOP_U_IPV6 = 0;
                break;
            case 'r':
                NFTOP_U_REDACT_SRC = 1;
                break;
            case 'R':
                NFTOP_U_REDACT_DST = 1;
                break;
            case 'v':
                printf("nftop v%s\n", VERSION);
                exit(EXIT_SUCCESS);
                break;
            case 'V':
                NFTOP_U_DISPLAY_STATUS = 1;
                break;
            case '6':
                NFTOP_U_IPV4 = 0;
                NFTOP_U_IPV6 = 1;
                break;
            case 'm':
                NFTOP_U_REPORT_WIDE = 1;
                NFTOP_U_BPS = 1;
                NFTOP_U_CONTINUOUS = 1;
                NFTOP_U_DISPLAY_ID = 1;
                NFTOP_U_DISPLAY_AGE = 1;
                NFTOP_U_MACHINE = 1;
                break;
            case '?':
                if (optopt == 'a' || optopt == 't' || optopt == 'u' || optopt == 's' || optopt == 'S') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint (optopt)) {
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                }
                exit(EXIT_FAILURE);
            default:
                printf("Unhandled option\n");
                exit(EXIT_FAILURE);
        }
    }

    displayInit();

    int ret = 0;

    int pause = 0;  // 0 = Continue as normal
                    // 1 = PAUSE
                    // 2 = Display one more time, then pause

    struct Interface *devices_list = NULL;

    while (ret != -1 && NFTOP_FLAGS_EXIT != 1) {
        struct if_nameindex *if_nidxs, *intf;
        int numInterfaces = 0;

        // Retrieve a list of network interfaces
        if_nidxs = if_nameindex();
        if (if_nidxs == NULL) {
            perror("if_nameindex");
            exit(EXIT_FAILURE);
        }

        // Count the number of interfaces
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            numInterfaces++;
        }

        // Allocate memory for the interfaces
        devices_list = (struct Interface *)malloc(numInterfaces * sizeof(struct Interface));
        if (devices_list == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(devices_list, 0, numInterfaces*sizeof(struct Interface));

        // Copy interface names to the structure
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            strncpy(devices_list[intf - if_nidxs].name, intf->if_name, IFNAMSIZ-1);
        }

        if_freenameindex(if_nidxs);

        enumerateNetworkDevices(&devices_list);

        if (!(current_head_ct = (struct Connection *)malloc(sizeof(struct Connection)))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(current_head_ct, 0, sizeof(struct Connection));

        ret = queryNFCT(current_head_ct);
        curr_ct = current_head_ct;
        curr_ct->bps_rx = 0;
        curr_ct->bps_tx = 0;
        curr_ct->bps_sum = 0;
        struct Connection *displayArray;
        if (!(displayArray = (struct Connection *)malloc(sizeof(struct Connection)))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(displayArray, 0, sizeof(struct Connection));

        bool match = false;
        int array_pos = 0;
        struct Connection *display_head = displayArray;

        if (history_head_ct != NULL) {
            while(curr_ct != NULL) {
                if (array_pos >= NFTOP_DISPLAY_COUNT) {
                    break;
                }
                hist_ct = history_head_ct;

                while(hist_ct != NULL) {
                    if (curr_ct->id == hist_ct->id &&
                        curr_ct->time_start == hist_ct->time_start // ensure times match (ID re-use)
                    ) {
                        delta_delta = NFTOP_U_INTERVAL; // default to NFTOP_U_INTERVAL in case the delta of (item1->delta - item2->delta) has not changed

                        if (curr_ct->delta > 0 && curr_ct->delta != hist_ct->delta) {
                            delta_delta = curr_ct->delta - hist_ct->delta;
                        }

                        if (delta_delta > 0) {
                            bool is_local = isLocalAddress(curr_ct->local.dst, &devices_list);
                            if (curr_ct->bytes_repl - hist_ct->bytes_repl > 0) {
                                if (is_local) {
                                    // use bytes_repl as bps_tx
                                    curr_ct->bps_tx = ((curr_ct->bytes_repl - hist_ct->bytes_repl) / delta_delta) * 8;
                                } else {
                                    curr_ct->bps_rx = ((curr_ct->bytes_repl - hist_ct->bytes_repl) / delta_delta) * 8;    
                                }
                            }
                            if (curr_ct->bytes_orig - hist_ct->bytes_orig > 0) {
                                if (is_local) {
                                    curr_ct->bps_rx = ((curr_ct->bytes_orig - hist_ct->bytes_orig) / delta_delta) * 8;
                                } else {
                                    curr_ct->bps_tx = ((curr_ct->bytes_orig - hist_ct->bytes_orig) / delta_delta) * 8;
                                }
                            }
                            curr_ct->bps_sum = curr_ct->bps_rx + curr_ct->bps_tx;
                        }

                        // copy over the hostnames if already resolved so we don't need to hit the dns_cache
                        if (strlen(hist_ct->local.hostname_src) > 0) {
                            memcpy(&curr_ct->local.hostname_src, hist_ct->local.hostname_src, sizeof(hist_ct->local.hostname_src));
                        }
                        if (strlen(hist_ct->local.hostname_dst) > 0) {
                            memcpy(&curr_ct->local.hostname_dst, hist_ct->local.hostname_dst, sizeof(hist_ct->local.hostname_dst));
                        }

                        // Moved below to only show total ct entries that match the filter.
                        // TODO: add a NFTOP_{RX,TX}_MATCH and allow the user to toggle.
                        // NFTOP_RX_ALL += curr_ct->bps_rx;
                        // NFTOP_TX_ALL += curr_ct->bps_tx;
                        break;
                    }
                    hist_ct = hist_ct->next;
                }

                // match true if L3 protocol matches
                switch (curr_ct->proto_l3) {
                    case AF_INET:
                        match = NFTOP_U_IPV4 ? true : false;
                        break;
                    case AF_INET6:
                        match = NFTOP_U_IPV6 ? true : false;
                        break;
                    default:
                        match = false;
                        break;
                }

                if (curr_ct->delta > 0 && curr_ct->bps_sum >= NFTOP_U_THRESH && match == true) {
                    match = false; // reset the match to further investigate

                    struct Interface *net_in_dev = getIfaceNameForAddr(curr_ct->local.dst, curr_ct->proto_l3, &devices_list);

                    if (net_in_dev == NULL) {
                        net_in_dev = getIfaceNameForAddr(curr_ct->remote.dst, curr_ct->proto_l3, &devices_list);
                    }

                    if (net_in_dev == NULL) {
                        strcpy(curr_ct->net_in_dev.name, "*");
                    } else {
                        net_in_dev->bps_tx += curr_ct->bps_tx;
                        net_in_dev->bps_rx += curr_ct->bps_rx;
                        net_in_dev->bps_sum += curr_ct->bps_tx + curr_ct->bps_rx;
                        memcpy(&curr_ct->net_in_dev, net_in_dev, sizeof(struct Interface));

                        struct Address *addr = net_in_dev->addresses;
                        while (addr) {
                            if (strcmp(curr_ct->local.src, addr->ip) == 0 || strcmp(curr_ct->remote.dst, addr->ip) == 0 || strcmp(curr_ct->local.dst, addr->ip) == 0) {
                                addr->bps_tx += curr_ct->bps_tx;
                                addr->bps_rx += curr_ct->bps_rx;
                                addr->bps_sum += curr_ct->bps_tx + curr_ct->bps_rx;
                            }
                            addr = addr->next;
                        }
                    }

                    struct Interface *net_out_dev = getIfaceNameForAddr(curr_ct->local.src, curr_ct->proto_l3, &devices_list);
                    if (net_out_dev == NULL) {
                        net_out_dev = getIfaceNameForAddr(curr_ct->local.dst, curr_ct->proto_l3, &devices_list);
                    }

                    if (net_out_dev == NULL) {
                        strcpy(curr_ct->net_out_dev.name, "*");
                    } else {
                        if (net_in_dev != net_out_dev) {
                            net_out_dev->bps_tx += curr_ct->bps_rx;
                            net_out_dev->bps_rx += curr_ct->bps_tx;
                            net_out_dev->bps_sum = curr_ct->bps_tx + curr_ct->bps_rx;

                            struct Address *addr = net_out_dev->addresses;
                            while (addr) {
                                if (strcmp(curr_ct->remote.src, addr->ip) == 0 || strcmp(curr_ct->remote.dst, addr->ip)  == 0 || strcmp(curr_ct->local.src, addr->ip)  == 0) {
                                    addr->bps_tx += curr_ct->bps_tx;
                                    addr->bps_rx += curr_ct->bps_rx;
                                    addr->bps_sum += curr_ct->bps_tx + curr_ct->bps_rx;
                                }
                                addr = addr->next;
                            }
                        }
                        memcpy(&curr_ct->net_out_dev, net_out_dev, sizeof(struct Interface));
                    }

                    if (NFTOP_U_IN_IFACE == NULL && NFTOP_U_OUT_IFACE == NULL) {
                        match = true;
                    } else if (NFTOP_U_IN_IFACE != NULL) {
                        if (NFTOP_U_IN_IFACE_FUZZY == 1) {
                            match = strncmp(curr_ct->net_in_dev.name, NFTOP_U_IN_IFACE, (sizeof(char))*(strlen(NFTOP_U_IN_IFACE))) == 0;
                        } else {
                            match = strcmp(curr_ct->net_in_dev.name, NFTOP_U_IN_IFACE) == 0;
                        }
                    } else if (NFTOP_U_OUT_IFACE != NULL) {
                        if (NFTOP_U_OUT_IFACE_FUZZY == 1) {
                            match = strncmp(curr_ct->net_out_dev.name, NFTOP_U_OUT_IFACE, (sizeof(char))*(strlen(NFTOP_U_OUT_IFACE))) == 0;
                        } else {
                            match = strcmp(curr_ct->net_out_dev.name, NFTOP_U_OUT_IFACE) == 0;
                        }
                    }

                    if ((curr_ct->net_in_dev.flags & IFF_LOOPBACK) && NFTOP_U_NO_LOOPBACK == 1) {
                        match = false;
                    }

                    if (NFTOP_U_DNS && (strlen(curr_ct->local.hostname_src) < 2 || strlen(curr_ct->local.hostname_dst) < 2)) {
                        addr2host(curr_ct);
                    }

                    if (match == true) {
                        add_ct(&displayArray, curr_ct);
                        array_pos++;
                        NFTOP_TX_ALL += curr_ct->bps_tx;
                        NFTOP_RX_ALL += curr_ct->bps_rx;
                    }
                }

                curr_ct = curr_ct->next;
            }
        }

        if (NFTOP_U_SORT_FIELD > 0 && NFTOP_FLAGS_DEV_ONLY == 0) {
            sortConnections(&displayArray);
        }

        // if IO is not being redirected (i.e. via grep, tee, etc.), display the header
        if (!is_redirected()) {
            displayHeader();
        }

        if (!NFTOP_FLAGS_DEV_ONLY) {
            display_head = displayArray;
            while (display_head != NULL) {
                if (display_head->id > 0) {
                    displayCTInfo(display_head);
                }
                display_head = display_head->next;
            }
        } else {
            sortInterfaces(&devices_list);
            displayDevices(devices_list);
        }

        if (history_head_ct != NULL) {
            pause = wait_char(NFTOP_U_INTERVAL);
            if (pause == 1) {
                NFTOP_FLAGS_PAUSE = 1;
                pause = 0;
            }
            else if (pause == 2) {
                NFTOP_FLAGS_PAUSE = 1;
                pause = 0;
                if (!NFTOP_FLAGS_DEV_ONLY) {
                    display_head = displayArray;
                    while (display_head != NULL) {
                        if (display_head->id > 0) {
                            displayCTInfo(display_head);
                        }
                        display_head = display_head->next;
                    }
                } else {
                    displayDevices(devices_list);
                }
                NFTOP_FLAGS_PAUSE = wait_char(NFTOP_U_INTERVAL);
            } else {
                NFTOP_FLAGS_PAUSE = pause;
            }
        }

        freeConnectionTrackingList(history_head_ct);
        freeConnectionTrackingList(displayArray);

        history_head_ct = current_head_ct;

        NFTOP_RX_ALL = 0;
        NFTOP_TX_ALL = 0;
        NFTOP_CT_COUNT = 0;

        // clear out the display list(s)
        free_interfaces(&devices_list);
    }

    if (curr_ct != NULL)
        free(curr_ct);

    free_dns_cache();
    displayClose();

    return 0;
}
