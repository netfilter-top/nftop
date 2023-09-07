/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "nftop.h"
#include "util.h"

#include <termios.h>
#include <unistd.h>
#include <sys/select.h>

struct termios orig_termios;

void reset_terminal_mode()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
}

void set_conio_terminal_mode()
{
    struct termios new_termios;

    /* take two copies - one for now, one for later */
    tcgetattr(STDIN_FILENO, &orig_termios);
    memcpy(&new_termios, &orig_termios, sizeof(new_termios));

    atexit(reset_terminal_mode);

    new_termios.c_lflag &= ~(ICANON | ECHO | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
}

void freeConnectionTrackingList(struct Connection *head) {
    struct Connection *temp;

    while (head != NULL) {
        temp = head;
        head = temp->next;
        free(temp);
    }
}

void freeDeviceList(struct Interface* device_list_head) {
    struct Interface* temp;

    while (device_list_head != NULL) {
        temp = device_list_head;
        struct Address* addr_head = temp->addresses;
        struct Address* addr_next = temp->addresses->next;

        while (addr_head != NULL && addr_next) {
            addr_next = addr_head->next;
            free(addr_head);
            addr_head = addr_next;
        }
        device_list_head = device_list_head->next;
    }
}

char *formatUOM(uint64_t value) {
    /* Format the Unit of Measure */
    double n_val = 0, factor;
	int slen = 0;
    char *suffix = '\0';
    char *format = "%.1f %s";

	char suffix_unit1 = ' '; 	// {'',K,M,G,T,E}
	char *suffix_unit2 = '\0'; 	    // bps, Bps, ibps or iBps

    if (NFTOP_U_BPS) {
        slen = snprintf(NULL, 0, "%ld", value);
        char *ret = malloc(slen + 1);
        snprintf(ret, slen+1, "%ld", value);
        return ret;
    }

	if (NFTOP_U_BYTES == 1) {
		if (NFTOP_U_SI == 1) {
			factor = 8.192;
			suffix_unit2 = "iBps";
		} else {
			factor = 8;
			suffix_unit2 = "Bps";
		}
	} else {
		if (NFTOP_U_SI == 1) {
			factor = 1.024;
			suffix_unit2 = "ibps";
		} else {
			suffix_unit2 = "bps";
			factor = 1;
		}
	}

	if (value < (Kbps * factor)) {
		n_val = value;
		format = "%.0f %s";
		if (NFTOP_U_BYTES == 1) {
			suffix_unit2 = "Bps";
		} else {
			suffix_unit2 = "bps";
		}
	} else if (value < Mbps * factor) {
		n_val = value / (Kbps * factor);
		suffix_unit1 = 'K';
	} else if (value < Gbps * factor) {
		n_val = value / (Mbps * factor);
		suffix_unit1 = 'M';
	} else if (value < Tbps * factor) {
		n_val = value / (Gbps * factor);
		suffix_unit1 = 'G';
	} else {
		n_val = value / (Tbps * factor);
		suffix_unit1 = 'T';
	}

	slen = snprintf(NULL, 0,   "%c%s", suffix_unit1, suffix_unit2);
	suffix = malloc(slen + 1);
	snprintf(suffix, slen + 1, "%c%s", suffix_unit1, suffix_unit2);

    slen = snprintf(NULL, 0, format, n_val, suffix);
    char *ret = malloc(slen + 2);

    snprintf(ret, slen + 2, format, n_val, suffix);

	free(suffix);

    return ret;
}

char *getProtocolName(uint8_t proto) {
    return (proto == AF_INET) ? "IPv4" : "IPv6";
}

char *getIPProtocolName(uint8_t l3proto, uint8_t proto) {
    char *proto_s, *proto_string;
    int len = 1;
    char version = (l3proto == AF_INET6) ? '6' : '\0';

    switch(proto) {
        case IPPROTO_TCP:
            proto_s = "tcp";
            break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            proto_s = "icmp";
            break;
        case IPPROTO_IGMP:
            proto_s = "igmp";
            break;
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
            proto_s = "udp";
            break;
        case IPPROTO_IPV6:
            proto_s = "ipv6";
            break;
        case 89:
            proto_s = "ospf";
            break;
        case 112:
            proto_s = "vrrp";
            break;
        default:
            len = snprintf(NULL, 0, "%u", proto) + 1;
            proto_s = malloc(len+1);
            snprintf(proto_s, len, "%d", proto);
    }

    len = snprintf(NULL, 0, "%s%c", proto_s, version) + 1;
    proto_string = malloc(len+1);
    snprintf(proto_string, len, "%s%c", proto_s, version);

    return proto_string;
}

char *getSortIndicator(int field) {
	char *indicator = "";

	if (NFTOP_U_SORT_FIELD == field) {
		if (NFTOP_U_SORT_ASC == 1) {
			indicator = "\u2c7d";
		} else {
            indicator = "^";
		}
	}

	return indicator;
}

void add_ct(struct Connection **head, struct Connection *curr_ct) {
    struct Connection *new_ct = (struct Connection *)malloc(sizeof(struct Connection));
    if (!new_ct) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memcpy(new_ct, curr_ct, sizeof(struct Connection));
    new_ct->next = NULL;  // Ensure the new node's next pointer is NULL

    // If the list is empty, make the new node the head
    if (*head == NULL) {
        *head = new_ct;
        return;
    }

    // Traverse the list to find the last node
    struct Connection *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }

    // Append the new node to the end of the list
    current->next = new_ct;
}

void add_address(struct Address **head, const char *ip, const char *nm, sa_family_t family) {
    struct Address *new_address = (struct Address *)malloc(sizeof(struct Address));
    if (!new_address) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    *new_address->ip = '\0';
    *new_address->netmask = '\0';
    strcpy(new_address->ip, ip);
    strcpy(new_address->netmask, nm);
    new_address->bps_tx = 0;
    new_address->bps_rx = 0;
    new_address->bps_sum = 0;
    new_address->s_addr.ss_family = family;
    new_address->s_mask.ss_family = family;
    new_address->next = *head;

    while (*head != NULL)
        *head = (*head)->next;

    *head = new_address;
}

void add_interface(struct Interface **head, const char *name) {
    struct Interface *new_interface;
    if (!(new_interface = (struct Interface *)malloc(sizeof(struct Interface)))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(new_interface, 0, sizeof(struct Interface));
    strncpy(new_interface->name, name, IFNAMSIZ-1);
    new_interface->bps_tx = 0;
    new_interface->bps_rx = 0;
    new_interface->bps_sum = 0;
    new_interface->next = *head;
    new_interface->n_addresses = 0;
    new_interface->addresses = NULL;
    *head = new_interface;
}

void free_addresses(struct Address **head) {
    struct Address *temp;

    while (*head != NULL) {
        temp = *head;
        *head = temp->next;
        free(temp);
    }

    *head = NULL;
}

void free_interfaces(struct Interface **head) {
    struct Interface *temp;
    while (*head != NULL) {
        temp = *head;
        free_addresses(&temp->addresses);
        *head = temp->next;

        free(temp);
    }

    *head = NULL;
}

void enumerateNetworkDevices(struct Interface **interfaces) {
    struct ifaddrs *ifaddr, *ifa;

    // Retrieve network interfaces and addresses
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    // struct Interface *interfaces = NULL;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
            // Find or create the associated interface in the linked list
            struct Interface *interface = *interfaces;
            while (interface != NULL && strcmp(interface->name, ifa->ifa_name) != 0) {
                interface = interface->next;
            }
            if (interface == NULL && ifa->ifa_name != NULL) {
                add_interface(interfaces, ifa->ifa_name);
                interface = *interfaces;
            }

            interface->flags = ifa->ifa_flags;

            // Convert the address to a string and add it to the associated interface
            char ip_str[INET6_ADDRSTRLEN];
            char nm_str[INET6_ADDRSTRLEN];
            void *addr, *netmask;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                netmask = &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
            } else {
                addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                netmask = &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
            }
            inet_ntop(ifa->ifa_addr->sa_family, addr, ip_str, sizeof(ip_str));
            inet_ntop(ifa->ifa_addr->sa_family, netmask, nm_str, sizeof(ip_str));
            add_address(&(interface->addresses), ip_str, nm_str, ifa->ifa_addr->sa_family);
            interface->n_addresses += 1;
            memcpy(&(interface->addresses)->s_addr, (struct sockaddr_storage *)(ifa->ifa_addr), sizeof(struct sockaddr_storage));
            memcpy(&(interface->addresses)->s_mask, (struct sockaddr_storage *)(ifa->ifa_netmask), sizeof(struct sockaddr_storage));

        }
    }

    freeifaddrs(ifaddr);
}

static int subnet_match(int family,  const void *address1, const void *address2, const void *netmask) {
    int bytes = (family == AF_INET) ? 4 : 16;

    for (int i = 0; i < bytes; i++) {
        if ((((const unsigned char *)address1)[i] & ((const unsigned char *)netmask)[i]) !=
                (((const unsigned char *)address2)[i] & ((const unsigned char *)netmask)[i])) {
            return 1;
        }
    }
    return 0;
}

bool isLocalAddress(char *addr, struct Interface **devices_list) {
    struct Interface *curr_dev;

    for (curr_dev = (*devices_list); curr_dev != NULL; curr_dev = curr_dev->next) {
        struct Address *address = curr_dev->addresses;

        while (address != NULL) {
            if (strcmp(addr, address->ip) == 0)
                return true;
            address = address->next;
        }
    }
    return false;
}

struct Interface *getIfaceNameForAddr(char *addr, uint8_t proto, struct Interface **devices_list) {
    struct Interface *curr_dev;

    struct sockaddr_storage check_ip;
    check_ip.ss_family = proto;

    if (proto == AF_INET) {
        inet_pton(proto, addr, &((struct sockaddr_in *)(&check_ip))->sin_addr);
    } else {
        inet_pton(proto, addr, &((struct sockaddr_in6 *)(&check_ip))->sin6_addr);
    }

    for (curr_dev = (*devices_list); curr_dev != NULL; curr_dev = curr_dev->next) {
        struct Address *address = curr_dev->addresses;

        while (address != NULL) {
            if (strcmp(addr, address->ip) == 0)
                return curr_dev;

            if (address->s_addr.ss_family == proto) {
                if (proto == AF_INET) {
                    if (subnet_match(proto, &((struct sockaddr_in *)(&address->s_addr))->sin_addr.s_addr,
                            &((struct sockaddr_in *)(&check_ip))->sin_addr.s_addr,
                            &((struct sockaddr_in *)(&address->s_mask))->sin_addr.s_addr) == 0) {
                        return curr_dev;
                    }
                } else {
                    if (subnet_match(proto, &((struct sockaddr_in6 *)(&address->s_addr))->sin6_addr,
                            &((struct sockaddr_in6 *)(&check_ip))->sin6_addr,
                            &((struct sockaddr_in6 *)(&address->s_mask))->sin6_addr) == 0) {
                        return curr_dev;
                    }
                }
            }
            address = address->next;
        }
    }

    return NULL;
}

bool is_dns_cached(char *ip) {
    struct DNSCache *temp = dns_cache;

    while (temp != NULL) {
        if (strcmp(temp->ip, ip) == 0) {
            return true;
        }
        temp = temp->next;
    }
    return false;
}

void add_dns_cache(char *ip, char *hostname) {
    NFTOP_DNS_ITER++;

    // Initialize the DNS cache if it's empty
    if (dns_cache_head == NULL) {
        if (!(dns_cache_head = malloc(sizeof(struct DNSCache)))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        dns_cache = dns_cache_head;
        dns_cache_head->next = NULL;
    }

    // Copy IP and hostname data to the current cache node
    strncpy(dns_cache_head->hostname, hostname, NI_MAXHOST-1);
    strncpy(dns_cache_head->ip, ip, INET6_ADDRSTRLEN-1);

    // Move the head to the next node, or wrap around
    if (NFTOP_DNS_ITER < NFTOP_MAX_DNS) {
        if (dns_cache_head->next == NULL) {
            if (!(dns_cache_head->next = malloc(sizeof(struct DNSCache)))) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            dns_cache_head = dns_cache_head->next;
            dns_cache_head->next = NULL;
        } else {
            dns_cache_head = dns_cache_head->next;
        }
    } else {
        dns_cache_head = dns_cache;
        NFTOP_DNS_ITER = 0;
    }
}

void free_dns_cache() {
    struct DNSCache *head = dns_cache;
    struct DNSCache *temp;

    while (head != NULL) {
        temp = head;
        head = temp->next;
        free(temp);
    }
    head = NULL;
}

char *get_cached_dns(char *ip) {
    struct DNSCache *temp = dns_cache;

    while (temp != NULL) {
        if (strcmp(temp->ip, ip) == 0) {
            return temp->hostname;
        }
        temp = temp->next;
    }
    return '\0';
}

void addr2host(struct Connection *ct_info) {
    struct sockaddr_in ipaddr;
    char hostname_src[NI_MAXHOST], hostname_dst[NI_MAXHOST];
    char *from_cache;
    int resolved;

    if (!NFTOP_U_NUMERIC_SRC) {
        if (strlen(ct_info->local.hostname_src) < 1 && NFTOP_U_REDACT_SRC == 0) {
            memset(&ipaddr, 0, sizeof(struct sockaddr_in));
            ipaddr.sin_family = ct_info->proto_l3;
            ipaddr.sin_port = htons(0);
            inet_pton(AF_INET, ct_info->local.src, &ipaddr.sin_addr);
            from_cache = get_cached_dns(ct_info->local.src);
            if (!from_cache) {
                resolved = getnameinfo((struct sockaddr *) &ipaddr, sizeof(struct sockaddr_in), hostname_src, sizeof(hostname_src), NULL, 0, NI_NAMEREQD);
                if (resolved == 0) {
                    strncpy(ct_info->local.hostname_src, hostname_src, NFTOP_MAX_HOSTNAME-1);
                    add_dns_cache(ct_info->local.src, hostname_src);
                } else {
                    add_dns_cache(ct_info->local.src, ct_info->local.src);
                }
            } else {
                strncpy(ct_info->local.hostname_src, from_cache, NFTOP_MAX_HOSTNAME-1);
                ct_info->local.hostname_src[NFTOP_MAX_HOSTNAME] = '\0';
            }
        }
    }

    if (!NFTOP_U_NUMERIC_DST) {
        if (strlen(ct_info->local.hostname_dst) < 1 && NFTOP_U_REDACT_DST == 0) {
            memset(&ipaddr, 0, sizeof(struct sockaddr_in));
            ipaddr.sin_family = ct_info->proto_l3;
            ipaddr.sin_port = htons(0);
            inet_pton(AF_INET, ct_info->local.dst, &ipaddr.sin_addr);
            from_cache = get_cached_dns(ct_info->local.dst);
            if (!from_cache) {
                resolved = getnameinfo((struct sockaddr *) &ipaddr, sizeof(struct sockaddr_in), hostname_dst, sizeof(hostname_dst), NULL, 0, NI_NAMEREQD);
                if (resolved == 0) {
                    strncpy(ct_info->local.hostname_dst, hostname_dst, NFTOP_MAX_HOSTNAME-1);
                    add_dns_cache(ct_info->local.dst, hostname_dst);
                } else {
                    add_dns_cache(ct_info->local.dst, ct_info->local.dst);
                }
            } else {
                strncpy(ct_info->local.hostname_dst, from_cache, NFTOP_MAX_HOSTNAME-1);
                ct_info->local.hostname_dst[NFTOP_MAX_HOSTNAME] = '\0';
            }
        }
    }
}

int is_redirected() {
   if (!isatty(fileno(stdout)) || NFTOP_U_CONTINUOUS) {
       return 1;
   }
   return 0;
}