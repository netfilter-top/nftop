/* tests/query_route: test attribute parsing for RTM_GETROUTE */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#define BUFSIZE 8192

void process_route(struct nlmsghdr *nlh, unsigned int protocol) {
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm);
    int route_len = RTM_PAYLOAD(nlh);
    struct sockaddr_storage ip;
    char ip_str[INET6_ADDRSTRLEN];
    char if_str[IF_NAMESIZE];

    while (RTA_OK(rta, route_len)) {
        switch(rta->rta_type) {
            case RTA_IIF:
                if_indextoname(*(unsigned int *)RTA_DATA(rta), if_str);
                printf("iif: %s (%u)\n", if_str, *(unsigned int *)RTA_DATA(rta));
                break;
            case RTA_OIF:
                if_indextoname(*(unsigned int *)RTA_DATA(rta), if_str);
                printf("oif: %s (%u)\n", if_str, *(unsigned int *)RTA_DATA(rta));
                break;
            case RTA_SRC:
                memcpy(&ip, RTA_DATA(rta), sizeof(struct sockaddr_storage));

                inet_ntop(protocol, &ip, ip_str, INET6_ADDRSTRLEN);
                printf("Source IP: %s\n", ip_str);
                break;
            case RTA_DST:
                memcpy(&ip, RTA_DATA(rta), sizeof(struct sockaddr_storage));

                inet_ntop(protocol, &ip, ip_str, INET6_ADDRSTRLEN);
                printf("Destination IP: %s\n", ip_str);
                break;
            case RTA_GATEWAY:
                memcpy(&ip, RTA_DATA(rta), sizeof(struct sockaddr_storage));

                inet_ntop(protocol, &ip, ip_str, INET6_ADDRSTRLEN);
                printf("Gateway: %s\n", ip_str);
                break;
            case RTA_PREFSRC:
                memcpy(&ip, RTA_DATA(rta), sizeof(struct sockaddr_storage));

                inet_ntop(protocol, &ip, ip_str, INET6_ADDRSTRLEN);
                printf("Pref-Source: %s\n", ip_str);
                break;
            default:
                printf("rta->rta_type: %d\n", rta->rta_type);
                break;
        }

        memset(&ip_str, 0, sizeof(ip_str));
        memset(&if_str, 0, sizeof(if_str));

        rta = RTA_NEXT(rta, route_len);
    }
}

static int get_ip_ver(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return AF_INET6;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    int sock_fd;
    struct sockaddr_nl sa;
    struct rtattr *rta;
    char buffer[BUFSIZE];
    struct sockaddr_storage target_ip, source_ip;
    char dst_ip[INET6_ADDRSTRLEN];
    char src_ip[INET6_ADDRSTRLEN];
    int mark = 0;

    if (argc < 2) {
        printf("Enter destination IP address (IPv4): ");
        fgets(dst_ip, sizeof(dst_ip), stdin);
        dst_ip[strlen(dst_ip) - 1] = '\0';  // Remove newline
    } else if (argc == 2) {
        strcpy(dst_ip, argv[1]);
    } else if (argc >= 3) {
        strcpy(dst_ip, argv[1]);
        strcpy(src_ip, argv[2]);
        if (argc == 4) {
            mark = atoi((char *)argv[3]);
        }
    }

    // Set the target IP address you want to query
    if (inet_pton(get_ip_ver(dst_ip), dst_ip, &target_ip) != 1) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    if (argc == 3) {
        // Set the source IP address you want to query
        if (inet_pton(get_ip_ver(src_ip), src_ip, &source_ip) != 1) {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }
    }

    // Create a netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Initialize sockaddr_nl structure
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 0; // No multicast groups

    // Bind the socket
    if (bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Prepare and send the request message
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char attrbuf[BUFSIZE];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    //req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_family = get_ip_ver(dst_ip);

    int addr_size = 0;
    switch(req.rtm.rtm_family) {
        case AF_INET:
            addr_size = sizeof(struct in_addr);
            break;
        case AF_INET6:
            addr_size = sizeof(struct in6_addr);
            break;
        default:
            addr_size = sizeof(struct sockaddr_storage);
    }

    // Add the target IP address to the request
    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(addr_size);
    memcpy(RTA_DATA(rta), &target_ip, addr_size);

    // Set the request message length
    req.nlh.nlmsg_len += RTA_LENGTH(sizeof(addr_size));

    // Add the source IP address
    if (argc == 3) {
        rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
        rta->rta_type = RTA_SRC;
        rta->rta_len = RTA_LENGTH(addr_size);
        memcpy(RTA_DATA(rta), &source_ip, addr_size);
        req.nlh.nlmsg_len += RTA_LENGTH(addr_size);
    }

    if (argc == 4) {
        rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
        rta->rta_type = RTA_MARK;
        rta->rta_len = RTA_LENGTH(sizeof(int));
        memcpy(RTA_DATA(rta), &mark, sizeof(int));
        req.nlh.nlmsg_len += RTA_LENGTH(sizeof(int));
    }

    // Send the request
    if (send(sock_fd, &req, req.nlh.nlmsg_len, 0) == -1) {
        perror("send");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Receive and process the response
    ssize_t len = recv(sock_fd, buffer, BUFSIZE, 0);
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

    while (NLMSG_OK(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (nlh->nlmsg_type == RTM_NEWROUTE) {
            process_route(nlh, get_ip_ver(dst_ip));
        }

        nlh = NLMSG_NEXT(nlh, len);
    }

    close(sock_fd);
    return 0;
}