#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <net/if.h>
#include "../src/nftop.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int NFTOP_IFINDEX_OUTDEV = 0;
int NFTOP_IFINDEX_PHYSINDEV = 0;
int NFTOP_IFINDEX_PHYSOUTDEV = 0;


static int cb(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type,
              struct nf_conntrack *ct,
              void *data)
{
	if (ct == NULL)
		return MNL_CB_OK;

    char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);
    printf("[CT] %s\n", buf);

	nfct_nlmsg_parse(nlh, ct);
    printf("cb called...");

	uint8_t l4proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);

    uint32_t ifindex_in       = nfct_get_attr_u32(ct, 10);
    uint32_t ifindex_out      = nfct_get_attr_u32(ct, NFTOP_IFINDEX_OUTDEV);
    uint32_t ifindex_phys_in  = nfct_get_attr_u32(ct, NFTOP_IFINDEX_PHYSINDEV);
    uint32_t ifindex_phys_out = nfct_get_attr_u32(ct, NFTOP_IFINDEX_PHYSOUTDEV);

    char in_ifname[IF_NAMESIZE] = {'*'};
    char out_ifname[IF_NAMESIZE] = {'*'};
    char in_phys[IF_NAMESIZE] = {'*'};
    char out_phys[IF_NAMESIZE] = {'*'};
    int saved_errno = errno;

    char *name;
    name = if_indextoname(ifindex_in, in_ifname);
    if (name == NULL && errno == ENXIO) {
        // fprintf(stderr, "Index %d : No such device\n", ifindex_in);
    }
    errno = saved_errno;
    name = if_indextoname(ifindex_out, out_ifname);
    if (name == NULL && errno == ENXIO) {
        // fprintf(stderr, "Index %d : No such device\n", ifindex_out);
    }
    errno = saved_errno;

    name = if_indextoname(ifindex_phys_in, in_phys);
    if (name == NULL && errno == ENXIO) {
        // fprintf(stderr, "Index %d : No such device\n", ifindex_phys_in);
    }
    errno = saved_errno;
    name = if_indextoname(ifindex_phys_out, out_phys);
    if (name == NULL && errno == ENXIO) {
        // fprintf(stderr, "Index %d : No such device\n", ifindex_phys_out);
    }
    errno = saved_errno;

    printf("IFINDEX_IN: (%s) IFINDEX_OUT: (%s) IFINDEX_IN_DEV: %s IFINDEX_OUT_DEV: %s PROTO: %u\n", in_ifname, out_ifname, in_phys, out_phys, l4proto);

    // nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3 | NFCT_OF_TIMESTAMP);
    //printf("%s\n", buf);

    return NFCT_CB_CONTINUE;
}

int main(void) {
    int ret;
    uint32_t family = AF_UNSPEC;
    struct nfct_handle *h;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return -1;
    }

    nfct_callback_register2(h, NFCT_T_ALL, cb, NULL);
    ret = nfct_query(h, NFCT_Q_DUMP, &family);

    printf("TEST: get conntrack ");
    if (ret == -1)
        printf("(%d)(%s)\n", ret, strerror(errno));
    else
        printf("(OK)\n");

    nfct_close(h);

    ret == -1 ? exit(EXIT_FAILURE) : exit(EXIT_SUCCESS);
}
