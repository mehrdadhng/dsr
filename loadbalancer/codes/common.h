#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <jhash.h>

#define IP_ADDRESS(x) (unsigned int)(10 + (89 << 8) + (0 << 16) + (x << 24))

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
typedef struct server_info{
    unsigned int address;
    __u64 load;
} server_info;

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#define MAX_SERVERS 512
#define MAX_FLOWS 4096
#define MAX_CLIENTS 65343
/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

struct pkt_meta {
	__be32 src;
	__be32 dst;
	union {
		__u32 ports;
		__u16 port16[2];
	};
};

struct dest_info {
	__u32 saddr;
	__u32 daddr;
	__u64 bytes;
	__u64 pkts;
	// __u8 dmac[6];
};

struct server_ip_key {
	__u32 servers_key;
};

struct client_port_ip {
	__u32 client_ip;
};

// struct server_port_map {
// 	__u16 dport;
// 	__u32 daddr;
// 	__u32 servers_key;
// };

struct port_map {
	__u16 dport;
	__u32 daddr;
};