#include "common.h"
#define addr 6

SEC("xdp_server")
int xdp_server_func(struct xdp_md *ctx)
{
    // unsigned long long start = bpf_ktime_get_ns();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 off;


    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_IPIP)
        return XDP_PASS;

    if(iph->daddr != IP_ADDRESS(addr))
        return XDP_DROP;
    bpf_printk("server3 got an IPIP packet from %x", bpf_ntohl(iph->saddr));

    if (bpf_xdp_adjust_head(ctx, 0 + (int)sizeof(struct iphdr) + (int)sizeof(struct ethhdr)))
		return XDP_DROP;
  
    data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

    eth = data;
    off = sizeof(struct ethhdr);
    if (data + off > data_end)
        return XDP_DROP;
    iph = data + off;
    if(iph + 1 > data_end)
        return XDP_DROP;

    unsigned int tempAddr = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tempAddr;

    // char tempmac = new_eth->h_dest[5];
    // new_eth->h_dest[5] = new_eth->h_source[5];
    // new_eth->h_source[5] = tempmac;
    
    // new_eth->h_proto = ETH_P_IP;
    __u8 tempMac[6];
    memcpy(tempMac, eth->h_dest, sizeof(eth->h_dest));
    memcpy(eth->h_dest, eth->h_source, sizeof(eth->h_source));
    memcpy(eth->h_source, tempMac, sizeof(tempMac));

    if (iph->protocol == IPPROTO_TCP){
        bpf_printk("it\'s a TCP packet");
        return XDP_PASS;
    }
    else{
        bpf_printk("it\'s an UDP packet");
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_DROP;
        struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        unsigned short tempPort = udph->dest;
        udph->dest = udph->source;
        udph->source = tempPort;
    }
    
    iph->check = iph_csum(iph);
    bpf_printk("redirecting packet to client");
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";