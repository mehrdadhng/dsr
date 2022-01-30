#include "common.h"
#define addr 4

SEC("xdp_server")
int xdp_server_func(struct xdp_md *ctx)
{

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
        return XDP_PASS;
    bpf_printk("server1 got an IPIP packet from %x", bpf_ntohl(iph->saddr));
  
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

    __u8 tempMac[6];
    memcpy(tempMac, eth->h_dest, sizeof(eth->h_dest));
    memcpy(eth->h_dest, eth->h_source, sizeof(eth->h_source));
    memcpy(eth->h_source, tempMac, sizeof(tempMac));
    
    iph->check = iph_csum(iph);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";