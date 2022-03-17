#include "common.h"

SEC("xdp_server")
int xdp_load_balancer(struct xdp_md *ctx)
{
    unsigned long long start = bpf_ktime_get_ns();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // // bpf_printk("got something");

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // bpf_printk("Got UDP packet from %x", iph->saddr);

    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return XDP_ABORTED;
    
    // if(iph->saddr != IP_ADDRESS(LB) || iph->daddr != IP_ADDRESS(BACKEND_A))
    //     return XDP_PASS;

    unsigned int tempAddr = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tempAddr;

    char tempMac = eth->h_dest[5];
    eth->h_dest[5] = eth->h_source[5];
    eth->h_source[5] = tempMac;

    unsigned short tempPort = udph->dest;
    udph->dest = udph->source;
    udph->source = tempPort;

    iph->check = iph_csum(iph);

    bpf_printk("Got UDP packet from %x, XDP lasted for: %llu ns", iph->saddr, bpf_ktime_get_ns() - start);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
