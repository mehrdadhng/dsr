#include "common.h"

#define addr 7

SEC("xdp_server")
int xdp_server_func(struct xdp_md *ctx)
{
    // unsigned long long start = bpf_ktime_get_ns();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //return XDP_DROP;

    __u32 off;
    struct ethhdr *new_eth;
    struct iphdr *new_iph;


    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;
    
    //return XDP_DROP;

    if (iph->protocol != IPPROTO_IPIP)
        return XDP_PASS;
    if(iph->daddr != IP_ADDRESS(addr))
        return XDP_DROP;
    bpf_printk("in s server4 got an IPIP packet from %x", bpf_ntohl(iph->saddr));
    bpf_printk("in s destination address of packet: %x" , bpf_ntohl(iph->daddr));
    bpf_printk("in s in s old eth hproto: %x" , bpf_ntohl(eth->h_proto));
    bpf_printk("in s in s old eth source mac 0: %x" , eth->h_source[0]);
    bpf_printk("in s in s old eth source mac 1: %x" , eth->h_source[1]);
    bpf_printk("in s in s old eth source mac 2: %x" , eth->h_source[2]);
    bpf_printk("in s in s old eth source mac 3: %x" , eth->h_source[3]);
    bpf_printk("in s in s old eth source mac 4: %x" , eth->h_source[4]);
    bpf_printk("in s in s old eth source mac 5: %x" , eth->h_source[5]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[0]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[1]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[2]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[3]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[4]);
    bpf_printk("in s in s old eth dest mac: %x" , eth->h_dest[5]);
    bpf_printk("in s old ip proto %x" , bpf_ntohl(iph->protocol));
    bpf_printk("in s old ip saddr %x" , bpf_ntohl(iph->saddr));
    bpf_printk("in s old ip daddr %x" , bpf_ntohl(iph->daddr));
    bpf_printk("in s old ip version: %x" , bpf_ntohl(iph->version));

    //return XDP_DROP;

    if (bpf_xdp_adjust_head(ctx, 0 + (int)sizeof(struct iphdr)))
		return XDP_DROP;
    
    //return XDP_DROP;
    data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

    new_eth = data;
    off = sizeof(struct ethhdr);
    if (data + off > data_end)
        return XDP_DROP;
    new_iph = data + off;
    if(new_iph + 1 > data_end)
        return XDP_DROP;
    bpf_printk("in s original source address %x" , bpf_ntohl(new_iph->saddr));
    bpf_printk("in s original source mac 0: %x",new_eth->h_source[0]);
    bpf_printk("in s original source mac 1: %x",new_eth->h_source[1]);
    bpf_printk("in s original source mac 2: %x",new_eth->h_source[2]);
    bpf_printk("in s original source mac 3: %x",new_eth->h_source[3]);
    bpf_printk("in s original source mac 4: %x",new_eth->h_source[4]);
    bpf_printk("in s original source mac 5: %x",new_eth->h_source[5]);

    bpf_printk("in s original dest mac 0: %x",new_eth->h_dest[0]);
    bpf_printk("in s original dest mac 1: %x",new_eth->h_dest[1]);
    bpf_printk("in s original dest mac 2: %x",new_eth->h_dest[2]);
    bpf_printk("in s original dest mac 3: %x",new_eth->h_dest[3]);
    bpf_printk("in s original dest mac 4: %x",new_eth->h_dest[4]);
    bpf_printk("in s original dest mac 5: %x",new_eth->h_dest[5]);

    unsigned int tempAddr = new_iph->saddr;
    new_iph->saddr = new_iph->daddr;
    new_iph->daddr = tempAddr;

    // char tempmac = new_eth->h_dest[5];
    // new_eth->h_dest[5] = new_eth->h_source[5];
    // new_eth->h_source[5] = tempmac;
    new_eth->h_source[0] = 0;
    new_eth->h_source[1] = 0;
    new_eth->h_source[2] = 0;
    new_eth->h_source[3] = 0;
    new_eth->h_source[4] = 0;
    new_eth->h_source[5] = 3;

    new_eth->h_dest[0] = 0;
    new_eth->h_dest[1] = 0;
    new_eth->h_dest[2] = 0;
    new_eth->h_dest[3] = 0;
    new_eth->h_dest[4] = 0;
    new_eth->h_dest[5] = 2;
    
    new_eth->h_proto = ETH_P_IP;

    if (new_iph->protocol == IPPROTO_TCP){
        bpf_printk("in s it\'s a TCP packet");
        return XDP_PASS;
    }
    else{
        bpf_printk("in s it\'s an UDP packet");
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_DROP;
        struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        unsigned short tempPort = udph->dest;
        udph->dest = udph->source;
        udph->source = tempPort;
        bpf_printk("in s new udp s port: %x" , udph->source);
        bpf_printk("in s new udp d port: %x" , udph->dest);
    }
    
    new_iph->check = iph_csum(new_iph);
    bpf_printk("in s new saddr: %x", bpf_ntohl(new_iph->saddr));
    bpf_printk("in s new daddr: %x", bpf_ntohl(new_iph->daddr));
    bpf_printk("in s new version: %x", bpf_ntohl(new_iph->version));
    bpf_printk("in s new ip proto : %x" , bpf_ntohl(new_iph->protocol));
    bpf_printk("in s ipip : %x" , IPPROTO_IPIP);
    bpf_printk("in s tcp: %x" , IPPROTO_TCP);
    bpf_printk("in s udp: %x" , IPPROTO_UDP);
    bpf_printk("in s new eth source mac 0 %x" , new_eth->h_source[0]);
    bpf_printk("in s new eth source mac 1 %x" , new_eth->h_source[1]);
    bpf_printk("in s new eth source mac 2 %x" , new_eth->h_source[2]);
    bpf_printk("in s new eth source mac 3 %x" , new_eth->h_source[3]);
    bpf_printk("in s new eth source mac 4 %x" , new_eth->h_source[4]);
    bpf_printk("in s new eth source mac 5 %x" , new_eth->h_source[5]);
    bpf_printk("in s new eth dest mac 0 %x" , new_eth->h_dest[0]);
    bpf_printk("in s new eth dest mac 1 %x" , new_eth->h_dest[1]);
    bpf_printk("in s new eth dest mac 2 %x" , new_eth->h_dest[2]);
    bpf_printk("in s new eth dest mac 3 %x" , new_eth->h_dest[3]);
    bpf_printk("in s new eth dest mac 4 %x" , new_eth->h_dest[4]);
    bpf_printk("in s new eth dest mac 5 %x" , new_eth->h_dest[5]);
    bpf_printk("in s new eth proto %x" , bpf_ntohl(new_eth->h_proto));
    bpf_printk("in s eth_p_ip: %x" , ETH_P_IP);
    bpf_printk("in s redirecting the packet to %x" , bpf_ntohl(new_iph->daddr));
    //return XDP_DROP;
    return XDP_TX;
    // struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
    //     return XDP_ABORTED;
    
    // if(iph->daddr != IP_ADDRESS(server1))
    //     return XDP_PASS;

    // unsigned int tempAddr = iph->saddr;
    // iph->saddr = iph->daddr;
    // iph->daddr = tempAddr;

    // char tempMac = eth->h_dest[5];
    // eth->h_dest[5] = eth->h_source[5];
    // eth->h_source[5] = tempMac;

    // unsigned short tempPort = udph->dest;
    // udph->dest = udph->source;
    // udph->source = tempPort;

    // iph->check = iph_csum(iph);

    // return XDP_TX;
    //return XDP_PASS;
}

char _license[] SEC("license") = "GPL";