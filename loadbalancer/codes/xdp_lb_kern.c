// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

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
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "jhash.h"
#include "common.h"

struct bpf_map_def SEC("maps") servers = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct dest_info),
	.max_entries = MAX_SERVERS,
};

static __always_inline struct dest_info *hash_get_dest(struct pkt_meta *pkt)
{
	__u32 key;
	struct dest_info *tnl;

	/* hash packet source ip with both ports to obtain a destination */
	key = jhash_2words(pkt->src, pkt->ports, MAX_SERVERS) % MAX_SERVERS;

	/* get destination's network details from map */
	tnl = bpf_map_lookup_elem(&servers, &key);
	if (!tnl) {
		/* if entry does not exist, fallback to key 0 */
		key = 0;
		tnl = bpf_map_lookup_elem(&servers, &key);
	}
	return tnl;
}

static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct udphdr *udp;

	udp = data + off;
	if (udp + 1 > data_end)
		return false;

	pkt->port16[0] = udp->source;
	pkt->port16[1] = udp->dest;

	return true;
}

static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct tcphdr *tcp;

	tcp = data + off;
	if (tcp + 1 > data_end)
		return false;

	pkt->port16[0] = tcp->source;
	pkt->port16[1] = tcp->dest;

	return true;
}

static __always_inline void set_ethhdr(struct ethhdr *new_eth,
				       const struct ethhdr *old_eth,
				       const struct dest_info *tnl,
				       __be16 h_proto)
{
	memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
	memcpy(new_eth->h_dest, tnl->dmac, sizeof(new_eth->h_dest));
	new_eth->h_proto = h_proto;
}

static __always_inline bool is_from_back_servers(unsigned int source_address){
	__u32 key;
	struct dest_info *tnl;
#pragma unroll
	for (int i = 0 ; i < MAX_SERVERS ; i++){
		key = 0;
		tnl = bpf_map_lookup_elem(&servers, &key);
		if (!tnl)
			return XDP_DROP;
		if (tnl->daddr == source_address){
			return true;
		}
	}
	return false;
}

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct pkt_meta pkt = {};
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;
	struct dest_info *tnl;
	struct iphdr iph_tnl;
	struct iphdr *iph;
	__u16 *next_iph_u16;
	__u16 pkt_size;
	__u16 payload_len;
	__u8 protocol;
	u32 csum = 0;

	iph = data + off;
	if (iph + 1 > data_end)
		return XDP_DROP;
	if (iph->ihl != 5)
		return XDP_DROP;
	bpf_printk("it\'s an ip packet from %x" , iph->saddr);
	protocol = iph->protocol;
	payload_len = bpf_ntohs(iph->tot_len);
	off += sizeof(struct iphdr);

	/* do not support fragmented packets as L4 headers may be missing */
	if (iph->frag_off & IP_FRAGMENTED)
		return XDP_DROP;

	if (iph->protocol == IPPROTO_IPIP){
		if (bpf_xdp_adjust_head(ctx, 0 + (int)sizeof(struct ethhdr) + (int)sizeof(struct iphdr)))
			return XDP_DROP;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		struct ethhdr *eth = data;
		if (eth + 1 > data_end)
			return XDP_DROP;
		struct iphdr *iph = data + sizeof(struct ethhdr);
		if (iph + 1 > data_end)
			return XDP_DROP;
		unsigned int addrtemp = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = addrtemp;

		__u8 tempMac[6];
		memcpy(tempMac, eth->h_dest, sizeof(eth->h_dest));
		memcpy(eth->h_dest, eth->h_source, sizeof(eth->h_source));
		memcpy(eth->h_source, tempMac, sizeof(tempMac));

		if (iph->protocol == IPPROTO_TCP){
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
				return XDP_DROP;
			struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if(tcph + 1 > data_end)
				return XDP_DROP;
			unsigned short tempPort = tcph->dest;
			tcph->dest = tcph->source;
			tcph->source = tempPort;
		}
		else{
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
				return XDP_DROP;
			struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if(udph + 1 > data_end)
				return XDP_DROP;
			unsigned short tempPort = udph->dest;
			udph->dest = udph->source;
			udph->source = tempPort;
		}
		iph->check = iph_csum(iph);
		
		return XDP_TX;
	}

	pkt.src = iph->saddr;
	pkt.dst = iph->daddr;

	/* obtain port numbers for UDP and TCP traffic */
	if (protocol == IPPROTO_TCP) {
		if (!parse_tcp(data, off, data_end, &pkt))
			return XDP_DROP;
	} else if (protocol == IPPROTO_UDP) {
		if (!parse_udp(data, off, data_end, &pkt))
			return XDP_DROP;
	} else {
		return XDP_PASS;
	}

	/* allocate a destination using packet hash and map lookup */
	tnl = hash_get_dest(&pkt);
	if (!tnl)
		return XDP_DROP;

	/* extend the packet for ip header encapsulation */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr) - (int)sizeof(struct ethhdr)))
		return XDP_DROP;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* relocate ethernet header to start of packet and set MACs */
	new_eth = data;
	old_eth = data + sizeof(*iph) + sizeof(struct ethhdr);

	if (new_eth + 1 > data_end || old_eth + 1 > data_end ||
	    iph + 1 > data_end)
		return XDP_DROP;

	set_ethhdr(new_eth, old_eth, tnl, bpf_htons(ETH_P_IP));

	/* create an additional ip header for encapsulation */
	iph_tnl.version = 4;
	iph_tnl.ihl = sizeof(*iph) >> 2;
	iph_tnl.frag_off = 0;
	iph_tnl.protocol = IPPROTO_IPIP;
	iph_tnl.check = 0;
	iph_tnl.id = 0;
	iph_tnl.tos = 0;
	iph_tnl.tot_len = bpf_htons(payload_len + sizeof(*iph) + sizeof(struct ethhdr));
	iph_tnl.daddr = tnl->daddr;
	iph_tnl.saddr = tnl->saddr;
	iph_tnl.ttl = 8;

	/* calculate ip header checksum */
	next_iph_u16 = (__u16 *)&iph_tnl;
	#pragma clang loop unroll(full)
	for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
		csum += *next_iph_u16++;
	iph_tnl.check = ~((csum & 0xffff) + (csum >> 16));

	iph = data + sizeof(*new_eth);
	*iph = iph_tnl;

	/* increment map counters */
	pkt_size = (__u16)(data_end - data); /* payload size excl L2 crc */
	__sync_fetch_and_add(&tnl->pkts, 1);
	__sync_fetch_and_add(&tnl->bytes, pkt_size);

	bpf_printk("in p packet size: %x" , data_end - data);

	return XDP_TX;
}

SEC("xdp")
int loadbal(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	bpf_printk("balancer got something!");
	struct ethhdr *eth = data;
	__u32 eth_proto;
	__u32 nh_off;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		return XDP_DROP;
	eth_proto = eth->h_proto;

	/* demo program only accepts ipv4 packets */
	if (eth_proto == bpf_htons(ETH_P_IP))
		return process_packet(ctx, nh_off);
	else
		return XDP_PASS;
}
char _license[] SEC("license") = "GPL";