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

#define BALANCER 3

struct bpf_map_def SEC("maps") servers = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ip_key),
	.value_size = sizeof(struct dest_info),
	.max_entries = MAX_SERVERS,
};

struct bpf_map_def SEC("maps") server_ips = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ip_key),
	.value_size = sizeof(struct server_ip_key),
	.max_entries = MAX_SERVERS,
};

struct bpf_map_def SEC("maps") client_addrs = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct port_key),
	.value_size = sizeof(struct client_port_addr),
	.max_entries = MAX_CLIENTS,
};

struct bpf_map_def SEC("maps") stoc_port_maps = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct port_key),
	.value_size = sizeof(struct port_map),
	.max_entries = MAX_FLOWS,
};

struct bpf_map_def SEC("maps") ctos_port_maps = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct port_key),
	.value_size = sizeof(struct port_map),
	.max_entries = MAX_FLOWS,
};

static __always_inline struct dest_info *hash_get_dest(struct pkt_meta *pkt)
{
	struct ip_key key;
	struct dest_info *tnl;

	/* hash packet source ip with both ports to obtain a destination */
	key.key = jhash_2words(pkt->src, pkt->ports, MAX_SERVERS) % MAX_SERVERS;
	key.pad = 0;

	/* get destination's network details from map */
	tnl = bpf_map_lookup_elem(&servers, &key);
	if (tnl) {
		/* if entry does not exist, fallback to key 0 */
		// key.key = 0;
		// tnl = bpf_map_lookup_elem(&servers, &key);
		return tnl;
	}
	return NULL;
}

static __always_inline struct port_map *hash_get_port(struct pkt_meta *pkt, bool isFromServers)
{
	struct port_key key;
	struct port_map *tnl;

	key.port = pkt->port16[0];
	key.pad[0] = 0;
	key.pad[1] = 0;
	key.pad[2] = 0;
	
	tnl = (isFromServers) ? bpf_map_lookup_elem(&stoc_port_maps, &key) :
							bpf_map_lookup_elem(&ctos_port_maps, &key);
	if(tnl) {
		return tnl;
	}
	return NULL;
}

static __always_inline struct client_port_addr *hash_get_client_ip(__u16 port)
{
	struct port_key key;
	struct client_port_addr *tnl;

	key.port = port;
	key.pad[0] = 0;
	key.pad[1] = 0;
	key.pad[2] = 0;
	
	tnl = bpf_map_lookup_elem(&client_addrs, &key);
	if(tnl)
		return tnl;
	return NULL;
}

static __always_inline bool is_from_back_servers(unsigned int source_address){
	struct ip_key key;
	key.key = source_address;
	key.pad = 0;
	struct server_ip_key *tnl;
	
	tnl = bpf_map_lookup_elem(&server_ips, &key);
	if (!tnl) {
		return false;
	}
	return true;
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

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct pkt_meta pkt = {};
	struct dest_info *dest_tnl;
	struct port_map *port_tnl;
	struct ethhdr *eth;
	struct iphdr *iph;
	__u8 protocol;
	bool isFromServers;

	eth = data;
	if (eth + 1 > data_end)
		return XDP_DROP;
	iph = data + off;
	if (iph + 1 > data_end)
		return XDP_DROP;
	if (iph->ihl != 5)
		return XDP_DROP;
	bpf_printk("it\'s an ip packet from %x" , iph->saddr);
	protocol = iph->protocol;
	// payload_len = bpf_ntohs(iph->tot_len);
	off += sizeof(struct iphdr);

	/* do not support fragmented packets as L4 headers may be missing */
	if (iph->frag_off & IP_FRAGMENTED)
		return XDP_DROP;

	pkt.src = iph->saddr;
	pkt.dst = iph->daddr;
	pkt.smac[0] = eth->h_source[0];
	pkt.smac[1] = eth->h_source[1];
	pkt.smac[2] = eth->h_source[2];
	pkt.smac[3] = eth->h_source[3];
	pkt.smac[4] = eth->h_source[4];
	pkt.smac[5] = eth->h_source[5];

	pkt.dmac[0] = eth->h_dest[0];
	pkt.dmac[1] = eth->h_dest[1];
	pkt.dmac[2] = eth->h_dest[2];
	pkt.dmac[3] = eth->h_dest[3];
	pkt.dmac[4] = eth->h_dest[4];
	pkt.dmac[5] = eth->h_dest[5];

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

	isFromServers = is_from_back_servers(iph->saddr);
	port_tnl = hash_get_port(&pkt, isFromServers);
	if(isFromServers)
	{
		struct client_port_addr *dst;
		dst = hash_get_client_ip(pkt.port16[1]);
		if(!dst)
			return XDP_DROP;
		if(!port_tnl)
		{
			struct port_key key1, key2;
			struct port_map val1, val2;
			key1.port = pkt.port16[0];
			key1.pad[0] = 0;
			key1.pad[1] = 0;
			key1.pad[2] = 0;
			key2.port = pkt.port16[1];
			key2.pad[0] = 0;
			key2.pad[1] = 0;
			key2.pad[2] = 0;
			val1.daddr = dst->client_ip;
			val1.dport = key2.port;
			val1.dmac[0] = dst->dmac[0];
			val1.dmac[1] = dst->dmac[1];
			val1.dmac[2] = dst->dmac[2];
			val1.dmac[3] = dst->dmac[3];
			val1.dmac[4] = dst->dmac[4];
			val1.dmac[5] = dst->dmac[5];
			val1.pad = 0;
			// bpf_map_update_elem(&stoc_port_maps, &key1, &val1, BPF_ANY);
			val2.daddr = pkt.src;
			val2.dport = key1.port;
			val2.dmac[0] = pkt.smac[0];
			val2.dmac[1] = pkt.smac[1];
			val2.dmac[2] = pkt.smac[2];
			val2.dmac[3] = pkt.smac[3];
			val2.dmac[4] = pkt.smac[4];
			val2.dmac[5] = pkt.smac[5];
			val2.pad = 0;
			// bpf_map_update_elem(&ctos_port_maps, &key2, &val2, BPF_ANY);
		}
		iph->saddr = IP_ADDRESS(BALANCER);
		iph->daddr = dst->client_ip;

		eth->h_source[0] = eth->h_dest[0];
		eth->h_source[1] = eth->h_dest[1];
		eth->h_source[2] = eth->h_dest[2];
		eth->h_source[3] = eth->h_dest[3];
		eth->h_source[4] = eth->h_dest[4];
		eth->h_source[5] = eth->h_dest[5];

		eth->h_dest[0] = dst->dmac[0];
		eth->h_dest[1] = dst->dmac[1];
		eth->h_dest[2] = dst->dmac[2];
		eth->h_dest[3] = dst->dmac[3];
		eth->h_dest[4] = dst->dmac[4];
		eth->h_dest[5] = dst->dmac[5];
	}
	else
	{
		if(!port_tnl)
		{
			__u16 key;
			struct client_port_addr val;
			// struct client_port_addr *test;
			
			// allocate a destination using packet hash and map lookup,
			// could be replaced with custom balancing algorithms
			struct ip_key tnl_key;
			tnl_key.key = jhash_2words(pkt.src, pkt.ports, MAX_SERVERS) % MAX_SERVERS;
			tnl_key.pad = 0;
			dest_tnl = bpf_map_lookup_elem(&servers, &key);
			if (!dest_tnl) {
				/* if entry does not exist, fallback to key 0 */
				// key.key = 0;
				// tnl = bpf_map_lookup_elem(&servers, &key);
				return XDP_ABORTED;
			}
			
			key = pkt.port16[0];
			val.client_ip = pkt.src;
			val.dmac[0] = pkt.smac[0];
			val.dmac[1] = pkt.smac[1];
			val.dmac[2] = pkt.smac[2];
			val.dmac[3] = pkt.smac[3];
			val.dmac[4] = pkt.smac[4];
			val.dmac[5] = pkt.smac[5];

			// test = hash_get_client_ip(key);
			// if(test) {
			// 	bpf_printk("client port %d busy", key);
			// 	return XDP_DROP;
			// }
			bpf_map_update_elem(&client_addrs, &key, &val, BPF_ANY);

			iph->saddr = IP_ADDRESS(BALANCER);
			iph->daddr = dest_tnl->daddr;

			eth->h_source[0] = eth->h_dest[0];
			eth->h_source[1] = eth->h_dest[1];
			eth->h_source[2] = eth->h_dest[2];
			eth->h_source[3] = eth->h_dest[3];
			eth->h_source[4] = eth->h_dest[4];
			eth->h_source[5] = eth->h_dest[5];

			eth->h_dest[0] = dest_tnl->dmac[0];
			eth->h_dest[1] = dest_tnl->dmac[1];
			eth->h_dest[2] = dest_tnl->dmac[2];
			eth->h_dest[3] = dest_tnl->dmac[3];
			eth->h_dest[4] = dest_tnl->dmac[4];
			eth->h_dest[5] = dest_tnl->dmac[5];

		}
		else{
			iph->saddr = IP_ADDRESS(BALANCER);
			iph->daddr = port_tnl->daddr;

			eth->h_source[0] = eth->h_dest[0];
			eth->h_source[1] = eth->h_dest[1];
			eth->h_source[2] = eth->h_dest[2];
			eth->h_source[3] = eth->h_dest[3];
			eth->h_source[4] = eth->h_dest[4];
			eth->h_source[5] = eth->h_dest[5];

			eth->h_dest[0] = port_tnl->dmac[0];
			eth->h_dest[1] = port_tnl->dmac[1];
			eth->h_dest[2] = port_tnl->dmac[2];
			eth->h_dest[3] = port_tnl->dmac[3];
			eth->h_dest[4] = port_tnl->dmac[4];
			eth->h_dest[5] = port_tnl->dmac[5];
			// memcpy (destination, source, sizeof(source));
		}
	}
		// /* increment map counters */
		// pkt_size = (__u16)(data_end - data); /* payload size excl L2 crc */
		// __sync_fetch_and_add(&dest_tnl->pkts, 1);
		// __sync_fetch_and_add(&dest_tnl->bytes, pkt_size);

	iph->check = iph_csum(iph);

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