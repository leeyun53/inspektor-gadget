// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpretrans(8) from BCC
//
// Copyright 2016 Netflix, Inc.
//
// 14-Feb-2016   Brendan Gregg   Created this.
// 03-Nov-2017   Matthias Tafelmeier Extended this.
// Copyright 2023 Microsoft Corporation

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

enum type {
	RETRANS,
	LOSS,
};

enum tcp_flags_set : __u8 {
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	PSH = 0x08,
	ACK = 0x10,
	URG = 0x20,
	ECE = 0x40,
	CWR = 0x80,
};

struct ip_key_t {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	struct gadget_process proc;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	__u8 state;
	enum tcp_flags_set tcpflags_raw;
	__u32 reason;
	enum type type_raw;

	//gadget_mntns_id mntns_id;
	//gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	//gadget_pid pid;
	//gadget_tid tid;
};

struct traffic_t {
	size_t sent_seg;
	size_t retrans_segs;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

GADGET_MAPITER(tcpretransrate, ip_map);

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6


//GADGET_TRACER_MAP(events, 1024 * 256);
//GADGET_TRACER(tcpretrans, events, event);

static __always_inline int __trace_tcp_retrans(void *ctx, const struct sock *sk,
					       const struct sk_buff *skb,
					       enum type type)
{
	bpf_printk("Function called with type: %d\n", type);

	if (type == RETRANS) {
		bpf_printk("Handling RETRANS event\n");
	} else if (type == LOSS) {
		bpf_printk("Handling LOSS event\n");
	}
	struct inet_sock *sockp;
	struct tcp_skb_cb *tcb;
	//struct event *event;
	unsigned int family;
	struct ip_key_t *ip_key;
	struct traffic_t *trafficp;

	if (sk == NULL) {
		bpf_printk("sk == NULL\n");
		return 0;
	}

	__u8 protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
	//char protocol_str[16];
	//char ipproto_tcp_str[16];

	// Convert protocol to string
	//snprintf(protocol_str, sizeof(protocol_str), "%d", protocol);

	// Convert IPPROTO_TCP to string
	//snprintf(ipproto_tcp_str, sizeof(ipproto_tcp_str), "%d", IPPROTO_TCP);
	if ((int)protocol == (int)IPPROTO_TCP) {
		bpf_printk("protocol_str and ipproto_tcp_str are equal: %d, type is :%d\n", (int)protocol, (int)type);
	} else {
		bpf_printk("protocol_str and ipproto_tcp_str are NOT equal: %d != %d, type: %d\n", (int)protocol, (int)IPPROTO_TCP, (int)type);
		return 0;
	}
	//event = gadget_reserve_buf(&events, sizeof(*event));
	//if (!event)
	//	return 0;

	//event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;
	ip_key->src.proto_raw = ip_key->dst.proto_raw = IPPROTO_TCP;

	sockp = (struct inet_sock *)sk;

	ip_key->type_raw = type;
	ip_key->timestamp_raw = bpf_ktime_get_boot_ns();

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	bpf_printk("family\n");
	switch (family) {
	case AF_INET:
		bpf_printk("AF_INET\n");
		ip_key->src.version = ip_key->dst.version = 4;

		BPF_CORE_READ_INTO(&ip_key->src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (ip_key->src.addr_raw.v4 == 0) {
			bpf_printk("ip_key->src.addr_raw.v4 == 0\n");
			goto cleanup;
		}

		BPF_CORE_READ_INTO(&ip_key->dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (ip_key->dst.addr_raw.v4 == 0) {
			bpf_printk("ip_key->dst.addr_raw.v4 == 0\n");
			goto cleanup;
		}
		break;

	case AF_INET6:
		bpf_printk("AF_INET6\n");
		ip_key->src.version = ip_key->dst.version = 6;

		BPF_CORE_READ_INTO(
			&ip_key->src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (((u64 *)ip_key->src.addr_raw.v6)[0] == 0 &&
		    ((u64 *)ip_key->src.addr_raw.v6)[1] == 0) {
				bpf_printk("ip_key->src.addr_raw.v6 == 0\n");
				goto cleanup;
			}

		BPF_CORE_READ_INTO(&ip_key->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (((u64 *)ip_key->dst.addr_raw.v6)[0] == 0 &&
		    ((u64 *)ip_key->dst.addr_raw.v6)[1] == 0) {
				bpf_printk("ip_key->dst.addr_raw.v6 == 0\n");
				goto cleanup;
			}
		break;

	default:
		// drop
		bpf_printk("dropped\n");
		goto cleanup;
	}

	//event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	ip_key->state = BPF_CORE_READ(sk, __sk_common.skc_state);

	// The tcp_retransmit_skb tracepoint is fired with a skb that does not
	// contain the TCP header because the TCP header is built on a cloned skb
	// we don't have access to.
	// skb->transport_header is not set: skb_transport_header_was_set() == false.
	// Instead, we have to read the TCP flags from the TCP control buffer.
	if (skb) {
		bpf_printk("skb not null\n");
		tcb = (struct tcp_skb_cb *)&(skb->cb[0]);
		/* bpf_probe_read_kernel(&event->tcpflags_raw,
				      sizeof(event->tcpflags_raw),
				      &tcb->tcp_flags); */
		bpf_probe_read_kernel(&ip_key->tcpflags_raw, sizeof(ip_key->tcpflags_raw), &tcb->tcp_flags);
	}

/* 	BPF_CORE_READ_INTO(&event->dst.port, sk, __sk_common.skc_dport);
	event->dst.port = bpf_ntohs(
		event->dst.port); // host expects data in host byte order
	if (event->dst.port == 0)
		goto cleanup; */
	
	BPF_CORE_READ_INTO(&ip_key->dst.port, sk, __sk_common.skc_dport);
	ip_key->dst.port = bpf_ntohs(
		ip_key->dst.port); // host expects data in host byte order
	if (ip_key->dst.port == 0) {
		bpf_printk("ip_key->dst.port == 0\n");
		goto cleanup;
	}

	/* BPF_CORE_READ_INTO(&event->src.port, sockp, inet_sport);
	event->src.port = bpf_ntohs(
		event->src.port); // host expects data in host byte order
	if (event->src.port == 0)
		goto cleanup; */
	BPF_CORE_READ_INTO(&ip_key->src.port, sockp, inet_sport);
	ip_key->src.port = bpf_ntohs(
		ip_key->src.port); // host expects data in host byte order
	if (ip_key->src.port == 0) {
		bpf_printk("ip_key->src.port == 0\n");
		goto cleanup;
	}

	/* BPF_CORE_READ_INTO(&event->netns_id, sk, __sk_common.skc_net.net,
			   ns.inum); */
	BPF_CORE_READ_INTO(&ip_key->netns_id, sk, __sk_common.skc_net.net, ns.inum);
	//bpf_printk("ip_key->netns_id = %u\n", ip_key->netns_id);
	bpf_printk("netns_id\n");
	/* struct sockets_value *skb_val = gadget_socket_lookup(sk, event->netns_id); */
	struct sockets_value *skb_val =
		gadget_socket_lookup(sk, ip_key->netns_id);
	//struct sockets_value *skb_val = gadget_socket_lookup(skb);
	//skb_val -> mnts
	if (skb_val == NULL) {
		bpf_printk("SKB_VAL == NULL \n");
	}
	if (skb_val != NULL) {
		bpf_printk("SKB_VAL != NULL \n");
		// Use the mount namespace of the socket to filter by container
		if (gadget_should_discard_mntns_id(skb_val->mntns))
			goto cleanup;

		//gadget_process_populate_from_socket(skb_val, &event->proc);
		gadget_process_populate_from_socket(skb_val, &ip_key->proc);
		//__builtin_memcpy(&ip_key->comm, skb_val->task, sizeof(ip_key->comm));
		//ip_key->pid = skb_val->pid_tgid >> 32;
		//ip_key->tid = skb_val->pid_tgid;
		//ip_key->mntns_id = skb_val->mntns;
		//bpf_printk("skb_val: %p, task: %p, pid_tgid: %llu", skb_val, skb_val ? skb_val->task : NULL, skb_val ? skb_val->pid_tgid : 0);
		//bpf_printk("comm: %s, pid: %u, tid: %u, mntns_id: %u \n", ip_key->comm, ip_key->pid, ip_key->tid, ip_key->mntns_id);
	}
	bpf_printk("final step\n");
	//submit map iterator only when skb != NULL (retransmit event occurred)
	//if (skb) {
	//gadget_submit_buf(ctx, &events, event, sizeof(*event));
	if (type == RETRANS) {
		bpf_printk("RETRANS type\n");
		trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
		if (!trafficp) {
			//bpf_printk("SENT?RECEIVE: New entry: setting the value again\n");
			struct traffic_t zero = {0};
			zero.retrans_segs = 1;
			bpf_printk("New map val added\n");
			bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
			//bpf_map_update_elem(&ip_map2, &ip_key2, &zero, BPF_NOEXIST);
		} else {
			trafficp->retrans_segs++;
			bpf_printk("Existing map val added\n");
			bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
		}
	} else {
		bpf_printk("type value: %d\n", type);
	}
	bpf_printk("I don't think here\n");
	return 0;

cleanup:
	//gadget_discard_buf(event);
	bpf_printk("cleaning\n");
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int ig_tcpretrans(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	// struct trace_event_raw_tcp_event_sk_skb is described in:
	// /sys/kernel/tracing/events/tcp/tcp_retransmit_skb/format
	const struct sk_buff *skb = ctx->skbaddr;
	const struct sock *sk = ctx->skaddr;
	bpf_printk("RETRANS called\n");
	return __trace_tcp_retrans(ctx, sk, skb, RETRANS);
}

SEC("kprobe/tcp_send_loss_probe")
int BPF_KPROBE(ig_tcplossprobe, struct sock *sk)
{
	bpf_printk("send loss called\n");
	return __trace_tcp_retrans(ctx, sk, NULL, LOSS);
}

char LICENSE[] SEC("license") = "GPL";
