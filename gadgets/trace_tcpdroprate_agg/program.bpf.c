// SPDX-License-Identifier: GPL-2.0
//
// Based on tcpdrop(8) from BCC
//
// Copyright 2018 Netflix, Inc.
// 30-May-2018    Brendan Gregg   Created this.
// 15-Jun-2022    Rong Tao        Add tracepoint:skb:kfree_skb
// Copyright 2023 Microsoft Corporation

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/core_fixes.bpf.h>
#include <gadget/kernel_stack_map.h>
#include <gadget/filter.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>


/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10
const volatile pid_t target_pid = 0;
GADGET_PARAM(target_pid);
const volatile int target_family = -1;
GADGET_PARAM(target_family);

struct ip_key_t {
	gadget_netns_id netns_id;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	gadget_mntns_id mntns_id;
	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
};

struct traffic_t {
	size_t sent_pkts;
	size_t received_pkts;
	size_t dropped_pkts;
};

struct ip_key2_t {
	gadget_pid name;
	//gadget_netns_id netns_id;
	//struct gadget_l4endpoint_t src;
	//struct gadget_l4endpoint_t dst;

	//gadget_mntns_id mntns_id;
	//gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	//gadget_pid pid;
	//gadget_tid tid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key2_t);
	__type(value, struct traffic_t);
} ip_map2 SEC(".maps");

//GADGET_MAPITER(tcpdroprateagg, ip_map);
GADGET_MAPITER(tcpdropratetest, ip_map2);

static int trace_tcp_drop(void *ctx, struct sock *sk,
					    struct sk_buff *skb, int reason)
{
/* 	if (sk == NULL) {
		//bpf_printk("sk==NULL\n");
		return 0;
	}

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP) {
		//bpf_printk("BPF_CORE_READ_BITFIELD_PROBED != IPROTO_TCP\n");
		return 0;
	} */
	//bpf_printk("no null yes tcp\n");
	/*
	struct tcphdr_with_flags *tcphdr =
		(struct tcphdr_with_flags *)(BPF_CORE_READ(skb, head) +
					     BPF_CORE_READ(skb,
							   transport_header));
							   */
	struct inet_sock *sockp = (struct inet_sock *)sk;

	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;

	ip_key.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (ip_key.dst.port == 0) {
		goto cleanup;
	}

	ip_key.src.port = bpf_ntohs(BPF_CORE_READ(sockp, inet_sport));
	if (ip_key.src.port == 0) {
		goto cleanup;
	}

	unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		ip_key.src.version = ip_key.dst.version = 4;

		BPF_CORE_READ_INTO(&ip_key.dst.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		if (ip_key.dst.addr_raw.v4 == 0) {
			goto cleanup;
		}
		BPF_CORE_READ_INTO(&ip_key.src.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
		if (ip_key.src.addr_raw.v4 == 0) {
			goto cleanup;
		}
		break;

	case AF_INET6:
		ip_key.src.version = ip_key.dst.version = 6;

		BPF_CORE_READ_INTO(
			&ip_key.src.addr_raw.v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (ip_key.src.addr_raw.v6 == 0) {
			goto cleanup;
		}
		BPF_CORE_READ_INTO(&ip_key.dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (ip_key.dst.addr_raw.v6 == 0) {
			goto cleanup;
		}
		break;
	default:
		// drop
		goto cleanup;
	}

	BPF_CORE_READ_INTO(&ip_key.netns_id, sk, __sk_common.skc_net.net,
			   ns.inum);
	struct sockets_value *skb_val =
		gadget_socket_lookup(sk, ip_key.netns_id);
	if (skb_val != NULL) {
		//__u64 mntns_id;
		//__u16 family;
		//__u64 pid_tgid = bpf_get_current_pid_tgid();
		//__u32 pid = pid_tgid >> 32;
		//__u32 tid = pid_tgid;
		// Use the mount namespace of the socket to filter by container

		/*
		if (gadget_should_discard_mntns_id(skb_val->mntns)) {
			//bpf_printk("gadget_should_discard_mntns_id\n");
			goto cleanup;
		}
		*/

		ip_key.mntns_id = skb_val->mntns;
		ip_key.pid = skb_val->pid_tgid >> 32;
		ip_key.tid = (__u32)skb_val->pid_tgid;
		__builtin_memcpy(&ip_key.comm, skb_val->task,
				 sizeof(ip_key.comm));

		u64 len = BPF_CORE_READ(skb, len);
		//trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
		struct ip_key2_t ip_key2 = {};
		ip_key2.name = ip_key.pid;
		trafficp = bpf_map_lookup_elem(&ip_map2, &ip_key2);
		if (!trafficp) {
			bpf_printk("DROP: New entry: setting the value again\n");
			struct traffic_t zero = {0};
			zero.dropped_pkts = 1;
			//bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
			bpf_map_update_elem(&ip_map2, &ip_key2, &zero, BPF_NOEXIST);
		} else {
			trafficp->dropped_pkts++;
			//bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
			bpf_map_update_elem(&ip_map2, &ip_key2, trafficp, BPF_EXIST);
		}

		return 0;
	}

	return 0;

cleanup:
	//gadget_discard_buf(event);

	return 0;
}

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	__u64 mntns_id;
	__u16 family;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	if (target_pid != 0 && target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && ((target_family == 4 && family != AF_INET) ||
				    (target_family == 6 && family != AF_INET6)))
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	mntns_id = gadget_get_current_mntns_id();
	ip_key.pid = pid;
	ip_key.tid = tid;
	ip_key.mntns_id = mntns_id;
	bpf_get_current_comm(&ip_key.comm, sizeof(ip_key.comm));
	ip_key.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_key.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_key.src.proto_raw = ip_key.dst.proto_raw = IPPROTO_TCP;
	if (family == AF_INET) {
		ip_key.src.version = ip_key.dst.version = 4;
	} else {
		ip_key.src.version = ip_key.dst.version = 6;
	}

	if (family == AF_INET) {
		bpf_probe_read_kernel(&ip_key.src.addr_raw.v4,
				      sizeof(sk->__sk_common.skc_rcv_saddr),
				      &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&ip_key.dst.addr_raw.v4,
				      sizeof(sk->__sk_common.skc_daddr),
				      &sk->__sk_common.skc_daddr);
	} else {
		/*
		 * family == AF_INET6,
		 * we already checked above family is correct.
		 */
		bpf_probe_read_kernel(
			&ip_key.src.addr_raw.v6,
			sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
			&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(
			&ip_key.dst.addr_raw.v6,
			sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	struct ip_key2_t ip_key2 = {};
	ip_key2.name = ip_key.pid;
	trafficp = bpf_map_lookup_elem(&ip_map2, &ip_key2);
	if (!trafficp) {
		bpf_printk("SENT?RECEIVE: New entry: setting the value again\n");
		struct traffic_t zero = {0};

		if (receiving) {
			zero.received_pkts = 1;
		} else {
			zero.sent_pkts = 1;
		}
		zero.dropped_pkts = 0;
		//bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
		bpf_map_update_elem(&ip_map2, &ip_key2, &zero, BPF_NOEXIST);
	} else {
		if (receiving) {
			trafficp->received_pkts++;
		}
		else {
			trafficp->sent_pkts++;
		}
		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_toptcp_sdmsg, struct sock *sk, struct msghdr *msg,
	       size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_toptcp_clean, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

SEC("tracepoint/skb/kfree_skb")
int ig_tcpdrop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(ctx, skbaddr);
    //struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
	//struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
	int reason = ctx->reason;

	// If enum value was not found, bpf_core_enum_value returns 0.
	// The verifier will reject the program with
	// invalid func unknown#195896080
	// 195896080 == 0xbad2310 reads "bad relo"
	
	int reason_not_specified = bpf_core_enum_value(
		enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);

	if (reason_not_specified == 0) {
		//bpf_printk("reason_not_specified\n");
		bpf_core_unreachable();
	}

	if (reason > reason_not_specified) {
		if ((sk != NULL) && (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) == IPPROTO_TCP)) {
			return trace_tcp_drop(ctx, sk, skb, reason);
			//don't really need ctx to be passed down
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
