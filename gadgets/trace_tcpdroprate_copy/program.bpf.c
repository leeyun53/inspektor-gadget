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


// This enum is the same as the one in vmlinux.h, but redefined so that it can provide a name
// to be used for `state` in struct event. This way we get a readable value for column `state`.
enum tcp_state {
	tcp_established = 1,
	tcp_syn_sent = 2,
	tcp_syn_recv = 3,
	tcp_fin_wait1 = 4,
	tcp_fin_wait2 = 5,
	tcp_time_wait = 6,
	tcp_close = 7,
	tcp_close_wait = 8,
	tcp_last_ack = 9,
	tcp_listen = 10,
	tcp_closing = 11,
	tcp_new_syn_recv = 12,
	tcp_max_states = 13,
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

const volatile pid_t target_pid = 0;
GADGET_PARAM(target_pid);
const volatile int target_family = -1;
GADGET_PARAM(target_family);

struct event {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	// The original gadget has instances of these fields for both process context and
	// socket context. Since sub-structures in the `event` are not yet supported, we only use
	// socket context for now. Once sub-structures in the `event` are supported, convert the
	// next fields to a struct.
	gadget_mntns_id mount_ns_id;
	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	enum tcp_state state_raw;
	enum tcp_flags_set tcpflags_raw;
	enum skb_drop_reason reason_raw;
	gadget_kernel_stack kernel_stack_raw;

	u64 packet_counter; //ADDED BY YUN
};

//GADGET_TRACER_MAP(events, 1024 * 256);

//GADGET_TRACER(tcpdrop, events, event);


struct ip_key_t {
	gadget_mntns_id mntns_id;
	gadget_netns_id netns_id;
	gadget_pid pid;
	gadget_tid tid;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	gadget_comm comm[TASK_COMM_LEN];
};

struct traffic_t {
	//size_t sent;
	size_t received;
	size_t received_count;
	size_t dropped_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

GADGET_MAPITER(tcpdroprate, ip_map);

// This struct is the same as struct tcphdr in vmlinux.h but with flags defined as single field instead of bitfield
struct tcphdr_with_flags {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4;
	__u16 doff : 4;
	__u8 flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static int trace_tcp_drop(void *ctx, struct sock *sk,
					    struct sk_buff *skb, int reason)
{
/* 	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	struct tcphdr_with_flags *tcphdr =
		(struct tcphdr_with_flags *)(BPF_CORE_READ(skb, head) +
					     BPF_CORE_READ(skb,
							   transport_header));
	struct inet_sock *sockp = (struct inet_sock *)sk;

	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	ip_key.src.proto_raw = ip_key.dst.proto_raw = IPPROTO_TCP;
	ip_key.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (ip_key.dst.port == 0)
		goto cleanup;
	ip_key.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (ip_key.src.port == 0)
		goto cleanup;

	unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (family) {
	case AF_INET:
		//event->src.version = event->dst.version = 4;
		ip_key.src.version = ip_key.dst.version = 4;

		bpf_probe_read_kernel(&ip_key.src.addr_raw.v4,
			sizeof(sk->__sk_common.skc_rcv_saddr),
			&sk->__sk_common.skc_rcv_saddr);
		if (ip_key.dst.addr_raw.v4 == 0)
			goto cleanup;
		bpf_probe_read_kernel(&ip_key.dst.addr_raw.v4,
			sizeof(sk->__sk_common.skc_daddr),
			&sk->__sk_common.skc_daddr);
		if (ip_key.src.addr_raw.v4 == 0)
			goto cleanup;
		break;

	case AF_INET6:
		//event->src.version = event->dst.version = 6;
		ip_key.src.version = ip_key.dst.version = 6;
		bpf_probe_read_kernel(
			&ip_key.src.addr_raw.v6,
			sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
			&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (ip_key.src.addr_raw.v6 == 0)
			goto cleanup;
		bpf_probe_read_kernel(
			&ip_key.dst.addr_raw.v6,
			sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (ip_key.dst.addr_raw.v6 == 0)
			goto cleanup;
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
		// Use the mount namespace of the socket to filter by container
		if (gadget_should_discard_mntns_id(skb_val->mntns))
			goto cleanup;

		ip_key.mntns_id = skb_val->mntns;
		ip_key.pid = skb_val->pid_tgid >> 32;
		ip_key.tid= (__u32)skb_val->pid_tgid;
		bpf_get_current_comm(&ip_key.comm, sizeof(ip_key.comm));

	} */
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	__u64 mntns_id;
	__u16 family;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

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

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		bpf_printk("trafficp is NULL\n");
		struct traffic_t zero = {0};
		zero.dropped_count = 1;
		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		bpf_printk("trafficep is not NULL\n");
		trafficp->dropped_count = 1;
		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}
	//gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;

cleanup:
	//gadget_discard_buf(event);
	//gadget_discard_buf(ip_map);
	return 0;
}

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	__u64 mntns_id;
	__u16 family;
	//__u64 pid_tgid = bpf_get_current_pid_tgid();
	//__u32 pid = pid_tgid >> 32;
	//__u32 tid = pid_tgid;

	__u64 pid_tgid;
	__u32 pid;
	__u32 tid;
	if (receiving) {
		bpf_printk("is it here??? \n");
		pid_tgid = bpf_get_current_pid_tgid();
		pid = pid_tgid >> 32;
		tid = pid_tgid;
	} else {
		bpf_printk("is it here \n");
		BPF_CORE_READ_INTO(&ip_key.netns_id, sk, __sk_common.skc_net.net,ns.inum);
		struct sockets_value *skb_val = gadget_socket_lookup(sk, ip_key.netns_id);
		bpf_printk("is this the error\n");
		if (skb_val != NULL) {
			pid_tgid=skb_val->pid_tgid;
			ip_key.mntns_id = skb_val->mntns;
			pid = skb_val->pid_tgid >> 32;
			tid = (__u32)skb_val->pid_tgid;
		}
	}

	if (target_pid != 0 && target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && ((target_family == 4 && family != AF_INET) ||
				    (target_family == 6 && family != AF_INET6)))
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	//if (gadget_should_discard_data_current())
	//	return 0;

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

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		struct traffic_t zero = {0};

		if (receiving) {
			//zero.sent = 0;
			zero.received = size;
			zero.received_count = 1;
			zero.dropped_count = 0;
		} else {
			//zero.sent = size;
			//zero.received = 0;
			zero.dropped_count = 1;
		}

		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving) {
			trafficp->received += size;
			trafficp->received_count = 1;
		} else {
			trafficp->dropped_count = 1;
		}
		//else
			//trafficp->sent += size;

		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}

	return 0;
}

SEC("tracepoint/skb/kfree_skb")
int ig_tcpdrop(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = BPF_CORE_READ(skb, sk);
	int reason = ctx->reason;

	// If enum value was not found, bpf_core_enum_value returns 0.
	// The verifier will reject the program with
	// invalid func unknown#195896080
	// 195896080 == 0xbad2310 reads "bad relo"
	int reason_not_specified = bpf_core_enum_value(
		enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);
	if (reason_not_specified == 0)
		bpf_core_unreachable();

	if (reason > reason_not_specified)
		return probe_ip(false, sk, 0);
		//return trace_tcp_drop(ctx, sk, skb, reason);

	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_toptcp_clean, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
