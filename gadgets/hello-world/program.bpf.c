// program.bpf.c

// Kernel types definitions
// Check https://blog.aquasec.com/vmlinux.h-ebpf-programs for more details
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor Gadget buffer
#include <gadget/buffer.h>

// Inspektor Gadget macros
#include <gadget/macros.h>
#include <gadget/types.h>

#define MAX_ENTRIES 10240

struct metrics_key {
	__u32 key;
};

struct metrics_value {
	gadget_conuter__u32 counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
} metrics SEC(".maps");

//registers a map iterator called "mymetrics" (this will be the name of the data source later on) for the map "metrics" defined above
GADGET_MAPITER(mymetrics, metrics);

#define NAME_MAX 255

// event: a structure with all the information that the gadget will provide
struct event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char filename[NAME_MAX];
	//gadget_timestamp timestamp_raw;
};

// "events" is the name of the buffer eBPF map to send events to user space
// GADGET_TRACER_MAP is a macro that will automatically create a ring buffer if the kernel supports it.
// otherwise a perf array will be created.
// events is the name of the buffer map and 1024 * 256 is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

//Tracer name(open), Buffer Map name(events), Event Structure name(event)
// Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event *event;
	//reserve space for event structure
	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	// collect the information to fill the event
	event->pid = bpf_get_current_pid_tgid() >> 32;
	//event->timestamp_raw = bpf_ktime_get_boot_ns(); //hidden when using columns only when json
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[1]);

	// send the event to user space
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}
//define the license of the eBPF code
char LICENSE[] SEC("license") = "GPL";