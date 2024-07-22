#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") openat_counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("tracepoint/syscalls/sys_enter_openat")
int count_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    u64 *counter;

    counter = bpf_map_lookup_elem(&openat_counter, &key);
    if (counter) {
        (*counter)++;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

