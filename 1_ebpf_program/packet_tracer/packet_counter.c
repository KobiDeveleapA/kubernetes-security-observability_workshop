#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") pkt_counter = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("prog")
int count_packets(struct __sk_buff *skb) {
    u32 key = 0;
    u64 *counter;

    counter = bpf_map_lookup_elem(&pkt_counter, &key);
    if (counter) {
        (*counter)++;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

