//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    __u32 num;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} array_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event evt = {};
    __u32 key = 0;
    __u32 *value = bpf_map_lookup_elem(&array_map, &key); 
    if (!value) {
	return 0;
    }
    evt.num = *value;

    if (bpf_ringbuf_output(&events_map, &evt, sizeof(evt), 0) != 0) {
	bpf_printk("Failed to send data to user space.");
        return 0;
    }

    int new_value = *value + 1;
    if (bpf_map_update_elem(&array_map, &key, &new_value, 0) != 0) {
	bpf_printk("Failed to update elem in array_map");	    
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
