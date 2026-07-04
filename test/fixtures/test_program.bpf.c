#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 8);
} test_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 4);
} test_sockmap SEC(".maps");

SEC("sk_reuseport")
int test_program(struct sk_reuseport_md *ctx) {
  return SK_PASS;
}

char _license[] SEC("license") = "GPL";
