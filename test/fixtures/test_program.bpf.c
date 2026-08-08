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

SEC("tracepoint/syscalls/sys_enter_getpid")
int test_tracepoint_program(void *ctx) {
  return 0;
}

SEC("xdp")
int test_xdp_program(struct xdp_md *ctx) {
  return XDP_PASS;
}

SEC("tcx/ingress")
int test_tcx_program(struct __sk_buff *skb) {
  return 0;
}

SEC("kprobe")
int test_kprobe_program(struct pt_regs *ctx) {
  return 0;
}

char _license[] SEC("license") = "GPL";
