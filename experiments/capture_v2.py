# capture_v2.py — adds openat + tcp_connect
from bcc import BPF

prog = r'''
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct exec_data_t {
    u32 pid; u32 ppid; char comm[16]; u64 ts; u8 etype;
};
struct file_data_t {
    u32 pid; char fname[256]; u64 ts; u8 etype;
};
struct net_data_t {
    u32 pid; u32 daddr; u16 dport; u64 ts; u8 etype;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(net_events);

int trace_exec(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    struct exec_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    data.etype = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_open(struct tracepoint__syscalls__sys_enter_openat *ctx) {
    struct file_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.etype = 1;
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), ctx->filename);
    file_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct net_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.etype = 2;
    data.daddr = sk->__sk_common.skc_daddr;
    data.dport = sk->__sk_common.skc_dport;
    net_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
'''

b = BPF(text=prog)
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_exec")
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_open")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

import socket, struct as pystruct

def handle_exec(cpu, data, size):
    e = b["exec_events"].event(data)
    print(f"[EXEC] ts={e.ts} pid={e.pid} ppid={e.ppid} comm={e.comm.decode(errors='replace')}")

def handle_file(cpu, data, size):
    e = b["file_events"].event(data)
    print(f"[FILE] ts={e.ts} pid={e.pid} path={e.fname.decode(errors='replace')}")

def handle_net(cpu, data, size):
    e = b["net_events"].event(data)
    ip = socket.inet_ntoa(pystruct.pack("I", e.daddr))
    port = socket.htons(e.dport)
    print(f"[NET]  ts={e.ts} pid={e.pid} dst={ip}:{port}")

b["exec_events"].open_perf_buffer(handle_exec)
b["file_events"].open_perf_buffer(handle_file)
b["net_events"].open_perf_buffer(handle_net)

print("Tracing exec/open/connect... Ctrl+C to stop")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopped.")
