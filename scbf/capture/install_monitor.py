from bcc import BPF
import subprocess
import time
import threading

PROG = r'''
#include <linux/sched.h>

struct exec_data_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    u64 ts;
};

struct file_data_t {
    u32 pid;
    char fname[256];
    u64 ts;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(file_events);

int trace_exec(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    struct exec_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    exec_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_open(struct tracepoint__syscalls__sys_enter_openat *ctx) {
    struct file_data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();

    bpf_probe_read_user_str(
        &data.fname,
        sizeof(data.fname),
        ctx->filename
    );

    file_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
'''


class InstallMonitor:
    def __init__(self):
        self.b = BPF(text=PROG)

        self.b.attach_tracepoint(
            tp="syscalls:sys_enter_execve",
            fn_name="trace_exec"
        )

        self.b.attach_tracepoint(
            tp="syscalls:sys_enter_openat",
            fn_name="trace_open"
        )

        self.tracked_pids = set()
        self.on_event = None

        self._stop = False
        self._poll_thread = None
        self._buffers_open = False
        self._lock = threading.Lock()

        self._open_buffers()

    def _open_buffers(self):
        if self._buffers_open:
            return

        self.b["exec_events"].open_perf_buffer(self._handle_exec)
        self.b["file_events"].open_perf_buffer(self._handle_file)

        self._buffers_open = True

    def _is_descendant(self, pid, ppid):
        return pid in self.tracked_pids or ppid in self.tracked_pids

    def _handle_exec(self, cpu, data, size):
        e = self.b["exec_events"].event(data)

        if self._is_descendant(e.pid, e.ppid):
            with self._lock:
                self.tracked_pids.add(e.pid)

            event = {
                "type": "exec",
                "pid": e.pid,
                "ppid": e.ppid,
                "comm": e.comm.decode(
                    errors="replace"
                ).rstrip("\x00"),
                "ts": e.ts
            }

            if self.on_event:
                self.on_event(event)

    def _handle_file(self, cpu, data, size):
        e = self.b["file_events"].event(data)

        with self._lock:
            tracked = e.pid in self.tracked_pids

        if tracked:
            event = {
                "type": "open",
                "pid": e.pid,
                "fname": e.fname.decode(
                    errors="replace"
                ).rstrip("\x00"),
                "ts": e.ts
            }

            if self.on_event:
                self.on_event(event)

    def _poll_loop(self):
        while not self._stop:
            try:
                self.b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception:
                if not self._stop:
                    raise
                break

    def run_and_capture(self, cmd, duration_sec=30):
        self._stop = False

        with self._lock:
            self.tracked_pids.clear()

        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            daemon=True
        )

        self._poll_thread.start()

        proc = subprocess.Popen(cmd)

        with self._lock:
            self.tracked_pids.add(proc.pid)

        try:
            proc.wait(timeout=duration_sec)

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        time.sleep(0.5)

        self._stop = True

        if self._poll_thread:
            self._poll_thread.join(timeout=2)

        return proc.returncode

    def cleanup(self):
        self._stop = True

        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=2)

        try:
            self.b.cleanup()
        except Exception:
            pass