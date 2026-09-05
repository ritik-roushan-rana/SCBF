#!/bin/bash

set -u

PACKAGE="${1:-}"
PYTHON_BIN="${2:-}"
ARTIFACT="${3:-}"
OUTPUT="${4:-}"

if [ -z "$PACKAGE" ] || [ -z "$PYTHON_BIN" ] || [ -z "$ARTIFACT" ] || [ -z "$OUTPUT" ]; then
    echo "Usage:"
    echo "  sudo ./monitor.sh PACKAGE PYTHON_BIN ARTIFACT OUTPUT"
    exit 2
fi

echo "============================================================"
echo "[+] SCBF eBPF Monitor"
echo "[+] Package : $PACKAGE"
echo "[+] Python  : $PYTHON_BIN"
echo "[+] Artifact: $ARTIFACT"
echo "[+] Output  : $OUTPUT"
echo "============================================================"

exec python3 - "$PACKAGE" "$PYTHON_BIN" "$ARTIFACT" "$OUTPUT" <<'PYTHON'
import sys
import os
import json
import time
import subprocess

from bcc import BPF


PACKAGE = sys.argv[1]
PYTHON_BIN = sys.argv[2]
ARTIFACT = sys.argv[3]
OUTPUT = sys.argv[4]


if os.geteuid() != 0:
    print("[ERROR] Monitor must run as root.")
    sys.exit(1)

os.makedirs(os.path.dirname(OUTPUT) or ".", exist_ok=True)

try:
    os.remove(OUTPUT)
except FileNotFoundError:
    pass


# ============================================================
# eBPF PROGRAM
# ============================================================

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char fname[512];
    u64 ts;
    u32 type;
};

BPF_PERF_OUTPUT(events);

BPF_HASH(tracked, u32, u8, 32768);

BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);


static int is_tracked(u32 pid)
{
    u8 *value = tracked.lookup(&pid);

    if (value)
        return 1;

    return 0;
}


/*
 * 0 = exec
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 0;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    bpf_probe_read_user_str(
        &event->fname,
        sizeof(event->fname),
        args->filename
    );

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}


/*
 * 1 = open
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 1;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    bpf_probe_read_user_str(
        &event->fname,
        sizeof(event->fname),
        args->filename
    );

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}


/*
 * 2 = connect
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(pid))
        return 0;

    u32 zero = 0;

    struct event_t *event =
        event_scratch.lookup(&zero);

    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0;
    event->ts = bpf_ktime_get_ns();
    event->type = 2;

    bpf_get_current_comm(
        &event->comm,
        sizeof(event->comm)
    );

    /*
     * Store a marker here.
     *
     * The userspace side can classify this as a
     * network connection event.
     */
    event->fname[0] = 'c';
    event->fname[1] = 'o';
    event->fname[2] = 'n';
    event->fname[3] = 'n';
    event->fname[4] = 'e';
    event->fname[5] = 'c';
    event->fname[6] = 't';
    event->fname[7] = '\0';

    events.perf_submit(
        args,
        event,
        sizeof(*event)
    );

    return 0;
}
"""


# ============================================================
# LOAD BPF
# ============================================================

print("[+] Loading eBPF program...")

try:
    bpf = BPF(text=BPF_PROGRAM)
except Exception as e:
    print("[ERROR] Failed to load eBPF:")
    print(e)
    sys.exit(1)

print("[+] eBPF loaded successfully.")


events = []
lost_events = 0


EVENT_TYPES = {
    0: "exec",
    1: "open",
    2: "connect",
}


def handle_lost(lost):
    global lost_events
    lost_events += lost


def get_ppid(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            data = f.read()

        close_paren = data.rfind(")")

        if close_paren == -1:
            return 0

        fields = data[close_paren + 2:].split()

        return int(fields[1])

    except Exception:
        return 0


def get_children(pid):
    children = set()

    try:
        for entry in os.listdir("/proc"):

            if not entry.isdigit():
                continue

            child = int(entry)

            if get_ppid(child) == pid:
                children.add(child)

    except Exception:
        pass

    return children


def get_process_tree(pid):
    tree = {pid}
    queue = [pid]

    while queue:

        parent = queue.pop()

        for child in get_children(parent):

            if child not in tree:

                tree.add(child)
                queue.append(child)

    return tree


def sync_process_tree(root_pid):

    tree = get_process_tree(root_pid)

    tracked_map = bpf["tracked"]

    for pid in tree:

        try:

            key = tracked_map.Key(pid)

            tracked_map[key] = tracked_map.Leaf(1)

        except Exception:
            pass

    return tree


def handle_event(cpu, data, size):

    event = bpf["events"].event(data)

    pid = int(event.pid)

    ppid = get_ppid(pid)

    comm = bytes(event.comm).split(
        b"\0",
        1
    )[0].decode(
        "utf-8",
        errors="replace"
    )

    fname = bytes(event.fname).split(
        b"\0",
        1
    )[0].decode(
        "utf-8",
        errors="replace"
    )

    event_type = EVENT_TYPES.get(
        int(event.type),
        "unknown"
    )

    events.append(
        {
            "type": event_type,
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "fname": fname,
            "ts": int(event.ts),
        }
    )


bpf["events"].open_perf_buffer(
    handle_event,
    page_cnt=128,
    lost_cb=handle_lost,
)


# ============================================================
# START PIP
# ============================================================

print("[+] Starting pip installation...")

cmd = [
    PYTHON_BIN,
    "-m",
    "pip",
    "install",
    "--no-build-isolation",
    "--disable-pip-version-check",
    ARTIFACT,
]

try:

    # The monitor must remain root for eBPF/BCC,
    # but pip/package installation must run as ubuntu.
    #
    # This prevents root-owned files from being created
    # inside the temporary virtual environment.
    proc = subprocess.Popen(
        [
            "sudo",
            "-u",
            "ubuntu",
            "-H",
            *cmd,
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

except Exception as e:

    print("[ERROR] Failed to start pip:")
    print(e)

    sys.exit(1)


root_pid = proc.pid

print(f"[+] pip PID: {root_pid}")
print("[+] Monitoring process tree...")
print()


# ============================================================
# MONITOR LOOP
# ============================================================

while proc.poll() is None:

    sync_process_tree(root_pid)

    try:

        bpf.perf_buffer_poll(
            timeout=100
        )

    except KeyboardInterrupt:

        proc.terminate()
        break

    except Exception:
        pass


returncode = proc.wait()


# ============================================================
# FINAL DRAIN
# ============================================================

print()
print("[+] pip finished.")
print(f"[+] pip return code : {returncode}")
print("[+] Draining remaining eBPF events...")

for _ in range(10):

    try:

        bpf.perf_buffer_poll(
            timeout=50
        )

    except Exception:
        pass


# ============================================================
# WRITE JSONL
# ============================================================

print("[+] Writing JSONL...")

with open(
    OUTPUT,
    "w",
    encoding="utf-8",
) as f:

    for event in events:

        f.write(
            json.dumps(event)
            + "\n"
        )


pids = set(
    event["pid"]
    for event in events
)


print()
print("============================================================")
print("[+] MONITOR COMPLETE")
print("============================================================")
print(f"[+] Package         : {PACKAGE}")
print(f"[+] pip return code : {returncode}")
print(f"[+] Events captured : {len(events)}")
print(f"[+] Events lost     : {lost_events}")
print(f"[+] PIDs with events: {len(pids)}")
print(f"[+] Output          : {OUTPUT}")

if returncode == 0:
    print("[+] INSTALLATION SUCCESS")
else:
    print("[!] INSTALLATION FAILED")

print("============================================================")


# Return the ACTUAL pip return code.
sys.exit(returncode)
PYTHON
