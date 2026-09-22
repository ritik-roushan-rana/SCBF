#!/usr/bin/env python3
"""
SCBF - NPM rich-telemetry capture (eBPF / BCC).

Traces `npm install <tarball>` followed by `node -e "require('<pkg>')"` and
writes one JSONL trace with the extended fields consumed by
scbf/training/npm_rich_features.py:

    exec     : argv (list of strings)
    connect  : daddr, dport, family ("inet" | "inet6" | "unix")
    all      : phase ("install" | "require")

plus the original {type, pid, ppid, comm, fname, ts}.

Differences from the original NPM collector:
  * children are tracked in-kernel via sched_process_fork (short-lived
    processes such as `sh -c "curl ... | bash"` are no longer missed)
  * ppid is read in-kernel (correct even for processes that exit quickly)
  * the tarball is copied to a neutral /tmp path so the label never
    appears in any file path

Usage (as root, on the Ubuntu VM):
    sudo -E python3 scripts/npm_capture_rich.py PKG.tgz OUT.jsonl \
        [--install-timeout 180] [--require-timeout 30] [--no-require]

Normally driven by scripts/npm_collect_rich.sh for a whole directory.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

from bcc import BPF

ARGV_MAX = 12
ARG_LEN = 200

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/stddef.h>

#define ARGV_MAX %d
#define ARG_LEN  %d

struct event_t {
    u32 pid;
    u32 ppid;
    u32 type;        /* 0 exec, 1 open, 2 connect */
    u32 nargs;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[512];
    /* connect */
    u16 family;
    u16 dport;
    unsigned char daddr[16];
    /* exec */
    char argv[ARGV_MAX][ARG_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(tracked, u32, u8, 65536);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);

static __always_inline int is_tracked(u32 pid)
{
    u8 *v = tracked.lookup(&pid);
    return v != 0;
}

static __always_inline struct event_t *prep(u32 type)
{
    u32 zero = 0;
    struct event_t *e = scratch.lookup(&zero);
    if (!e)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = task->real_parent->tgid;
    e->type = type;
    e->nargs = 0;
    e->ts = bpf_ktime_get_ns();
    e->family = 0;
    e->dport = 0;
    e->fname[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

/* follow forks so every descendant of the install process is traced */
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    if (is_tracked(parent)) {
        u8 one = 1;
        tracked.update(&child, &one);
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (pid == tid)
        tracked.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;
    struct event_t *e = prep(0);
    if (!e)
        return 0;
    bpf_probe_read_user_str(&e->fname, sizeof(e->fname), args->filename);

    const char *const *argv = args->argv;
    #pragma unroll
    for (int i = 0; i < ARGV_MAX; i++) {
        const char *argp = 0;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(&e->argv[i], ARG_LEN, argp);
        e->nargs = i + 1;
    }
    events.perf_submit(args, e, sizeof(*e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;
    struct event_t *e = prep(1);
    if (!e)
        return 0;
    bpf_probe_read_user_str(&e->fname, sizeof(e->fname), args->filename);
    events.perf_submit(args, e, offsetof(struct event_t, argv));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;
    struct event_t *e = prep(2);
    if (!e)
        return 0;
    e->fname[0] = 'c'; e->fname[1] = 'o'; e->fname[2] = 'n'; e->fname[3] = 'n';
    e->fname[4] = 'e'; e->fname[5] = 'c'; e->fname[6] = 't'; e->fname[7] = 0;

    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
    e->family = sa.sa_family;
    if (sa.sa_family == AF_INET) {
        struct sockaddr_in in4 = {};
        bpf_probe_read_user(&in4, sizeof(in4), args->uservaddr);
        e->dport = in4.sin_port;
        __builtin_memcpy(e->daddr, &in4.sin_addr.s_addr, 4);
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 in6 = {};
        bpf_probe_read_user(&in6, sizeof(in6), args->uservaddr);
        e->dport = in6.sin6_port;
        __builtin_memcpy(e->daddr, &in6.sin6_addr, 16);
    }
    events.perf_submit(args, e, offsetof(struct event_t, argv));
    return 0;
}
""" % (ARGV_MAX, ARG_LEN)

EVENT_TYPES = {0: "exec", 1: "open", 2: "connect"}
AF_INET, AF_INET6, AF_UNIX = 2, 10, 1


def cstr(buf):
    return bytes(buf).split(b"\0", 1)[0].decode("utf-8", errors="replace")


def package_name(tgz):
    """Read the package name from package/package.json inside the tarball."""
    try:
        with tarfile.open(tgz, "r:gz") as tf:
            for m in tf.getmembers():
                if m.name.endswith("package.json") and m.name.count("/") == 1:
                    return json.load(tf.extractfile(m)).get("name")
    except Exception:  # noqa: BLE001
        return None
    return None


def kill_tree(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tarball")
    ap.add_argument("output")
    ap.add_argument("--install-timeout", type=int, default=180)
    ap.add_argument("--require-timeout", type=int, default=30)
    ap.add_argument("--no-require", action="store_true", help="skip the require() phase")
    ap.add_argument("--user", default=os.environ.get("SCBF_USER") or os.environ.get("SUDO_USER") or "",
                    help="unprivileged user to run npm/node as (default: SUDO_USER)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[ERROR] must run as root (eBPF)")

    tarball = os.path.abspath(args.tarball)
    pkg = package_name(tarball) or os.path.basename(tarball).rsplit("-", 1)[0]
    print(f"[+] Package : {pkg}")
    print(f"[+] Tarball : {tarball}")

    # neutral working dirs: no dataset / label information in any path
    work = tempfile.mkdtemp(prefix="scbf-npm-pkg-")
    install_dir = tempfile.mkdtemp(prefix="scbf-npm-install-")
    cache_dir = tempfile.mkdtemp(prefix="scbf-npm-cache-")
    local_tgz = os.path.join(work, "package.tgz")
    shutil.copy(tarball, local_tgz)
    if args.user:
        subprocess.run(["chown", "-R", args.user, work, install_dir, cache_dir], check=False)

    # ---------------- eBPF ----------------
    print("[+] Loading eBPF program...")
    bpf = BPF(text=BPF_PROGRAM)
    events, lost, state = [], [0], {"phase": "install"}

    def on_lost(n):
        lost[0] += n

    def on_event(cpu, data, size):
        ev = bpf["events"].event(data)
        rec = {
            "type": EVENT_TYPES.get(int(ev.type), "unknown"),
            "pid": int(ev.pid),
            "ppid": int(ev.ppid),
            "comm": cstr(ev.comm),
            "fname": cstr(ev.fname),
            "ts": int(ev.ts),
            "phase": state["phase"],
        }
        if ev.type == 0:
            n = min(int(ev.nargs), ARGV_MAX)
            rec["argv"] = [cstr(ev.argv[i]) for i in range(n)]
        elif ev.type == 2:
            fam = int(ev.family)
            raw = bytes(ev.daddr)
            if fam == AF_INET:
                rec["family"], rec["daddr"] = "inet", socket.inet_ntop(socket.AF_INET, raw[:4])
                rec["dport"] = struct.unpack("!H", struct.pack("=H", int(ev.dport)))[0]
            elif fam == AF_INET6:
                rec["family"], rec["daddr"] = "inet6", socket.inet_ntop(socket.AF_INET6, raw[:16])
                rec["dport"] = struct.unpack("!H", struct.pack("=H", int(ev.dport)))[0]
            elif fam == AF_UNIX:
                rec["family"], rec["daddr"], rec["dport"] = "unix", "", 0
            else:
                rec["family"], rec["daddr"], rec["dport"] = str(fam), "", 0
        events.append(rec)

    bpf["events"].open_perf_buffer(on_event, page_cnt=256, lost_cb=on_lost)

    def as_user(cmd):
        return ["sudo", "-u", args.user, "-H", *cmd] if args.user and args.user != "root" else cmd

    def run_phase(name, cmd, timeout, cwd):
        """Run cmd traced; the tracked map is seeded with the root pid and
        sched_process_fork follows every descendant."""
        state["phase"] = name
        print(f"[+] phase={name}: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        bpf["tracked"][bpf["tracked"].Key(proc.pid)] = bpf["tracked"].Leaf(1)
        deadline = time.time() + timeout
        timed_out = False
        while proc.poll() is None:
            if time.time() > deadline:
                timed_out = True
                kill_tree(proc)
                break
            try:
                bpf.perf_buffer_poll(timeout=50)
            except KeyboardInterrupt:
                kill_tree(proc)
                raise
        rc = proc.wait()
        for _ in range(20):  # drain before the phase label changes
            bpf.perf_buffer_poll(timeout=20)
        print(f"[+] phase={name} done rc={rc}{' (TIMEOUT)' if timed_out else ''}  events so far={len(events)}")
        return rc, timed_out

    env = ["env", f"HOME={os.path.expanduser('~' + args.user) if args.user else os.environ.get('HOME', '/root')}",
           f"npm_config_cache={cache_dir}", "npm_config_update_notifier=false", "npm_config_fund=false",
           "npm_config_audit=false", "npm_config_loglevel=error"]

    result = {"package": pkg, "tarball": os.path.basename(tarball)}
    t0 = time.time()
    rc, to = run_phase("install",
                       as_user([*env, "npm", "install", "--prefix", install_dir, "--no-save",
                                "--ignore-scripts=false", local_tgz]),
                       args.install_timeout, install_dir)
    result["install_rc"], result["install_timeout"] = rc, to

    if not args.no_require:
        node_path = os.path.join(install_dir, "node_modules")
        rc, to = run_phase("require",
                           as_user([*env, f"NODE_PATH={node_path}", "node", "-e",
                                    f"try{{require({json.dumps(pkg)})}}catch(e){{console.error(e.message)}}"]),
                           args.require_timeout, install_dir)
        result["require_rc"], result["require_timeout"] = rc, to

    # ---------------- write ----------------
    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    result.update({
        "events": len(events),
        "events_lost": lost[0],
        "n_exec": sum(1 for e in events if e["type"] == "exec"),
        "n_connect": sum(1 for e in events if e["type"] == "connect"),
        "n_require_phase": sum(1 for e in events if e["phase"] == "require"),
        "seconds": round(time.time() - t0, 1),
        "output": args.output,
    })
    print("[+] " + json.dumps(result))

    for d in (work, install_dir, cache_dir):
        shutil.rmtree(d, ignore_errors=True)
    return 0 if result["install_rc"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
