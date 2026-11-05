# HV Mode's Pause and the "allow visible Windows actions" switch (hvwindows / [Engine] HvAllowWindows, default OFF),
# driven through the REAL x64dbg (headless.exe) against antidebug-lab's adbg_target.
#   rev151 image (the hypervisor's FREEZE): Pause works with the switch OFF -- x64dbg shows the target paused, its own
#     writes stop, and Windows shows NO thread suspended (nothing visible); Run resumes it. The freeze is preferred with
#     the switch ON too.
#   older image: OFF, Pause is refused; ON, Pause freezes the target through Windows (logged as done through Windows).
#   Either: alloc is refused OFF and works ON (through Windows, logged). The switch is put back OFF -- and checked.
import ctypes, subprocess, sys, threading, time, queue, re

BIN = r"C:\projs\x64dbg-turing\bin\x64"
TARGET = r"C:\projs\antidebug-lab\target\adbg_target.exe"

def suspended_threads(pid):
    """Threads of `pid` Windows reports suspended (state 5 Waiting, wait reason 5 Suspended)."""
    ntqsi = ctypes.windll.ntdll.NtQuerySystemInformation
    buf = ctypes.create_string_buffer(1 << 22)
    ret = ctypes.c_ulong(0)
    if ntqsi(5, buf, len(buf), ctypes.byref(ret)) != 0:
        return -1
    raw = buf.raw
    off = 0
    while True:
        nxt = int.from_bytes(raw[off:off + 4], "little")
        nth = int.from_bytes(raw[off + 4:off + 8], "little")
        upid = int.from_bytes(raw[off + 0x50:off + 0x58], "little")
        if upid == pid:
            n = 0
            for i in range(nth):
                th = off + 0x100 + i * 0x50
                state = int.from_bytes(raw[th + 0x44:th + 0x48], "little")
                wr = int.from_bytes(raw[th + 0x48:th + 0x4C], "little")
                n += 1 if (state == 5 and wr == 5) else 0
            return n
        if not nxt:
            return -1
        off += nxt

t = subprocess.Popen([TARGET, "--seconds", "120", "--quiet"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                     encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
secret = None
t0 = time.time()
while secret is None and time.time() - t0 < 10:
    l = t.stdout.readline()
    m = re.search(r"g_secret=([0-9A-Fa-f]+)", l or "")
    if m:
        secret = int(m.group(1), 16)
if secret is None:
    print("ABORT: no bait line from the target")
    t.kill()
    sys.exit(1)
threading.Thread(target=lambda: [None for _ in t.stdout], daemon=True).start()

p = subprocess.Popen([BIN + r"\headless.exe"], cwd=BIN, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace", bufsize=1)
lines = queue.Queue()
log = []
def pump():
    for l in p.stdout:
        lines.put(l.rstrip("\n"))
threading.Thread(target=pump, daemon=True).start()

def drain(seconds):
    end = time.time() + seconds
    while time.time() < end:
        try:
            l = lines.get(timeout=0.1)
            log.append(l)
            print("  | " + l)
        except queue.Empty:
            pass

def send(cmd, wait):
    print(f"> {cmd}")
    mark = len(log)
    p.stdin.write(cmd + "\n")
    p.stdin.flush()
    drain(wait)
    return "\n".join(log[mark:])

def value(tag, wait=1.5):
    out = send(f'log "{tag}={{x:[{secret:X}]}}"', wait)
    m = re.search(tag + r"=([0-9A-Fa-f]+)", out)
    return int(m.group(1), 16) if m else None

def pause_cycle(tag):
    """pause, read the target's value twice (1 s apart), count suspended threads, run, read again"""
    out = send("pause", 4)
    v1 = value(tag + "1")
    susp = suspended_threads(t.pid)
    time.sleep(1.0)
    v2 = value(tag + "2")
    rip = send(f'log "{tag}rip={{x:cip}}"', 1)
    ran = send("run", 2)
    time.sleep(1.0)
    v3 = value(tag + "3")
    m = re.search(tag + r"rip=([0-9A-Fa-f]+)", rip)
    return out, v1, v2, v3, susp, (int(m.group(1), 16) if m else 0)

drain(6)
send("hvmode on", 2)
if "HV Mode is ON" not in "\n".join(log[-5:]):
    print("ABORT: x64dbg did not confirm HV Mode ON -- not attaching")
    p.kill(); t.kill()
    sys.exit(1)
send("hvwindows off", 1)
send(f"attach {t.pid:X}", 8)

off_out, o1, o2, o3, osusp, orip = pause_cycle("off")
freeze = "freezes every thread" in off_out
off_alloc = send("alloc 1000", 2)
off_alloc_result = send('log "allocoff={x:$result}"', 1)

send("hvwindows on", 1)
on_out, n1, n2, n3, nsusp, nrip = pause_cycle("on")
on_alloc = send("alloc 1000", 2)
alloc_out = send('log "allocon={x:$result}"', 1)
m = re.search(r"allocon=([0-9A-Fa-f]+)", alloc_out)
allocated = int(m.group(1), 16) if m else 0
if allocated:
    send(f"free {allocated:X}", 2)

send("hvwindows off", 1)
restored = send("hvwindows", 1)
send("detach", 4)
send("exit", 3)
try:
    p.wait(timeout=15)
except subprocess.TimeoutExpired:
    p.kill()
t.kill()

text = "\n".join(log)
print(f"  info image has the freeze: {freeze}; OFF {o1}->{o2} then {o3} (suspended {osusp}); ON {n1}->{n2} then {n3} "
      f"(suspended {nsusp}); alloc {allocated:X}")
checks = [("attached through the hypervisor", "Process Started:" in text)]
if freeze:
    checks += [
        ("OFF: Pause -> the hypervisor's freeze, x64dbg paused", "paused!" in off_out),
        ("OFF: ...the target's own writes stopped", o1 is not None and o1 == o2),
        ("OFF: ...no thread suspended the Windows way (invisible)", osusp == 0),
        ("OFF: ...the paused thread's RIP (its snapshot or trap frame)", orip != 0),
        ("OFF: Run -> the target runs again", o2 is not None and o3 is not None and o3 != o2),
        ("ON: Pause still the freeze (preferred), paused, writes stopped, nothing suspended",
         "freezes every thread" in on_out and "paused!" in on_out and n1 == n2 and nsusp == 0),
        ("ON: Run -> runs again", n2 is not None and n3 is not None and n3 != n2),
    ]
else:
    checks += [
        ("OFF: Pause is refused (an image before rev151 has no freeze)", "paused!" not in off_out and "Pause needs" in off_out),
        ("ON: Pause -> frozen through Windows, x64dbg paused", "paused!" in on_out and "did through Windows" in on_out),
        ("ON: ...the target's own writes stopped", n1 is not None and n1 == n2),
        ("ON: Run -> the target runs again", n2 is not None and n3 is not None and n3 != n2),
    ]
checks += [
    ("OFF: alloc is refused", "allocate memory in the target" in off_alloc and re.search(r"allocoff=0\b", off_alloc_result) is not None),
    ("ON: alloc through Windows returns memory (logged)", allocated != 0 and "did through Windows" in on_alloc),
    ("the switch is put back OFF", "Allow visible Windows actions (HV Mode): OFF" in restored),
]
fail = 0
for what, ok in checks:
    print(("  ok   " if ok else "  FAIL ") + what)
    fail += not ok
print("x64dbg pause/hvwindows: " + ("PASS" if not fail else f"FAIL ({fail})"))
sys.exit(1 if fail else 0)
