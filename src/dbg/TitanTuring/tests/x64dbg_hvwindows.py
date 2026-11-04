# 2026-11-04: HV Mode's "allow visible Windows actions" switch (hvwindows / [Engine] HvAllowWindows, default OFF),
# driven through the REAL x64dbg (headless.exe) against antidebug-lab's adbg_target.
#   OFF: Pause and allocation are refused (nothing touches the target the Windows way).
#   ON:  Pause freezes the target through Windows and x64dbg shows it paused (the target's own writes stop), Run
#        resumes it (they go on), alloc gets memory through Windows; each is logged as done through Windows.
# The switch is put back OFF at the end (a switch a test flips must not persist) -- and checked.
import subprocess, sys, threading, time, queue, re

BIN = r"C:\projs\x64dbg-turing\bin\x64"
TARGET = r"C:\projs\antidebug-lab\target\adbg_target.exe"

t = subprocess.Popen([TARGET, "--seconds", "90", "--quiet"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
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

drain(6)
send("hvmode on", 2)
if "HV Mode is ON" not in "\n".join(log[-5:]):
    print("ABORT: x64dbg did not confirm HV Mode ON -- not attaching")
    p.kill(); t.kill()
    sys.exit(1)
send("hvwindows off", 1)
send(f"attach {t.pid:X}", 8)

off_pause = send("pause", 2)
off_alloc = send("alloc 1000", 2)
off_alloc_result = send('log "allocoff={x:$result}"', 1)

send("hvwindows on", 1)
on_pause = send("pause", 4)
v1 = value("frozen1")
time.sleep(1.0)
v2 = value("frozen2")
rip = send('log "pausedrip={x:cip}"', 1)
on_run = send("run", 2)
time.sleep(1.0)
v3 = value("running")
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
m = re.search(r"pausedrip=([0-9A-Fa-f]+)", rip)
checks = [
    ("attached through the hypervisor", "Process Started:" in text),
    ("OFF: Pause is refused (it would freeze the target through Windows)", "Pause freezes the target through Windows" in off_pause and "paused!" not in off_pause),
    ("OFF: alloc is refused", "allocate memory in the target" in off_alloc and re.search(r"allocoff=0\b", off_alloc_result) is not None),
    ("ON: Pause -> x64dbg paused", "paused!" in on_pause),
    ("ON: ...logged as done through Windows", "did through Windows" in on_pause and "pause the target" in on_pause),
    ("ON: ...the target's own writes stopped while paused", v1 is not None and v1 == v2, ),
    ("ON: ...the paused thread's RIP from Windows", m is not None and int(m.group(1), 16) != 0),
    ("ON: Run -> the target runs again (its writes go on)", v2 is not None and v3 is not None and v3 != v2),
    ("ON: alloc through Windows returns memory", allocated != 0),
    ("the switch is put back OFF", "Allow visible Windows actions (HV Mode): OFF" in restored),
]
print(f"  info frozen {v1} -> {v2}, running {v3}, alloc {allocated:X}")
fail = 0
for what, ok in checks:
    print(("  ok   " if ok else "  FAIL ") + what)
    fail += not ok
print("x64dbg hvwindows: " + ("PASS" if not fail else f"FAIL ({fail})"))
sys.exit(1 if fail else 0)
