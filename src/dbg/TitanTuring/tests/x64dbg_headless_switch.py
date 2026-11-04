# Runtime HV Mode switch in the REAL x64dbg (headless): off -> the stock engine binds; on -> TitanTuring binds again
# and an attach through the hypervisor works. The stock engine is never used on a process here.
import subprocess, sys, threading, time, queue

BIN = r"C:\projs\x64dbg-turing\bin\x64"
out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
pid = int(out.strip().splitlines()[0].split('","')[1])
p = subprocess.Popen([BIN + r"\headless.exe"], cwd=BIN, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace", bufsize=1)
lines = queue.Queue()
log = []
threading.Thread(target=lambda: [lines.put(l.rstrip("\n")) for l in p.stdout], daemon=True).start()

def drain(seconds):
    end = time.time() + seconds
    while time.time() < end:
        try:
            l = lines.get(timeout=0.1)
            log.append(l)
            if "Thread " not in l and "[SYMBOL]" not in l:
                print("  | " + l)
        except queue.Empty:
            pass

def send(cmd, wait):
    print(f"> {cmd}")
    log.append(f"> {cmd}")
    p.stdin.write(cmd + "\n")
    p.stdin.flush()
    drain(wait)

drain(6)
send("hvmode off", 2)
send("hvmode", 1)
send("exit", 3)                  # leave this session with HV Mode OFF...
try:
    p.wait(timeout=15)
except subprocess.TimeoutExpired:
    p.kill()
# ...and the NEXT start must be in HV Mode again: the switch is per session, never the startup default
p = subprocess.Popen([BIN + r"\headless.exe"], cwd=BIN, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace", bufsize=1)
lines = queue.Queue()
threading.Thread(target=lambda: [lines.put(l.rstrip("\n")) for l in p.stdout], daemon=True).start()
log.append("--- second start ---")
drain(6)
second_start_on = any("HV Mode is ON" in l for l in log[log.index("--- second start ---"):][:6])
send("hvmode off", 2)
send("hvmode on", 3)
send("hvmode", 1)
send(f"attach {pid:X}", 8)
send('log "MZ after switching = {x:[mod.main()]&0xFFFF}"', 2)
send("hvmode off", 1)            # must be refused while debugging
send("detach", 4)
send("exit", 3)
try:
    p.wait(timeout=15)
except subprocess.TimeoutExpired:
    p.kill()

text = "\n".join(log)
def after(cmd):
    i = text.find("> " + cmd)
    return text[i:] if i >= 0 else ""
checks = [
    ("hvmode off -> the standard Windows debugger", "HV Mode is OFF: x64dbg is the standard Windows debugger" in text),
    ("hvmode reports OFF", "HV Mode is OFF. Usage" in text),
    ("the next x64dbg start is in HV Mode again (the switch never changes the startup default)", second_start_on),
    ("hvmode on -> HV Mode again", "HV Mode is ON: x64dbg debugs through the hypervisor and opens no other process" in text),
    ("attach after the switch goes through the hypervisor", "Process Started:" in text),
    ("memory read after the switch", "MZ AFTER SWITCHING = 5A4D" in text.upper()),
    ("hvmode off refused while debugging", "stop debugging first" in text),
    ("detached", "Detached!" in text),
    ("no HV Mode refusal", "[HV Mode] HV Mode refused" not in text),
]
fail = 0
for what, ok in checks:
    print(("  ok   " if ok else "  FAIL ") + what)
    fail += not ok
print("x64dbg headless HV switch: " + ("PASS" if not fail else f"FAIL ({fail})"))
sys.exit(1 if fail else 0)
