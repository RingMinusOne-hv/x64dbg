# Drive the REAL x64dbg (headless.exe + x64dbg.dll) in HV Mode against explorer.exe: attach through the hypervisor,
# read memory, walk the map, detach. Fails if x64dbg is not in HV Mode, if the attach fails, or if ANY HV Mode refusal
# shows up during an ordinary attach (each one = an x64dbg path that tried to open the target and needs routing).
import subprocess, sys, threading, time, queue

BIN = r"C:\projs\x64dbg-turing\bin\x64"

def explorer_pid():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
    return int(out.strip().splitlines()[0].split('","')[1])

pid = explorer_pid()
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
    p.stdin.write(cmd + "\n")
    p.stdin.flush()
    drain(wait)

drain(6)                                    # init (HV Mode banner expected)
send("hvmode on", 2)                        # never attach unless HV Mode is confirmed ON right now
if "HV Mode is ON" not in "\n".join(log[-5:]):
    print("ABORT: x64dbg did not confirm HV Mode ON -- not attaching (it would be the Windows debugger)")
    p.kill()
    sys.exit(1)
send(f"attach {pid:X}", 8)
send('log "MZ word at main module = {x:[mod.main()]&0xFFFF}"', 2)
send('log "PEB = {x:peb()}"', 2)
send("detach", 4)
send("exit", 3)
try:
    p.wait(timeout=15)
except subprocess.TimeoutExpired:
    p.kill()

text = "\n".join(log)
checks = [
    ("x64dbg started in HV Mode (startup banner)", any("HV Mode is ON" in l for l in log[:5])),
    ("attached through the hypervisor (x64dbg reports Process Started with the exe path)", "Process Started:" in text and "explorer.exe" in text.lower()),
    ("memory read through x64dbg: MZ = 5a4d", "MZ WORD AT MAIN MODULE = 5A4D" in text.upper()),
    ("x64dbg memory map splits every module into its sections (no Error replacing page)", "Error replacing page" not in text),
    ("detached", "Detached!" in text),
    # HV Mode never opens the target's files: images come from its memory, PDBs only from x64dbg's own symbol cache
    ("modules loaded from the target's memory through the hypervisor", "loaded from process memory through the hypervisor" in text),
    ("no module loaded from the target's files on disk", "loaded from disk path" not in text),
    ("every PDB probe stays inside x64dbg's own symbols folder",
     all("\\symbols\\" in l.split("Skipping non-existent PDB:", 1)[1] for l in log if "Skipping non-existent PDB:" in l)),
    ("no HV Mode refusal during an ordinary attach/read/detach", "[HV Mode] HV Mode refused" not in text),
]
fail = 0
for what, ok in checks:
    print(("  ok   " if ok else "  FAIL ") + what)
    fail += not ok
print("x64dbg headless HV: " + ("PASS" if not fail else f"FAIL ({fail})"))
sys.exit(1 if fail else 0)
