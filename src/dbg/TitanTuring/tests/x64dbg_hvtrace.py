# The hypervisor's NATIVE TRACE through the REAL x64dbg (headless.exe + x64dbg.dll, HV Mode) against antidebug-lab's
# adbg_target: `HvTrace hot_target, .300` and `HvTrace cold_target, .2000, 1` (step over). Each writes an x64dbg trace
# file; this test reads it back the way x64dbg's Trace tab does (TraceFileReader: header, then delta-coded register
# blocks) and checks what the hypervisor recorded: hot_target's first instructions with the right registers, no trap
# flag anywhere, the end at its PUSHF; the step-over trace never inside the callee. Then the target's own detectors.
import json, os, re, struct, subprocess, sys, threading, time, queue

BIN = r"C:\projs\x64dbg-turing\bin\x64"
TARGET = r"C:\projs\antidebug-lab\target\adbg_target.exe"
NWORDS = 172                       # REGDUMP words up to lastError on x64 (TraceRecord.h)
CIP, EFLAGS, CSP, CBP = 16, 17, 4, 5

def read_trace(path):
    """x64dbg's .trace64 -> [(cip, words, opcode)] as TraceFileReader reconstructs them."""
    data = open(path, "rb").read()
    assert data[:4] == b"TRAC", "no TRAC magic"
    hlen = struct.unpack_from("<I", data, 4)[0]
    hdr = json.loads(data[8:8 + hlen])
    off = 8 + hlen
    words = [0] * NWORDS
    out, full = [], 0
    while off < len(data):
        btype = data[off]; off += 1
        assert btype == 0, f"block type {btype}"
        changed, mem, flags = data[off], data[off + 1], data[off + 2]; off += 3
        if flags & 0x80:
            off += 4
        opsize = flags & 0x0F
        opcode = data[off:off + opsize]; off += opsize
        pos = data[off:off + changed]; off += changed
        vals = struct.unpack_from("<%dQ" % changed, data, off); off += 8 * changed
        last = -1
        for p, v in zip(pos, vals):
            last = last + p + 1
            assert 0 <= last < NWORDS, "position out of range"
            words[last] = v
        if changed == NWORDS:
            full += 1
        assert mem == 0, "memory operands recorded (the hypervisor records none)"
        out.append((words[CIP], list(words), bytes(opcode)))
    return hdr, out, full

tp = subprocess.Popen([TARGET, "--seconds", "90", "--out", os.path.join(os.environ["TEMP"], "hvtrace_adbg.txt")],
                      stdout=subprocess.PIPE, text=True)
hot = cold = None
for _ in range(50):
    l = tp.stdout.readline()
    m = re.search(r"hot_target=([0-9A-Fa-f]+) cold_target=([0-9A-Fa-f]+)", l)
    if m:
        hot, cold = int(m.group(1), 16), int(m.group(2), 16)
        break
threading.Thread(target=lambda: [None for _ in tp.stdout], daemon=True).start()
if not hot:
    tp.kill(); print("no bait line"); sys.exit(1)
print(f"adbg_target pid {tp.pid} hot {hot:X} cold {cold:X}")

p = subprocess.Popen([BIN + r"\headless.exe"], cwd=BIN, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace", bufsize=1)
lines, log = queue.Queue(), []
threading.Thread(target=lambda: [lines.put(l.rstrip("\n")) for l in p.stdout], daemon=True).start()

def drain(seconds, until=None):
    end = time.time() + seconds
    while time.time() < end:
        try:
            l = lines.get(timeout=0.1)
        except queue.Empty:
            continue
        log.append(l); print("  | " + l)
        if until and until in l:
            return l
    return None

def send(cmd, wait, until=None):
    print(f"> {cmd}")
    p.stdin.write(cmd + "\n"); p.stdin.flush()
    return drain(wait, until)

drain(6)
send("hvmode on", 2)
if "HV Mode is ON" not in "\n".join(log[-5:]):
    print("ABORT: x64dbg did not confirm HV Mode ON"); p.kill(); tp.kill(); sys.exit(1)
send(f"attach {tp.pid:X}", 8)

checks = []
def check(what, ok, detail=""):
    checks.append((what, ok)); print(("  ok   " if ok else "  FAIL ") + what + (f"  [{detail}]" if detail else ""))

def trace(cmd, attempts=4):
    """run one HvTrace; an interrupt can end a trace early (EVENT): try again a few times"""
    for _ in range(attempts):
        start = len(log)
        send(cmd, 2)
        w = next((l for l in log[start:] if "HvTrace: written to " in l), None) or drain(15, "HvTrace: written to ")
        summary = next((l for l in log[start:] if "instructions of thread" in l), "")
        if not w:
            return None, summary
        path = w.split("HvTrace: written to ", 1)[1].split(" (opened")[0].strip()
        if "interrupt was due" not in summary:
            return path, summary
    return path, summary

path, summary = trace(f"HvTrace {hot:X}, .300")
check("HvTrace hot_target wrote a trace file", bool(path) and os.path.exists(path), path or "")
if path and os.path.exists(path):
    hdr, recs, full = read_trace(path)
    check("the trace file's header is x64dbg's (ver 1, x64, murmurhash)", hdr.get("ver") == 1 and hdr.get("arch") == "x64" and hdr.get("hashAlgorithm") == "murmurhash", str(hdr)[:120])
    check("it starts with a full register dump (a reader page)", full >= 1, f"{full}")
    check("first instruction is hot_target (push rbp)", len(recs) > 2 and recs[0][0] == hot and recs[0][2][:1] == b"\x55", f"{recs[0][0]:X} {recs[0][2].hex()}" if recs else "")
    if len(recs) > 2:
        check("+1 mov rbp,rsp with RSP 8 lower", recs[1][0] == hot + 1 and recs[1][2] == bytes.fromhex("4889e5") and recs[1][1][CSP] == recs[0][1][CSP] - 8)
        check("+4 with RBP = RSP", recs[2][0] == hot + 4 and recs[2][1][CBP] == recs[2][1][CSP])
    check("no record shows the trap flag", all(not (r[1][EFLAGS] & 0x100) for r in recs))
    if "PUSHF" in summary:
        check("it ended AT the pushfq (the last record, recorded never stepped)", recs[-1][2][:1] == b"\x9c", recs[-1][2].hex())
    check("every record's opcode was read (sizes 1..15)", all(1 <= len(r[2]) <= 15 for r in recs))
    print(f"  {len(recs)} records; {summary}")

path2, summary2 = trace(f"HvTrace {cold:X}, .2000, 1")
check("HvTrace cold_target (step over) wrote a trace file", bool(path2) and os.path.exists(path2), path2 or "")
if path2 and os.path.exists(path2):
    _, recs2, _ = read_trace(path2)
    m = re.search(r"\((\d+) stepped", summary2)
    stepped = int(m.group(1)) if m else 0
    check("first instruction is cold_target", recs2 and recs2[0][0] == cold, f"{recs2[0][0]:X}" if recs2 else "")
    check("step over: nothing recorded inside hot_target's page", all((r[0] >> 12) != (hot >> 12) for r in recs2), f"{len(recs2)} records")
    check("step over: the callee was followed (more steps than records)", stepped > len(recs2), f"{stepped} > {len(recs2)}")

send("HvTraceStop", 1)          # nothing armed now: a clean refusal
send("detach", 4)
send("exit", 3)
try: p.wait(timeout=15)
except subprocess.TimeoutExpired: p.kill()
try: tp.wait(timeout=100)
except subprocess.TimeoutExpired: tp.kill()
verdict = open(os.path.join(os.environ["TEMP"], "hvtrace_adbg.txt")).read() if os.path.exists(os.path.join(os.environ["TEMP"], "hvtrace_adbg.txt")) else ""
m = re.search(r"SUMMARY DEBUGGER=(\d+) INTEGRITY=(\d+) TIMING=(\d+)", verdict)
check("the target finished and reported", bool(m))
if m:
    check("the target saw no debugger (DEBUGGER 0, INTEGRITY 0)", m.group(1) == "0" and m.group(2) == "0", m.group(0))
fail = sum(1 for _, ok in checks if not ok)
print("x64dbg HvTrace: " + ("PASS" if not fail else f"FAIL ({fail})"))
sys.exit(1 if fail else 0)
