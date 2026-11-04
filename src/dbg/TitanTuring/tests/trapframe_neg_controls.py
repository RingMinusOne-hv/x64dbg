# Negative controls for the trap-frame registers (TitanTuring.cpp trapContext): each mutation must make
# titanturing_harness FAIL. Sequential; restore with retry + md5 verify.
import hashlib, os, subprocess, sys, time

ROOT = r"C:\projs\x64dbg-turing"
SRC = ROOT + r"\src\dbg\TitanTuring\TitanTuring.cpp"
HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ.get("TEMP", "."), "titanturing_harness.exe")
DLL = ROOT + r"\bin\x64\TitanTuring.dll"
MUTATIONS = [
    # the two frame locations are redundant (measured: each alone finds the same threads), so break both
    ("both frame locations 8 bytes off", [("trapFrameAt(initial - 0x190, c)", "trapFrameAt(initial - 0x198, c)"),
                                         ("trapFrameAt(frame, c)", "trapFrameAt(frame - 8, c)")]),
    ("self-validation skipped + RIP from the wrong field",
     [("        if(!readT(rip - 2, site, 2) || site[0] != 0x0F || site[1] != 0x05) return false;\n        c.rip = rip;",
       "        (void)site;\n        c.rip = q(0x160);")]),
]

def md5(b): return hashlib.md5(b).hexdigest()
def build():
    r = subprocess.run(["cmake", "--build", ROOT + r"\build64", "--config", "Release", "--target", "TitanTuring"], capture_output=True, text=True)
    return r.returncode == 0
def pid():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
    return out.strip().splitlines()[0].split('","')[1]
def run():
    try:
        r = subprocess.run([HARNESS, DLL, pid()], capture_output=True, text=True, timeout=180)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""

original = open(SRC, "rb").read()
want = md5(original)
text = original.decode("utf-8")
nl = "\r\n" if "\r\n" in text else "\n"
results = []
for name, edits in MUTATIONS:
    mutated = text
    bad = False
    for old, new in edits:
        o, n = old.replace("\n", nl), new.replace("\n", nl)
        if mutated.count(o) != 1:
            bad = True
            break
        mutated = mutated.replace(o, n)
    if bad:
        print(f"[{name}] INVALID anchor"); results.append("INVALID"); continue
    try:
        open(SRC, "wb").write(mutated.encode("utf-8"))
        if not build():
            print(f"[{name}] NOBUILD"); results.append("NOBUILD"); continue
        code, out = run()
        line = next((l for l in out.splitlines() if "trap frame" in l), "")
        print(f"[{name}] harness exit {code} -> {'CAUGHT' if code != 0 else 'MISSED'}   {line.strip()}")
        results.append("CAUGHT" if code != 0 else "MISSED")
    finally:
        for i in range(6):
            open(SRC, "wb").write(original)
            if md5(open(SRC, "rb").read()) == want: break
            time.sleep(0.5 * (i + 1))
        else:
            print("!!! RESTORE FAILED"); sys.exit(3)
        print(f"      restored, md5 {want}")
build()
code, _ = run()
print(f"clean rebuild: harness exit {code} ({'PASS' if code == 0 else 'FAIL'})")
sys.exit(0 if code == 0 and all(r == "CAUGHT" for r in results) else 1)
