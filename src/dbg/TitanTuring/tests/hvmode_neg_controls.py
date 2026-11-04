# Negative controls for hvmode_test: each mutation breaks one property of HV Mode; the live test must NOT pass.
# Sequential: mutate -> build TitanTuring.dll -> run test (timeout) -> restore (retry + md5 verify). Never two at once.
import hashlib, os, subprocess, sys, time

ROOT = r"C:\projs\x64dbg-turing"
SRC = ROOT + r"\src\dbg\TitanTuring" + "\\"
TEST = r"C:\Users\hayk\AppData\Local\Temp\claude\c--projs-turing-hv\a5b106da-f6e8-40b1-87c5-a320ff1e02ce\scratchpad\tt\hvmode_test.exe"
DLL = ROOT + r"\bin\x64\TitanTuring.dll"

MUTATIONS = [
    ("guard allows every pid", "hvguard.cpp",
     "    bool allowedPid(DWORD pid) { return pid == g_self; }",
     "    bool allowedPid(DWORD pid) { (void)pid; return true; }"),
    ("thread open skips the owner check", "hvguard.cpp",
     "            if(!allowedPid(owner))\n            {\n                record(TT_REFUSE_OPEN_THREAD",
     "            if(false && !allowedPid(owner))\n            {\n                record(TT_REFUSE_OPEN_THREAD"),
    ("ntdll never actually patched", "hvguard.cpp",
     "            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(t), LONG64(v));",
     "            (void)v;"),
    ("HV Mode never switched on", "shim.cpp",
     "    hvguard::SetActive(true);\n    return true;",
     "    return true;"),
    ("region map loses image classification", "shim.cpp",
     "            mbi->Type = MEM_IMAGE;",
     "            mbi->Type = MEM_PRIVATE;"),
    ("terminate refused silently (no report)", "shim.cpp",
     '        REFUSE(phPid(h), "terminate the target (the debugger never kills it; Stop detaches)");',
     "        SetLastError(ERROR_ACCESS_DENIED);"),
    ("attach without the guard allowed", "TitanTuring.cpp",
     "        if(!hvguard::Active())\n        {\n            g_lastMsg = \"turing-hv: HV Mode's guard",
     "        if(false && !hvguard::Active())\n        {\n            g_lastMsg = \"turing-hv: HV Mode's guard"),
]

def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()

def build():
    r = subprocess.run(["cmake", "--build", ROOT + r"\build64", "--config", "Release", "--target", "TitanTuring"],
                       capture_output=True, text=True)
    ok = r.returncode == 0 and "error" not in r.stdout.lower().replace("0 error", "")
    return r.returncode == 0, r.stdout[-600:]

def explorer_pid():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
    return out.strip().splitlines()[0].split('","')[1]

def run_test(timeout=90):
    try:
        r = subprocess.run([TEST, DLL, explorer_pid()], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired as e:
        subprocess.run(["taskkill", "/F", "/IM", "hvmode_test.exe"], capture_output=True)
        return "TIMEOUT", (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")

def restore(path, original, want):
    for attempt in range(6):
        try:
            open(path, "wb").write(original)
            if md5(path) == want:
                return True
        except OSError:
            pass
        time.sleep(0.5 * (attempt + 1))
    return False

ONLY = sys.argv[1] if len(sys.argv) > 1 else None   # run just the controls whose name contains this
results = []
for name, f, old, new in MUTATIONS:
    if ONLY and ONLY not in name:
        continue
    path = SRC + f
    original = open(path, "rb").read()
    want = hashlib.md5(original).hexdigest()
    text = original.decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    o, n = old.replace("\n", nl), new.replace("\n", nl)
    if text.count(o) != 1:
        print(f"[{name}] ANCHOR NOT FOUND ({text.count(o)}) -- control invalid")
        results.append((name, "INVALID"))
        continue
    try:
        open(path, "wb").write(text.replace(o, n).encode("utf-8"))
        built, log = build()
        if not built:
            print(f"[{name}] mutant did not build:\n{log}")
            results.append((name, "NOBUILD"))
            continue
        code, out = run_test()
        caught = code != 0
        fails = [l for l in out.splitlines() if "FAIL" in l][:4]
        print(f"[{name}] test exit {code} -> {'CAUGHT' if caught else 'NOT CAUGHT'}")
        for l in fails:
            print("      " + l.strip())
        results.append((name, "CAUGHT" if caught else "MISSED"))
    finally:
        if not restore(path, original, want):
            print(f"!!! RESTORE FAILED for {path} -- fix by hand (want md5 {want})")
            sys.exit(3)
        print(f"      restored {f} md5 {md5(path)} (want {want})")

built, log = build()
code, out = run_test()
print(f"clean rebuild: built={built}, test exit {code} ({'PASS' if code == 0 else 'FAIL'})")
print("summary:", results)
sys.exit(0 if code == 0 and all(r == "CAUGHT" for _, r in results) else 1)
