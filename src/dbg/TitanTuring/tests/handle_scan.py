# The anti-cheat's view: scan the SYSTEM HANDLE TABLE for any handle x64dbg.exe holds on the target's process or any of
# its threads, while x64dbg is attached in HV Mode. Positive control: this scanner itself opens the target (and its
# threads) and must find ITS OWN handles in the same scan -- proving the scan sees such handles at all.
#   python handle_scan.py <x64dbg pid> <target pid>
import ctypes, ctypes.wintypes as wt, sys

ntdll = ctypes.WinDLL("ntdll")
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenThread.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE

class ENTRY(ctypes.Structure):
    _fields_ = [("Object", ctypes.c_void_p), ("UniqueProcessId", ctypes.c_size_t), ("HandleValue", ctypes.c_size_t),
                ("GrantedAccess", wt.ULONG), ("CreatorBackTraceIndex", wt.USHORT), ("ObjectTypeIndex", wt.USHORT),
                ("HandleAttributes", wt.ULONG), ("Reserved", wt.ULONG)]

def handles():
    size = 1 << 24
    while True:
        buf = ctypes.create_string_buffer(size)
        need = wt.ULONG(0)
        st = ntdll.NtQuerySystemInformation(64, buf, size, ctypes.byref(need)) & 0xFFFFFFFF  # SystemExtendedHandleInformation
        if st == 0xC0000004:
            size = max(size * 2, need.value + 0x100000)
            continue
        if st != 0:
            raise OSError(f"NtQuerySystemInformation: {st:#x}")
        n = ctypes.c_size_t.from_buffer(buf, 0).value
        return (ENTRY * n).from_buffer(buf, 16)

class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD), ("th32OwnerProcessID", wt.DWORD),
                ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG), ("dwFlags", wt.DWORD)]

dbg, target = int(sys.argv[1]), int(sys.argv[2])
me = k32.GetCurrentProcessId()
# our own handles on the target: its process + every thread (query-limited)
hp = k32.OpenProcess(0x1000, False, target)
threads = []
snap = k32.CreateToolhelp32Snapshot(0x4, 0)
te = THREADENTRY32()
te.dwSize = ctypes.sizeof(te)
ok = k32.Thread32First(snap, ctypes.byref(te))
while ok:
    if te.th32OwnerProcessID == target:
        h = k32.OpenThread(0x800, False, te.th32ThreadID)
        if h:
            threads.append(h)
    ok = k32.Thread32Next(snap, ctypes.byref(te))
k32.CloseHandle(snap)
mine = {int(h) for h in [hp] + threads if h}

table = handles()
objects = {}       # object address -> what it is (from OUR handles)
for e in table:
    if e.UniqueProcessId == me and e.HandleValue in mine and e.Object:
        objects[e.Object] = "process" if e.HandleValue == int(hp) else "thread"
dbg_hits = [e for e in table if e.UniqueProcessId == dbg and e.Object in objects]
print(f"system handles scanned: {len(table)}; our handles on the target found in the table: {len(objects)} "
      f"(1 process + {len(objects) - 1} threads; opened {1 + len(threads)})")
print(f"x64dbg.exe (pid {dbg}) handles in the table: {sum(1 for e in table if e.UniqueProcessId == dbg)}")
for e in dbg_hits:
    print(f"  x64dbg holds handle {e.HandleValue:#x} on the target's {objects[e.Object]} (access {e.GrantedAccess:#x})")
control = len(objects) == 1 + len(threads) and len(objects) > 1
print(("  ok   " if control else "  FAIL ") + "control: the scan finds the scanner's own handles on the target")
print(("  ok   " if not dbg_hits else "  FAIL ") + "x64dbg.exe holds NO handle on the target's process or any of its threads")
for h in [hp] + threads:
    k32.CloseHandle(h)
sys.exit(0 if control and not dbg_hits else 1)
