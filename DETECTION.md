# Detection-vector audit: what our debugging leaves behind, and how to keep it clean

The rule: we don't do active anti-anti-debug (no lying to `NtQueryInformationProcess`, no PEB/KUSD spoofing). Instead
the debugger must **introduce no detectable trace of its own**. This file audits every mechanism for what a process or
a kernel driver (anti-cheat) could observe, and the implementation rules that keep each clean. It is a living contract:
every new HV feature for the x64dbg port gets a row here before it ships.

## A. Classic debugger vectors we AVOID by construction

Because we are **not** a Windows debugger, none of these exist -- there is nothing to spoof:

- No debug port: `NtQueryInformationProcess(ProcessDebugPort / ProcessDebugObjectHandle / ProcessDebugFlags)` all read
  "not debugged". No debug object handle anywhere.
- `PEB.BeingDebugged`, `PEB.NtGlobalFlag`, heap `Flags`/`ForceFlags`: untouched, because nothing set them.
- No `int3` (`0xCC`) is ever written into the target's real code pages (breakpoints live in NX traps or shadow copies).
  A code-integrity scan that **reads** the code sees the original bytes.
- No debug registers: DR0-3 and DR7 are never programmed for breakpoints; `NtGetContextThread` shows them clean.
- The guest's own page tables are never modified: a guest PTE walk sees normal R/W/X; the NX / split-view state lives
  only in our NPT, which the guest cannot read.
- `KUSER_SHARED_DATA.KdDebuggerEnabled`, `NtSystemDebugControl`, kernel-debugger-presence: unaffected (no kernel debug).
- No `ThreadHideFromDebugger`, no `DBG_PRINTEXCEPTION`, no first-chance debug-string plumbing.

## B. Vectors we DO introduce, and the rules that contain them

### B1. Timing (the unavoidable one)
Our breakpoints and watches work by taking VM exits, so an armed region runs slower, and a stopped thread runs not at
all. Anything that times itself (`RDTSC`, `QueryPerformanceCounter`, a frame-time watchdog, a server heartbeat) can in
principle see it.
- **Parking** makes the breakpoint's whole 4 KiB page non-executable, so *every* instruction on it single-steps while
  armed -- a large, obvious slowdown. Rule: **do not leave a parking breakpoint armed on hot code**; use it to stop,
  not to sit. For a leave-armed breakpoint, prefer the **shadow page** (B4), where only the breakpoint instruction
  traps and the rest of the page runs native speed.
- **Data watch** costs ~2 exits per access to the watched page. Rule: keep it on cold data; it already self-throttles.
- A **frozen thread** makes no progress and **spins its core** (it re-faults in place), so `GetThreadTimes` /
  `QueryThreadCycleTime` show it burning cycles at one RIP, and a peer/watchdog thread sees it stalled. This is
  inherent to stopping a thread invisibly; there is no "quiet sleep" without the guest's cooperation. Rule: when you
  only need the state, use **snapshot-and-continue** (no stop) instead of freeze. Freeze is for when you accept the
  thread visibly stops.
- **Mass-park / whole-process pause** stalls every thread: heartbeats and server-side timeouts **will** fire. Rule:
  it is a deliberate "pause the game" action; expect the game/server to notice, exactly like any debugger pause.
- There is no way to make a *stopping* breakpoint invisible to a timer wrapped tightly around it. We minimize, we do
  not claim to defeat timing checks.

### B2. Guest CPU state must come back byte-exact on every guest-visible exit
The single step uses RFLAGS.TF; the shadow/park use NX faults. None of that may ever be visible in guest-readable
state. Implementation rules (already honored by rev149; re-check for every change):
- **RFLAGS.TF**: set only across one internal step, cleared before any guest-visible point; never stepped across an
  instruction that reads it (PUSHF/POPF/IRET/INT are "nostep" -> LOOSE, not single-stepped).
- **DR6** runs on a clean value during a step and the guest's DR6 is restored exactly (the rev146 live-leak fix);
  **DR7** is never touched. The single step's BS bit never reaches the guest.
- **RF (resume flag)** and the pending-#DB state must not leak from a step.
- On an exit **into L1 / the guest's own handler**, the let-through ends first so VMCB12 never carries TF, the held
  V_IRQ, or the step's DR6.
- A register **edit** (SETREG/SETRIP) is applied to the live VMCB so the thread simply continues with the new value --
  no shadow copy the guest could read a mismatch from.

### B3. Guest exception intercept (gap 1) -- fidelity is the whole game
When the HV intercepts `#BP/#PF/#UD/#GP` it must be invisible for anything that is not ours:
- An exception that is **not** our breakpoint is reflected to the guest **byte-exact**: same vector, error code, CR2
  (for #PF), faulting frame, and first-/second-chance ordering. A mis-reflected or delayed exception is both a bug and
  a detection vector (a routine that deliberately faults and times/validates the delivery -- a common anti-debug
  trick -- would notice).
- Intercept **only** the vectors a feature needs, and only while it needs them: a globally-hooked #PF would slow every
  page fault in the guest. Off by default, per-vector, scoped to the armed breakpoints.
- Our #BP (the shadow trap) is consumed and never delivered to the guest; a #BP the guest itself planted is reflected.

### B4. Shadow code page (gap 4) -- AMD has no execute-only pages, so the views swap per vCPU
AMD NPT cannot make a page executable but unreadable (FEATURE-MAP 11.1), so the shadow is mapped only while a vCPU is
executing on the page (hook-active) and the clean page otherwise (resting). The rules that keep it clean:
- **Resting must be the only view any vCPU has while executing elsewhere.** A vCPU left in hook-active after
  execution leaves P would let code on other pages -- where integrity checks run -- read `0xCC`. Rule: hook-active makes
  every other page NX, so leaving P always exits and swaps back; prove it with a test (a read of the target byte from
  another page returns the clean byte).
- **Each view is its own ASID**, so a swap never leaves a stale translation of the other view in the TLB.
- **Residual, stated:** while executing *on P itself*, a read of the exact target byte returns `0xCC` (the same limit
  SimpleSvmHook documents). Every other byte of P reads correctly. For self-checking code use the **Chain** trigger
  (nothing modified anywhere).
- **Entering and leaving P each cost one exit** (B1). On a page that is entered and left very often (a hot call into
  a short function on P) this is visible as timing; the hit counters show it, and the Chain trigger or a different
  target is the alternative. Never resolved by leaving the shadow mapped.
- **Self-modifying code**: P is read-only in every view; a write is applied to the clean page and the shadow re-synced
  before any vCPU fetches it again, so execution matches the real code and the write is never lost or doubled.
- **The guest must never receive a `#BP` it didn't plant**: the `#BP` intercept is re-applied at every L2 entry while
  hook-active; hits from other address spaces are stepped past silently; only a `0xCC` that was in the original code is
  reflected.
- **Branch records (LBR)**: a guest reading AMD LBR could in theory see a branch into our trap. Not checked by game
  anti-cheat in practice; noted as a residual, exotic vector.
- NPT A/D bits are ours (the guest can't read them); the guest's own page-table A/D bits are set by its MMU on its own
  tables and are unaffected -- no A/D anomaly.

### B6. x64dbg's own direct Windows calls (found 2026-11-02) -- every one routed or refused
Stock x64dbg opens handles and pokes the target outside TitanEngine. Left alone, these would be the loudest traces of
all, so the port intercepts each (PORT-TURINGHV.md "Two layers"):
- **Handle opens** (`OpenProcess`, `OpenThread`, `DuplicateHandle`): an anti-cheat driver sees every handle opened on
  its process through `ObRegisterCallbacks` -- the standard way they spot debuggers. Rule: **no real handle to the game
  is ever opened**; TitanTuring hands x64dbg pseudo-handles that name a pid / tid and are resolved in the hypervisor.
- **Thread injection** (`DebugBreakProcess` for "Pause", `CreateRemoteThread`): a new thread in the game, visible to
  thread-creation callbacks. Rule: never; "Pause" stops at the next breakpoint (P0) or mass-parks (gap 3).
- **Suspend counts** (`SuspendThread` / `ResumeThread`): observable through `NtQueryInformationThread` and kernel
  state. Rule: never call them on the game; a stopped thread is held by the HV, its suspend count never changes.
- **Remote allocation / protection / termination** (`VirtualAllocEx`, `VirtualProtectEx`, `VirtualFreeEx`,
  `TerminateThread`, `TerminateProcess`): visible kernel actions. Rule: refused with a message (the user-visible
  Windows fallback stays off).
- As built: x64dbg.dll's import-table entries for these names point at TitanTuring's shim (PORT-TURINGHV.md). Live
  test `hvmode_test.cpp` (PASS): each refused operation returns failure AND is reported; the target is checked still
  running afterwards (TerminateProcess really was refused).

### B7. HV Mode's guard (built 2026-11-02) -- no handle, from anything in x64dbg's process
The shim covers x64dbg.dll's own calls; the guard covers **everything else in the process** (GUI, plugins, dbghelp,
Qt, a future x64dbg feature nobody routed): the system calls that create a process/thread handle are refused inside
x64dbg.exe's own ntdll unless the handle is to x64dbg itself. A kernel driver watching handle creation
(`ObRegisterCallbacks`) and a user-mode scan of the system handle table therefore never see x64dbg holding anything on
the game -- or on any other process. Live-tested: opening the target, its threads, an unrelated process, and calling
`ntdll!NtOpenProcess` directly (no import table) are all refused; opening ourselves works.
What the guard does NOT cover (no handle involved -- listed so nothing is assumed):
- **Window messages.** x64dbg.dll's `PostThreadMessage` to another process's thread is refused by the shim (stock pause
  posts `WM_NULL`); pause itself is refused in HV Mode. Other modules' `PostMessage`/`SendMessage` to the game's windows
  aren't gated (x64dbg doesn't send any). Reading another window's caption (`GetWindowText`) sends no message.
- **The game's files on disk -- closed in HV Mode (2026-11-02).** Stock x64dbg maps every module's EXE/DLL from disk
  and probes for `<name>.pdb` next to it, file opens a file-system filter can see. In HV Mode the debuggee's module
  images are read from its memory through the hypervisor (page by page; a page not resident reads as zeros, like a
  dump; no headers = not loaded), and PDBs are looked for only in x64dbg's own symbol cache. Test:
  `x64dbg_headless_hv.py` checks x64dbg's own log for "loaded from process memory through the hypervisor", no
  "loaded from disk path", and no PDB probe outside its symbols folder.
- **System-wide queries** (`NtQuerySystemInformation` process/handle lists, `SystemProcessIdInformation` for paths):
  the target can't observe who queries them.

### B5. Thread trap-frame read/write (gap 2)
- Read path: purely observational, no trace.
- Write path (set-context on a non-stopped thread): modifying a switched-out thread's saved context is only safe at a
  clean boundary; a half-applied or inconsistent context the thread or a watchdog could observe is a bug + a vector.
  Behind confirmation, read path ships first.

## C. Vectors OUTSIDE our mechanisms (so you're aware)

These are not traces our code introduces, but they exist as long as you run the tools, and hiding them would be the
active process-list spoofing we are deliberately **not** doing:

- **`x64dbg.exe` and `thvbridge.exe` are real processes in the guest.** A process-list scan by the game or its
  anti-cheat finds them by name/path/window. HyperHide hides these by filtering `NtQuerySystemInformation`; we do not.
  If this matters to you, the options are: run them under innocuous names/paths, or (if you later decide you want it)
  ask explicitly and we revisit -- it would be a deliberate, separate decision, not something the debugger does on its
  own.
- The bridge opens a session with the hypervisor (the caller gate). That is host/HV state the guest cannot see; it is
  not a guest-visible trace.
- **x64dbg.exe's own ntdll carries the guard's three patched stubs** (`NtOpenProcess`, `NtOpenThread`,
  `NtGetNextProcess` start with a `jmp`). Only someone reading x64dbg.exe's memory sees them -- which means opening
  x64dbg.exe (the guard stops x64dbg opening others, not others opening x64dbg). Nothing changes in the game.

## D. Implementation checklist (applied to every port feature)

- [ ] No `0xCC`, no DRx, no guest PTE edit, no PEB/KUSD/debug-object touch -- verified per feature.
- [ ] TF / DR6 / DR7 / BS / RF restored exact on every guest-visible exit (unit test: guest reads of these after a
      step/park/snapshot match the pre-debug values).
- [ ] Exceptions not ours reflected byte-exact (unit test: error code, CR2, first/second chance).
- [ ] Shadow view-swap flushes so reads never see the shadow (unit test: a read of a breakpointed page returns clean
      bytes while execution traps).
- [ ] The feature's timing cost is documented and scoped (armed only when needed; snapshot over freeze where possible).
- [ ] Negative controls: a mutation that *does* leave a trace (e.g. skips the DR6 restore, or exposes the shadow to a
      read) is caught by the suite.
