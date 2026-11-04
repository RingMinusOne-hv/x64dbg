# Porting x64dbg onto turing-hv (invisible, hardware-backed debugging)

Goal: x64dbg debugs the game through the turing-hv hypervisor instead of the Windows debug API — no
`DebugActiveProcess`, no `int3` bytes in the game, no debug registers, nothing the guest can see. The same idea as
x64dbg's TitanHide / VM plugins, but the VM is our own hypervisor and the whole debug backend runs through
`turinghv.dll`.

## The seam: reimplement TitanEngine over turinghv

x64dbg's entire process-control layer is **TitanEngine** (`src/dbg/TitanEngine/TitanEngine.h`, shipped here as the
prebuilt `TitanEngine_x64.lib`). The debugger core (`src/dbg/debugger.cpp`, `breakpoint.cpp`, `memory.cpp`,
`thread.cpp`) calls ~37 TitanEngine functions; everything above that (disassembly, analysis, symbols, the GUI) is
engine-agnostic. So the port is: **a drop-in replacement lib, "TitanTuring", that implements `TitanEngine.h` over
`turinghv.dll`** — the 100k+ lines of x64dbg above it barely change. New dir: `src/dbg/TitanTuring/`.

The functions the core actually uses: `InitDebugW` / `AttachDebugger` / `StopDebug` / `DebugLoop`, `SetBPX` /
`DeleteBPX`, `SetMemoryBPXEx` / `RemoveMemoryBPX`, `SetHardwareBreakPoint` / `DeleteHardwareBreakPoint`, `StepInto` /
`StepOver`, `GetContextDataEx` / `SetContextDataEx` / `GetFullContextDataEx` / `SetFullContextDataEx` / AVX,
`MemoryReadSafe` / `MemoryWriteSafe`, `SuspendThread` / `ResumeThread`, `SetCustomHandler` (event callbacks), plus
`GetPEBLocation` / `GetTEBLocation` / `TitanOpenProcess` / `TitanOpenThread`.

## Feature -> turing-hv primitive

| x64dbg feature | Windows backend (TitanEngine) | turing-hv backend (this port) | status |
|---|---|---|---|
| Attach to the game | `DebugActiveProcess` | open the process through the backend (resolve CR3); no debug port | works (backend) |
| Read / write memory | `ReadProcessMemory` / `WriteProcessMemory` | `thv_read` / `thv_write` (no handle, invisible) | works |
| Software breakpoint (`int3`) | writes `0xCC` | **parking breakpoint** (rev149): NX code page, no byte changed | works |
| Execute hardware breakpoint | DR0-3 | **parking breakpoint** (rev149) | works, no DR |
| Memory / access / write breakpoint | guard page / DR | **data watch** (rev146b: what reads/writes) | works, no guard page |
| Step into / step over | trap flag | **concealed TF step** (rev149), step-over = return trap | works (within the bp's page) |
| Register view of the stopped thread | `GetThreadContext` | **capture snapshot** of the parked thread | works |
| Edit a register | `SetThreadContext` | break `SETREG` / `SETRIP` (rev149) | works (the parked thread) |
| Thread / module list | toolhelp / debug events | turing-hv thread / module enumeration (polled) | works |
| x87 / SSE (XMM, MXCSR) | context | the capture snapshot's FXSAVE | works |
| Run to cursor | one-shot bp | break `RUNTO` (rev149) | works (same page) |
| Run trace (Trace tab) | trap-flag stepping through debug events | **native trace** (rev150): `HvTrace` -> a `.trace64` | works; the thread never stops |

## What does NOT map without new hypervisor work (the gaps)

1. **Catching the game's exceptions** (access violations, divide-by-zero, an `int3` already in the game, first/second
   chance). x64dbg sees these through the Windows debug port; we have none. To get them the hypervisor must **intercept
   L2 (guest) exceptions** and report them on the control channel. This is the biggest gap and the one that makes
   "the game crashed, break on it" work. New HV feature; it changes guest exception timing slightly (still nothing the
   guest can *read*, but a heavy exception workload would slow). *Recommendation: add it, opt-in per vector (at least
   #PF / #UD / #GP / #BP), off by default.*

2. **The register context of a thread that is NOT stopped at a breakpoint.** x64dbg's "Threads" view shows every
   thread's CIP/registers when the process is paused. We can read a thread's registers only while it is parked. To fill
   the others the HV would **read a thread's saved kernel trap frame** (KTHREAD) when it is switched out. New HV feature
   (read-only). *Recommendation: add it — read-only, and it makes the thread view real; otherwise the view shows only
   the stopped thread.*

3. **Freeze the whole process** ("Pause" freezes every thread). We stop one thread. Freezing all = parking every thread
   (enumerate + hold each). Doable but heavy and it spins every core. *Recommendation: for v1, "pause" stops on the next
   breakpoint / stops the current thread; add mass-park later only if you want the classic freeze.*

4. **Debug from the entry point / TLS callbacks / DLL-load breakpoints.** These need create-with-debug and early
   control; we attach to an already-running game. *Recommendation: attach-only (x64dbg "attach", not "open exe"); not a
   limitation for live game work.*

5. **AVX/AVX-512 (YMM/ZMM).** The capture snapshot does XMM via FXSAVE only. *Recommendation: add an XSAVE path to the
   snapshot if you want YMM; low priority.*

Not planned (fundamentally a Windows-debugger thing or against the "nothing visible" rule): `int3` software bps, DR
hardware bps, conditional breakpoints evaluated in the HV. (Bulk tracing came after all, as the hypervisor's native
trace -- see "Native trace" below -- not as trap-flag stepping the debuggee could see.)

## The honest model this produces

A **thread-level, attach-only, invisible debugger**: when a breakpoint hits, *that thread* stops and you inspect/step
it while the rest of the game runs. Not a whole-process-freeze debugger (unless we add gap 3). This is the natural
shape of an invisible hypervisor debugger and is genuinely useful for game RE; it is not identical to stock x64dbg.

## Build reality

- The **engine** (`src/dbg` -> `x64dbg.dll` / `x32dbg.dll`) needs only MSVC — this is where the port lives, and it can
  be built and tested headless.
- The **GUI** (`src/gui`) needs **Qt5 (Widgets, WinExtras)**. Building the full app needs a Qt5 + MSVC toolchain set up
  on this machine. The port doesn't change the GUI.

## Two layers to port, not one (finding 2026-11-02)

1. **TitanEngine is a separate DLL** (`/DELAYLOAD:TitanEngine.dll`; `TitanEngine_x64.lib` is its import library).
   TitanTuring is therefore built as a **drop-in `TitanEngine.dll`** exporting the same 37 functions
   (`TitanEngine.def`): `MemoryReadSafe MemoryWriteSafe GetPEBLocation GetTEBLocation InitDebugW StopDebug SetBPXOptions
   IsBPXEnabled SetBPX DeleteBPX SetMemoryBPXEx RemoveMemoryBPX GetFullContextDataEx SetFullContextDataEx
   GetContextDataEx SetContextDataEx GetAVXContext SetAVXContext GetAVX512Context SetAVX512Context GetDebugData
   SetCustomHandler StepInto StepOver GetUnusedHardwareBreakPointRegister SetHardwareBreakPoint DeleteHardwareBreakPoint
   RemoveAllBreakPoints DebugLoop SetNextDbgContinueStatus AttachDebugger DetachDebuggerEx IsFileBeingDebugged
   TitanOpenProcess TitanOpenThread SetEngineVariable EngineCheckStructAlignment`.
2. **x64dbg's own core (`src/dbg`, -> `x64dbg.dll`) also calls Windows directly, bypassing TitanEngine**, in ~70
   places. Each must be routed to the hypervisor or refused, because several are detection vectors (DETECTION.md B6):

   | Win32 call in `src/dbg` | count | turing-hv route | P0 status |
   |---|---|---|---|
   | `OpenProcess` / `OpenThread` / `DuplicateHandle` | 1 / 2 / 4 | **pseudo-handles** owned by TitanTuring (pid / tid), no real handle is ever opened on the game | shim |
   | `ReadProcessMemory` | 2 | HV read | shim |
   | `VirtualQueryEx` | 7 | HV memory map (region enumeration) | shim |
   | `NtQueryInformationProcess` / `NtQueryInformationThread` | 6 / 3 | HV process / thread info (PEB, TEB, start address) | shim |
   | `CreateToolhelp32Snapshot` | 3 | HV thread / module enumeration | shim |
   | `GetThreadContext` | 4 | parked thread's snapshot; others need gap 2 | shim (stopped thread) |
   | `SuspendThread` / `ResumeThread` | 5 / 12 | parked thread: hold / release; other threads: gap 3 (P0: not suspended, they keep running) | shim |
   | `DebugBreakProcess` ("Pause") | 1 | P0: stop at the next breakpoint hit; gap 3 mass-park later. **Never** inject a thread | shim |
   | `CreateRemoteThread` | 1 | refused (would inject a thread) | refuse |
   | `VirtualAllocEx` / `VirtualFreeEx` / `VirtualProtectEx` | 1 / 2 / 1 | refused (the HV can't do it invisibly) | refuse |
   | `TerminateThread` / `TerminateProcess` | 3 / 1 | refused (visible kernel action) | refuse |

   **As built (2026-11-02): import-table routing, not a header.** At HV Mode entry, TitanTuring points the import-table
   entries of `x64dbg.dll` (and of `dbghelp.dll`, which reads memory for stack walks) for ~50 Win32/NT functions at
   its shim (`src/dbg/TitanTuring/shim.cpp`). A real handle goes to Windows unchanged; a pseudo-handle is answered by
   the hypervisor or refused. No call site in x64dbg changed, and nothing a header could miss (inlined helpers, psapi
   aliases like `K32GetModuleFileNameExW`) escapes, because the routing is at the binary's import table.

## HV Mode (built 2026-11-02)

x64dbg starts in **HV Mode** (setting `[Engine] HvMode`, default 1; command `hvmode [on|off]`, not while debugging).
The command switches **for that session only** -- it never changes the startup default (found 2026-11-02: a persisted
`hvmode off` from a test run made the next start the Windows debugger, silently; a game attach would have been a
Windows-debugger attach). `HvMode=0` in x64dbg.ini is the only way to start as the standard debugger, and then the
title says `[HV Mode OFF]`.

- **Engine:** x64dbg.dll delay-loads `TitanEngine.dll`; a delay-load hook (`src/dbg/hvmode.cpp`) hands it
  `TitanTuring.dll` in HV Mode and the stock engine otherwise. Switching unbinds the engine (`/DELAY:UNLOAD`) so the
  next call re-binds, then re-applies the engine settings.
- **The guard** (`src/dbg/TitanTuring/hvguard.cpp`): the handle-creating system calls (`NtOpenProcess`, `NtOpenThread`,
  `NtGetNextProcess`) are hooked inside **x64dbg.exe's own ntdll**, so no module in x64dbg's process (x64dbg.dll, the
  GUI, plugins, dbghelp, Qt) can get a handle to any other process or thread -- only to itself. Every read, debug
  attach, remote thread, suspend or allocation needs such a handle first, so none can happen. The stubs are verified
  byte-for-byte before patching (fail closed if anything else already patched them), patched with one atomic 8-byte
  store while our other threads are suspended, and the DLL pins itself.
- **Fail closed:** HV Mode on + guard not installable -> x64dbg refuses to start and names the cause; TitanTuring's
  `AttachDebugger` refuses unless the guard is active.
- **Reported, never silent, never blocking:** every refusal (guard or shim) goes to one queue; x64dbg logs each with
  the module that asked and the process it asked for, to the log window, the status bar and `<user dir>\hvmode.log`
  ("leave HV Mode to do this"). Not a modal box: one, raised by a background refusal, held up closing x64dbg. The one
  quiet refusal is suspending a running thread -- x64dbg does that internally every refresh to read registers (the
  call-stack panel); it is refused all the same, and the user's own suspend / resume / kill-thread commands explain.
- **The engine binds by setting, not by init order:** the GUI applies its settings (an engine call) before
  `DbgInit`, and the first engine call binds for good -- so the delay-load hook reads `HvMode` itself, the bridge
  preloads `TitanTuring.dll` instead of the stock engine, and init unbinds once more to be certain. Verified: the GUI
  process in HV Mode contains TitanTuring.dll and **no** stock TitanEngine.dll.
- **The attach list** is built without opening anything: the system process list + each image path by pid
  (`SystemProcessIdInformation`) + window captions (read without messaging the process). Command lines are not read.
- **Pause** is refused in HV Mode (stock pause suspends a thread, plants an int3, posts WM_NULL, may inject a thread);
  set a breakpoint instead. Title bar shows `[HV Mode]` / `[HV Mode OFF]`; the GUI's status bar has a permanent
  green **HV Mode** / red **HV Mode OFF** label, and Options has a checkable **HV Mode** item (the GUI follows the
  title prefix x64dbg.dll sets, and keeps the badge on titles set without it, e.g. after a stop).
- **No file of the target is opened:** module images are read from its memory through the hypervisor (pages not
  resident read as zeros), and PDBs are looked up only in x64dbg's own symbol cache -- never in the target's folder.
- **Other threads' registers** (read-only) come from their kernel trap frames (TitanTuring README).
- **Live tests (2026-11-02, explorer.exe through the running hypervisor; all in `src/dbg/TitanTuring/tests/`):**
  - `hvmode_test.cpp` -- the guard + shim, 45 checks: PASS. `hvmode_neg_controls.py` -- 7 mutations (guard allows all,
    owner check skipped, ntdll never patched, mode never on, map loses images, silent terminate, attach without
    guard): all caught.
  - `x64dbg_headless_hv.py` -- the real x64dbg.dll (headless): starts in HV Mode, attaches, reads memory, builds the
    memory map with every module split into sections, detaches, zero refusals: PASS. `x64dbg_headless_switch.py` --
    `hvmode off` / `on` at runtime, attach after the switch, switch refused while debugging: PASS.
  - The GUI: `x64dbg.exe -p <pid>` attaches (title `[HV Mode] explorer.exe - PID ...`), closes in ~2 s, target alive.
  - `handle_scan.py` -- the anti-cheat's view: the system handle table, while x64dbg is attached, shows **no** handle
    from x64dbg.exe on the target's process or any of its 168 threads; control (the scanner's own 169 handles found)
    and negative control (a helper holding one handle is found) both correct.

## Breakpoints live (2026-11-02, rev149 image)

First run on rev149 (`antidebug-lab\tests\target_vs_x64dbg.py bp`): "stopped at 0" -- x64dbg never saw the stop. Driven
directly through the bridge (`tests\bp_live.cpp`, no x64dbg in between) the hypervisor did park the thread exactly at
the breakpoint; three things were wrong:

1. **The hold's number.** A parked thread's hold number is `status.entries`; the record's own `seq` is the capture's,
   always 0 on rev149. TitanTuring compared `rec.seq` against 0 and called every hit "already reported". Fixed (and the
   stepping thread is now found by TID, not as index 0). rev149b also puts the hold number in `rec.seq`.
2. **The hypervisor loses held threads** (rev149): after a step or a continue the thread sometimes runs free for good
   -- Windows shows it asleep, the breakpoint page never faults again, commands are never taken; re-arming the
   breakpoint catches it at once (4 of 4). An executable translation of the page left behind on some core. rev149b
   fixes it in the hypervisor (an owed flush, and an escape guard that re-arms from reads). Client side meanwhile: a step
   that doesn't land in 3 s re-arms the breakpoint, and an idle breakpoint is re-armed every 2 s.
3. **Step over `call [rip+x]`**: rev149 measured FF 15 (every import call) as 2 bytes, trapped a return that never came.
   TitanTuring now steps over an indirect call as "run to the next instruction" (right on every image); rev149b fixes
   the hypervisor's decoder.

Also: a second breakpoint on a 4 KiB page that already has one is refused with the reason (the hypervisor watches
pages; the second would never fire).

After the fixes, on rev149: stopped exactly at `hot_target`, step into landed on `hot_target+1`; the step over that
followed hit the escape bug (re-caught at the breakpoint). The target saw DEBUGGER 0, INTEGRITY 0. To be re-run on
rev149b.

**rev150 run (2026-11-03):** continues land (bp_live `c,c,c,c,c` PASS: rev149b's fixes hold), but the SECOND step
failed every time: a new hold at the same address, the instruction not run. Cause: a step cut short before its
instruction ran (an interrupt due at the step's entry, or Hyper-V taking the vCPU) came back to the same RIP, faulted,
and was taken as "the step landed here"; and a fault with an interrupt in flight let the page open (LOOSE), so the
thread could run on. rev150b steps it again instead, and keeps the page closed for the event (turing-hv ledger,
rev150b). `tests\dw_probe.cpp` (a watch's own counters, live through the bridge) showed the capture / trace on
`cold_target` fine throughout -- the Cheat Engine test's failures there were its own RBX edit hanging the target.

## Steps that leave the breakpoint's page (2026-11-03)

The hypervisor holds a parked thread only on its breakpoint watch's own 4 KiB page, so a step whose instruction goes
elsewhere -- a call or jump to another page, a `ret` to the caller, code running off the page's end -- used to let the
thread run free until the breakpoint was hit again. TitanTuring now computes where the step lands (x64dbg's own Zydis,
linked into TitanTuring.dll: the next instruction, a direct or RIP-relative / register / memory indirect target, a
conditional branch evaluated against the stopped thread's flags and RCX, `ret`'s [RSP]) and, when that is on another
page, arms a **temporary breakpoint** there, releases the thread, and reports its stop there as the step
(`stepLanding` / `stepViaTemp`). The temporary breakpoint goes as soon as the thread is let go from it (Run, or a step
that lands on yet another page) -- it is armed only for the microseconds the thread needs to get there, which matters
when the landing is a system DLL page every process runs. Another thread of the process that stops on it is let go at
once. It takes a free watch (HVDW_MAX = 4 in all), refuses a page that already holds one of ours (the step then goes
the old way), and a thread that never reaches the landing within 3 s is reported ("runs on until a breakpoint").

**Live on rev150c** (`antidebug-lab\tests\target_vs_x64dbg.py xret`): held on `cold_target`'s `ret`, step into ->
landed on the caller's page (`…4548`, the return address) and held there. The next same-page step then ran free (the
rev150c step bug: an interrupt taken at the step's start -- fixed in the hypervisor as rev150d); `xstep` (three
same-page steps, then the `ret`) is the full scenario for rev150d.

## The held thread that got away (2026-11-04: rev150d run, rev150e built)

rev150d's RUN-ALL: `xret` PASS, `xstep` FAIL -- step 2 "landed" where step 1 had, every later step one behind;
DEBUGGER 0 / INTEGRITY 0 (rev150d's IF hold removed the TF leak). Measured with `bp_live` holding one thread and only
reading it: read every 5 s, the hold never moved in 30 s; read every 100 ms-1 s, the thread got away about once per
four of the hypervisor's escape-guard re-arms (rev149b re-armed the breakpoint page at every READ 250 ms apart) and
came round as a new hold at the same address -- which TitanTuring (rightly) took as the step's landing. rev150e (built,
not yet installed) re-arms only a thread that has stopped faulting, retries instead of passing a thread through when
the watch lock is busy, refuses a second watch on a watched page, and reports re-arms / escapes / the last escape's
vCPUs in the breakpoint's read status (bp_live prints them; `h<ms>` holds and fails if the hold moves -- in
RUN-ALL). A smaller leak remains open: arming ANY other watch frees a held thread ~3% of the time (the arm's kick of
every vCPU) -- a cross-page step's temporary breakpoint is such an arm. No TitanTuring change was needed.

**Correction (rev150e run, same day): the re-arm was the CATCH, not the escape.** rev150e failed the same way (plus
x64dbg's BREAKPOINT test and `xret`). `bp_live q20000` -- hold with NO hypervisor read, so nothing re-arms, and watch
the thread through Windows instead -- showed the "held" thread asleep in its own `Sleep(2)` 97% of the time from 78 ms
on: the breakpoint page was off on every core. Cause, in the hypervisor: the watch's "abandoned" test computed
`now - last_read` unsigned, and a READ on another core stamps `last_read` a few microseconds after a fault's own `now`
-- the difference wrapped, the watch was declared abandoned, and its page turned off everywhere. A held thread is
always mid-fault, so almost every READ raced one. rev149b's re-arm on READ turned the page back on, which is why holds
mostly LOOKED held and why the thread came round "as a new hold at the same address". rev150f (built) saturates every
cross-core time difference; a hosted test reproduces the race and fails on the rev150e source. `bp_live q<ms>` (under
10 s) is in RUN-ALL. Still no TitanTuring change needed.

## Native trace (2026-11-03, rev150): `HvTrace`

    HvTrace [address[, count[, stepover]]]      count 1..2048 (default 1000; x64dbg numbers are hex: `.300` = 300)
    HvTraceStop                                 end a waiting / running trace, keep what it recorded

Or right-click in the disassembly: **Hypervisor trace (HV Mode)** > Trace from here / ... stepping over calls / Stop.
The first user-mode thread of the debuggee to reach the address is followed by the hypervisor one instruction at a time
-- on any page, into calls and out through returns -- and each instruction's registers (before it ran) recorded. The
thread is never stopped and never sees the trap flag. When the trace ends, `hvtrace.cpp` writes a normal x64dbg trace
file (`db\<module>-hvtrace-<time>.trace64`: the TRAC header and delta-coded register blocks, a full dump every 512, as
`TraceRecord.cpp` writes them) and opens it in the Trace tab. Registers only: no memory-access columns, no segments /
x87 / SSE (left 0). It ends before PUSHF / POPF / IRET / SYSCALL / INT n, at an interrupt or exception due for the
thread, or after `count`; the log line says which and how long it took. One trace at a time (it uses one of the 4
hypervisor watches).

Pieces: `TitanTuring.dll` exports `TT_TraceStart / TT_TraceRead / TT_TraceStop / TT_TraceReason` (over bridge commands
43 / 44, `vendor	hvbridge_proto.h` + `turinghv.h` SDK 1.13); `hvmode.cpp` exposes the engine module
(`hvmodeEngine()`); `hvtrace.cpp` is the command and the file writer; `CPUDisassembly.cpp` the submenu.

Test: `testsddbg_hvtrace.py` (headless x64dbg, HV Mode, adbg_target): `HvTrace hot_target, .300` and
`HvTrace cold_target, .2000, 1`, then reads each file back the way the Trace tab's `TraceFileReader` does. **PASS live
on rev150**: 177 records from `push rbp` at `hot_target`, +1 `mov rbp,rsp` with RSP 8 lower, +4 with RBP = RSP, no TF
in any record, the last record the `pushfq` (recorded, never stepped); step over: 11 records, 187 stepped, none on
`.hot`; the target saw DEBUGGER 0, INTEGRITY 0, TIMING 0. In RUN-ALL. (The Trace tab itself opening the file is the
stock `GuiOpenTraceFile` path; the GUI was built but not driven by a test.)

## Build toolchain on this machine

CMake 4.3 and the VS 2022 MSVC toolchain. **Qt5 installed 2026-11-02**: x64dbg's own pinned dependency
`qt5.12.12-msvc2017_64.7z` (from github.com/x64dbg/deps, SHA256 `770490bf...ada48a` verified) extracted to
`C:\Qt\5.12.12-msvc2017_64`, beside Qt 6.11. Submodules fetched at their pinned revisions (`deps` 4a830e1, `btparser`
6daea14, `TitanEngine` 947ad61, `GleeBug` b2b68b8). Build:

    cmake -S . -B build64 -G "Visual Studio 17 2022" -A x64 -DQt5_DIR=C:/Qt/5.12.12-msvc2017_64/lib/cmake/Qt5
    cmake --build build64 --config Release --parallel

Output in `bin\x64`: `x64dbg.exe`, `x64dbg.dll`, `x64gui.dll`, the stock `TitanEngine.dll` and `TitanTuring.dll`.
`cmake.toml` is the source of truth (cmkr regenerates `CMakeLists.txt` at configure).

## Transport: x64dbg talks to the HV through the bridge, never directly

x64dbg can **not** be a trusted caller of the hypervisor: it is ~2000 code pages, loads plugins, and its Lua engine
generates code -- exactly the reasons the caller gate exists, and the reason Cheat Engine uses a broker. So TitanTuring
does **not** link `turinghv.dll`; it speaks the existing **`thvbridge.exe`** shared-section protocol
(`Cheat Engine/turinghv/thvbridge/thvbridge_proto.h`), the same tiny trusted broker Cheat Engine uses. The chain is:
`x64dbg -> TitanTuring (C++) -> thvbridge.exe (trusted) -> turinghv.dll -> the HV`. I'll vendor a small C++ client for
`thvbridge_proto.h` (the Pascal mirror is `turinghvbridge.pas`). The bridge already exposes everything P0 needs
(read/write/scatter, enumerate processes/threads/modules, memory map, the data watch, the capture breakpoint, and the
rev149 parking breakpoint arm/read/cmd); new HV features add new bridge commands.

## Phased plan

- **P0 (no HV change):** `TitanTuring` lib — memory r/w, attach(open)/stop, `SetBPX`/`DeleteBPX` = parking bp,
  `StepInto`/`StepOver`, `GetContextDataEx`/`SetContextDataEx` for the stopped thread, `SetMemoryBPXEx` = data watch,
  `DebugLoop` = poll parked threads + watch hits -> x64dbg callbacks, thread/module enumeration. Builds `x64dbg.dll`.
- **P1 (HV: gap 2):** read a switched-out thread's trap frame -> real Threads view + set-context on any thread.
- **P2 (HV: gap 1):** guest exception intercept -> exceptions tab, "break on crash".
- **P3 (optional HV: gap 3):** mass-park = classic whole-process pause.
- Each phase: hosted tests for the new HV piece, a built `x64dbg.dll`, and a prediction.
