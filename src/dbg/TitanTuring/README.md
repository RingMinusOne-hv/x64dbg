# TitanTuring — the turing-hv debug engine for x64dbg

Drop-in replacement for `TitanEngine_x64.lib`: it implements the `TitanEngine.h` API (the ~37 functions
`src/dbg` calls) over the turing-hv hypervisor, via the `thvbridge.exe` broker. See `../../../PORT-TURINGHV.md` and
`../../../FEATURE-MAP.md` for the full design. Nothing here uses `DebugActiveProcess`, `int3`, debug registers, or the
Windows debug port.

## Files (P0)

- `thvproto.h`      — vendored copy of the bridge wire format (`thvbridge_proto.h`) + the `thv_*` structs it needs.
- `thvclient.h/.cpp`— the C++ bridge client: create the shared section + events, launch `thvbridge.exe`, do slot
                       request/response. Mirrors `Cheat Engine/turinghvbridge.pas`. Interface below.
- `TitanTuring.cpp` — the `TitanEngine.h` surface implemented over `thvclient` (memory, context, breakpoints, step,
                       the `DebugLoop` poll that turns HV hits into x64dbg callbacks).
- `TitanTuring.def`  — same exports as `TitanEngine.def` (so the linker swap is transparent).

## P0 checklist (no HV change — uses rev146b/148/149 primitives)

Status 2026-11-02. "live" = verified against the running hypervisor; "built" = compiles, not yet exercised live.

- [x] `thvclient` (C++ bridge client, byte-compatible with Cheat Engine's): section/events/launch, slots, retire-on-
      timeout; Read/Write (chunked), ProcessInfo, EnumThreads/Modules/Memory (paged), Cr3Query, data watch,
      parking breakpoint, capture. **live** — `tests/thvclient_selftest.cpp`: broker start, ping, connection info,
      process info and a read of explorer.exe's PE header. PASS.
- [x] `TitanTuring.cpp` = a drop-in `TitanEngine.dll` (all 37 exports, plain C names like the original). **live** —
      `tests/titanturing_harness.cpp` plays x64dbg: attach to explorer.exe through the HV -> CREATE_PROCESS with a
      pseudo-handle Windows doesn't recognise (no real handle), 168 CREATE_THREAD, 348 LOAD_DLL, MemoryReadSafe 'MZ',
      GetPEBLocation (PEB.ImageBaseAddress matches), GetTEBLocation (TEB.Self matches), a running thread's registers
      reported as 0 not invented, 10,973 regions from the HV map, detach. PASS.
  - attach: CR3 = EPROCESS root validated by reading MZ/PE, else the HV CR3 tracker; no system breakpoint (stock
    attach gets one from a thread injected into the game -- never done).
  - EPROCESS.Peb / ETHREAD.Teb offsets learned from x64dbg's own process and thread (no per-build tables).
  - events are collected under the engine lock and fired after it is released (an x64dbg callback can wait on its GUI
    thread while that thread calls into us).
- [x] `SetBPX`/`DeleteBPX` -> parking breakpoint; `StepInto`/`StepOver` -> break STEP/STEPOVER; continue on callback
      return; `Get/SetContextDataEx`, `Get/SetFullContextDataEx` from the parked thread's snapshot + SETREG/SETRIP;
      `SetHardwareBreakPoint` -> parking (execute) / data watch (write, access); `SetMemoryBPXEx` -> data watch.
      **built, not live yet**: this machine's broker is SDK 1.10 (rev147b); needs the rev149 image + bridge.
- [x] the Win32 shim (`shim.cpp`): x64dbg.dll's and dbghelp's import-table entries for ~50 functions routed at HV Mode
      entry -- pseudo-handles answered by the HV (memory, VirtualQueryEx map, module/image paths, PEB/TEB, the stopped
      thread's CONTEXT) or refused + reported (alloc/protect/free, remote thread, terminate, suspend, duplicate,
      toolhelp module/heap snapshots, PostThreadMessage to another process, DebugActiveProcess). **live** -- 
      `tests/hvmode_test.cpp` vs explorer.exe: PASS (45 checks).
- [x] HV Mode's guard (`hvguard.cpp`): NtOpenProcess / NtOpenThread / NtGetNextProcess hooked in our own ntdll -- no
      handle to any other process or thread from anything in x64dbg's process; attach refused unless active. **live**
      (same test, incl. ntdll called directly).
- [x] build `x64dbg.dll` + GUI against this engine (Qt 5.12.12 installed; `TitanTuring` is a cmake.toml target; the
      engine is chosen by `src/dbg/hvmode.cpp`'s delay-load hook). Builds clean.
- [ ] live breakpoint test: extend the harness to set a breakpoint in a test target (Cheat Engine's
      `turinghv/tests/thvtarget.c`), verify park -> callback -> step -> step over -> continue, under rev149.

## P0 limits (documented, not bugs)

- The hypervisor holds **4 watches at once** (`HVDW_MAX`), shared by breakpoints, memory/hardware data breakpoints
  and captures; the 5th is refused with a message. Raising it is an HV change (to report).
- Memory / hardware data breakpoints report the access but don't stop the thread (the data watch lets it run on).
  "Break on access" needs the HV to park the thread at the hit (an HV change -- FEATURE-MAP gap list).
- Execute memory breakpoints (`UE_MEMORY_EXECUTE`) refused for now -- use a breakpoint on the instruction.
- The stopped thread has all its registers. **Other threads (2026-11-02, gap 2's read half, no HV change):** a thread
  waiting in a system call shows RIP, RSP, RBP, RFLAGS, RBX, RSI, RDI from the trap frame Windows saved on its kernel
  stack (read through the HV; the frame must prove itself -- user CS, RIP right after a `syscall`, user RSP -- or
  nothing is shown). Measured on explorer: ~41 of 170 threads (the rest have their kernel stack paged out, are running,
  or aren't in a system call); every one independently checked (RIP in a module after a syscall, RSP in that thread's
  own stack). Live harness PASS + 2 negative controls caught. Registers of other threads are read-only.
- Flags / segment / vector registers are read-only (the HV's SETREG covers the 16 GPRs and RIP).

## Later phases (new HV work, see FEATURE-MAP §12)

- P1 gap 2: other threads' context (trap-frame read).
- P2 gap 1: guest exception intercept -> exceptions tab, break-on-crash, and the shadow breakpoint's `#BP`.
- P3 gap 3: mass-park = whole-process pause.
- P4 gap 4: shadow code page breakpoints (read-invisible, full-speed between breakpoints).
- gap 5: XSAVE/YMM in the snapshot.
