# x64dbg -> turing-hv: every feature, its hypervisor equivalent, and what's new

This is the master port map. For each x64dbg capability it says: the turing-hv mechanism, **whether it touches user
mode / is visible to the guest** (the hard rule: it must not), whether it is **already in the backend** (rev146b data
watch, rev148 capture, rev149 parking) or **new HV work**, and for new work, how it will be built.

Legend: **[have]** already shipped · **[engine]** pure x64dbg-side, no HV change · **[new-HV]** needs new hypervisor
code (designed below) · **[limited]** works with a documented restriction · **[out]** not ported (says why).

## 0. The reference projects, and the line we hold

- **TitanHide** (mrexodia): a *kernel driver* that SSDT-hooks `Nt*` to hide a debugger (needs PatchGuard + DSE off).
  We reject the kernel route entirely; nothing here loads a driver or patches SSDT.
- **HyperHide** (Air14): the *hypervisor* route (Intel EPT) — the model we borrow for breakpoints, but its purpose is
  **anti-anti-debug**: it spoofs `NtQueryInformationProcess` (DebugPort/DebugObjectHandle), PEB `BeingDebugged`/
  `NtGlobalFlag`, heap flags, `KUSER_SHARED_DATA`, and freezes time to defeat timing checks.
- **The line:** we port x64dbg's **debugging** features (break, step, memory, registers, trace, disasm, patch). We do
  **not** build the anti-detection spoofing (lying to the guest's `NtQueryInformationProcess`, faking PEB/KUSD, time
  freezing) — that is active anti-anti-cheat tampering, which the operator has ruled out. It is also **mostly moot**:
  because we are *not* a Windows debugger (no `DebugActiveProcess`, no debug port, no `int3` in real pages, no DRx, no
  `PEB.BeingDebugged`), the usual anti-debug checks already see a clean process with nothing to spoof. Where x64dbg's
  own "hide debugger" plugin would act, we simply have nothing to hide. This section is the explicit boundary.

## 1. Attach / session

| Feature | Mechanism | Visible? | Status |
|---|---|---|---|
| Attach to a running game | backend opens the process, resolves CR3 (the gate) | no | **[have]** |
| Open an EXE and debug from entry / TLS callbacks | needs create-with-debug + early control | — | **[out]** attach-only; we join an already-running game |
| Detach | drop all breakpoints/watches (they self-release) | no | **[have]** |

## 2. Run control

| Feature | Mechanism | Status |
|---|---|---|
| Run / continue | release the parked thread (rev149 CONTINUE) | **[have]** |
| Step into / over / out | rev149 concealed TF step; step-over = return trap; step-out = return trap on the caller's return | **[have]** (holds within the bp's page; off-page runs to the next bp) |
| Run to selection | rev149 RUNTO | **[have]** |
| Pause one thread | parking breakpoint (rev149) | **[have]** |
| Pause the whole process | **mass-park**: park every user thread at once | **[new-HV]** gap 3 (below); 2026-11-04: through Windows when "allow visible Windows actions" is on |

## 3. Breakpoints

| Feature | Mechanism | Status |
|---|---|---|
| Software breakpoint (normally `int3`) | **shadow code page** (below) or parking; no byte in the real page | **[new-HV]** shadow / **[have]** parking |
| Hardware execute breakpoint (normally DR0-3) | same (shadow / parking); never a debug register | **[have]** |
| Memory read / write / access breakpoint (normally guard page / DR) | **data watch** (rev146b) | **[have]** |
| Conditional / log / command breakpoint | x64dbg evaluates the condition on the HV hit and resumes if false | **[engine]** |
| Breakpoint on DLL load / module entry | poll module enumeration for a new module, then arm | **[limited]** polled, not an exact event |
| Exception breakpoint ("break on C++/access-violation/...") | guest-exception intercept | **[new-HV]** gap 1 (below) |

## 4. Stepping, tracing, animate

| Feature | Mechanism | Status |
|---|---|---|
| Step into/over/out | rev149 | **[have]** |
| Trace into / over with a stop condition | repeated rev149 step; the engine checks the condition each step | **[engine]** (within the page window; cross-page falls back to run-to-next-bp) |
| Run trace / trace record (log every instruction) | repeated step logged by the engine | **[limited]** heavy; bounded by the step cost and the page window |
| Animate (step on a timer) | repeated step on a timer | **[engine]** |

## 5. Memory

| Feature | Mechanism | Status |
|---|---|---|
| Read / write memory, dump view | backend read/write (no handle, invisible) | **[have]** |
| Memory map | backend region enumeration (rev146 vmem_enum) | **[have]** |
| Patch bytes / save patched file | backend write (respects guest RO; shared-code pages need the opt-in) | **[have]** |
| Search (pattern / value / string) & references | engine reads via the backend and searches | **[engine]** |
| Allocate / free memory in the debuggee (`VirtualAllocEx`) | the HV cannot allocate guest memory invisibly | **[limited]** through Windows with "allow visible Windows actions" (off by default) |
| Fill / scatter read-write of many addresses | backend scatter read/write | **[have]** |

## 6. Registers & flags

| Feature | Mechanism | Status |
|---|---|---|
| View/edit GPRs, RIP, RFLAGS, segments of the stopped thread | capture snapshot (read) + rev149 SETREG/SETRIP (write) | **[have]** |
| x87 / SSE (XMM, MXCSR) | the snapshot's FXSAVE | **[have]** |
| AVX / AVX-512 (YMM/ZMM) | snapshot does XMM only today | **[new-HV]** gap 5 (XSAVE path) |
| Debug registers (DR0-7) view | we never use DRx; shown as not-applicable / zero | **[engine]** |
| Registers of a thread that is NOT stopped | read its switched-out kernel trap frame | **[have]** (2026-11-03, trapContext; full from Windows with "allow visible Windows actions") |

## 7. Stack, call stack, SEH

| Feature | Mechanism | Status |
|---|---|---|
| Stack view | read memory at RSP (the snapshot carries a slice) | **[have]** |
| Call stack | engine unwinds the stack slice with module unwind data | **[engine]** |
| SEH chain | engine reads the chain from memory | **[engine]** |

## 8. Threads

| Feature | Mechanism | Status |
|---|---|---|
| Thread list | backend thread enumeration | **[have]** |
| Suspend / resume a thread | parking hold / release | **[have]** |
| Per-thread context (the stopped one) | snapshot + SETREG | **[have]** |
| Per-thread context (others) | trap-frame read | **[have]** (trapContext) |
| Kill a thread | would require a visible/kernel action | **[limited]** through Windows with "allow visible Windows actions" (off by default) |

## 9. Modules, symbols, disassembly, analysis

| Feature | Mechanism | Status |
|---|---|---|
| Module list, imports/exports | backend module enumeration | **[have]** |
| Symbols (PDB), source lines | engine loads PDBs from files read via the backend | **[engine]** |
| Disassembly, analysis, xrefs, function graph | entirely engine-side over bytes read via the backend | **[engine]** |

## 10. Handles / windows / other OS views

| Feature | Mechanism | Status |
|---|---|---|
| Handle list, window list | x64dbg uses Windows APIs on the debuggee; the HV does not enumerate handles/windows | **[limited]** could be read from kernel objects later; out for now |

## 11. The shadow code page breakpoint (operator-requested, the new breakpoint engine)

The operator's design, and the preferred breakpoint from here on (supersedes the earlier "no shadow pages" note):

### 11.1 The AMD constraint (verified)

AMD nested page tables have **no execute-only pages**: a present page is always readable (there is no read bit, only
present / write / user / no-execute). Intel EPT has separate R/W/X bits, which is what DdiMon and HyperHide use to make
"execute sees the copy, read sees the original" at once. That cannot be expressed on AMD. Primary reference:
tandasat's **SimpleSvmHook** (the AMD sibling of DdiMon) states this and uses the two-state design below. AMD also has
no Monitor Trap Flag, so "step one instruction then restore" uses RFLAGS.TF (our concealed step, rev149).

### 11.2 Design: two NPT views per vCPU, swapped as execution enters and leaves the page

The real code page **P** stays byte-for-byte clean. The breakpoint lives only in a **shadow copy** of P in HV-private
memory (never mapped into the guest anywhere else, never DMA-reachable) with `0xCC` at the target. The shadow is mapped
at the **same guest-physical address**, so RIP-relative code and relative jumps behave identically.

| view | P maps to | P perms | every other page | when |
|---|---|---|---|---|
| **resting** | the clean page | read-only, **NX** | executable as normal | the vCPU is executing anywhere except P |
| **hook-active** | the **shadow** (with `0xCC`) | read-only, **X** | **NX** | the vCPU is executing on P |
| **step** | the clean page | read-only, **X** | **NX** | exactly one instruction, stepping off the breakpoint |

Each view is its own cached composition context of that vCPU (our composer already keeps several ASID-tagged
contexts per vCPU), so a swap is a VMCB `nCR3`/ASID change, not a rewrite of NPT entries. Entering P costs one exit
(resting: P is NX), leaving P costs one exit (hook-active: everything else is NX); **inside P, execution is native
speed** -- only the breakpoint instruction traps. This is the whole advantage over parking, where every instruction on
the page single-steps.

### 11.3 Never missing the target (operator requirement: "as soon as RIP reaches the target, trigger")

Every way RIP can arrive at the target is covered:

1. **Entering P at the target directly** (jump / call / ret / IRET / interrupt return into the target): the resting
   view's NX faults on the fetch with RIP = target -> **trigger right there**, the earliest possible moment, before any
   byte is fetched.
2. **Reaching the target from earlier code on P:** native in hook-active -> the fetch hits `0xCC` -> `#BP` -> trigger.
3. **Every vCPU, every thread:** views are per-vCPU, and P is NX in every vCPU's resting view, so no vCPU can ever
   execute P from the clean page. There is no path to the target that bypasses the shadow.
4. **The `#BP` intercept is mandatory and re-applied at every L2 entry while in hook-active** (L1 rebuilds VMCB02 from
   VMCB12, so a one-time set would be lost). The hook-active view can never be entered without it -- otherwise the
   guest would receive a `#BP` it never planted (a crash and a detection).
5. **Consecutive hits** (a loop back to the target): after the action, the original instruction is executed exactly
   once in the **step** view (P clean + X, everything else NX, TF set); the step ends at its `#DB` (still on P -> back
   to hook-active) or at the NX fault (left P -> resting). The next arrival at the target hits `0xCC` again. Nothing
   between two hits ever runs from an un-hooked copy.
6. **Instructions that can't be single-stepped** at the target: control transfers (SYSCALL, INT n, IRET, far jmp/call)
   leave P, and in the step view every other page is NX, so the step ends at the first fetch elsewhere -- no TF needed,
   control never escapes. PUSHF / POPF / MOV SS (stay on P, and TF would show in PUSHF) are **emulated in the HV** for
   that one instruction instead of run.
7. **An instruction that straddles a page boundary** (starts on P-1 and ends on P, or starts on P and ends on P+1):
   both pages must be executable for one fetch; detected when the faulting page != RIP's page, handled with a
   both-pages-executable step for that one instruction. A target that starts near the end of P still traps on its
   first byte (`0xCC` is a whole instruction), so the tail is never needed.
8. **Interrupts while hook-active:** the handler is on another page; before injecting an event we switch to resting so
   the handler runs without faulting, then the return into P re-enters hook-active through case 1.
9. **The code changes under us (self-modifying / hot-patched / decrypted code):** P is read-only in all three views, so
   a write faults; the write is applied to the clean page (let through like the data watch) and the shadow is
   **re-synced** (re-copied from the clean page, `0xCC` re-inserted) before any vCPU fetches it again. Vcpus in
   hook-active for P are moved to resting first so no core executes stale bytes. The shadow therefore always equals the
   real code except at the target.
10. **Windows moves or re-maps the page:** the target's linear address is re-translated on every client poll (as the
    watches do); a new physical page is re-copied and re-hooked. An optional watch on the guest PTE that maps the target
    makes this synchronous (closes the window between the move and the next poll).
11. **Shared code (a DLL page mapped by many processes):** every process runs P through the shadow; a hit from another
    address space is **not** stopped and **not** reflected -- it is silently stepped past (case 5). Only a `0xCC` that
    was already in the original code (the guest's own breakpoint) is reflected to the guest, byte-exact.
12. **RIP normalisation:** `#BP` from `0xCC` is a trap, so the saved RIP is the instruction after it; we set RIP back to
    the target before the action, so the snapshot / the frozen thread show RIP = target (the instruction about to
    run). To be verified on hardware and pinned by a unit test.

### 11.4 Per-breakpoint options (operator requirement)

Each breakpoint carries two choices, set when it is created and changeable later:

- **Action -- what happens when it hits:**
  - **Freeze** -- the thread stops at the target (the rev149 parking FSM: continue / step into / step over / run to /
    set register / release). Option: **freeze the whole process** (mass-park, gap 3) instead of just the thread.
  - **Snapshot and continue** -- the rev148 capture (registers + stack + code + memory at each register to the
    configured depth), stored, and the thread runs straight on. Option: how many hits to record before disarming.
- **Trigger -- how the target is caught:**
  - **Shadow** (default, the design above): native speed inside the page; one exit to enter / leave the page.
  - **Chain** (the existing rev149 mechanism): the page is never copied or modified at all and every instruction on it
    is single-stepped. Slower on hot code, but **no byte anywhere ever differs** -- for code that checks itself (11.5).

### 11.5 The residual (honest)

While a vCPU is executing **on P itself** (hook-active), P is mapped to the shadow and AMD cannot make it unreadable, so
an instruction on P that reads **the exact target byte** reads `0xCC`. Every other byte of P reads correctly (the
shadow equals the clean page elsewhere), and code on **any other page** -- which is where integrity checks normally
run -- always reads the clean page. SimpleSvmHook documents the same limit. For code that checksums its own page, use
the **Chain** trigger: nothing is ever modified.

### 11.6 Operator's questions (2026-11-02), answered

- **"A trigger that reads RIP every time and fires when RIP is on our list -- instead of an executable shadow?"** No
  x86 facility checks RIP for free. The hypervisor only sees RIP at an exit, so "check every RIP" means "exit on every
  instruction" -- which is exactly the **Chain** trigger: the page is made non-executable; a thread entering it is
  run one instruction at a time with a concealed TF, RIP compared each step; leaving the page re-arms the trap. It is
  what rev149 already does, it changes **zero bytes**, and it fires the instant RIP == target. Its price is one round
  trip per instruction executed **on that 4 KiB page** (not per hit) -- cheap on cold code, a timing signal on a hot
  loop. The hit itself can be freeze or snapshot-and-continue (rev148 capture: tens of microseconds). So: Chain is the
  safe default; Shadow is the fast option for hot pages, with the 11.5 residual. Both stay per-breakpoint choices.
- **"Make the shadow page non-readable and return zeros (or another read trigger)?"** AMD's nested page tables have no
  "executable but not readable": clearing Present removes read, write and execute together, so a not-readable page
  also traps every instruction fetch. And returning zeros would itself be a detection vector (a checksum of the page
  changes; code reading its own constants or jump tables breaks). The correct read answer is the ORIGINAL bytes --
  which the resting view already gives to every reader except code running on that same page (11.5).
- **"Can the hypervisor still read a page the guest can't?"** Yes. Nested-page permissions only restrict the guest; the
  hypervisor reads guest RAM through its own mapping of the physical pages, whatever the guest-side bits say. Memory the
  guest can't see at all already exists (the composition pools, where shadow copies would live), so no extra RAM
  reservation is needed.

## 12. New hypervisor work (designed; to build after P0)

- **Gap 1 -- guest exception intercept (`#BP`, `#PF`, `#UD`, `#GP`, ...).** The VMCB's exception-intercept bitmap for
  the L2 guest, opt-in per vector, reported on the control channel. Enables the shadow breakpoint's `#BP`, exception
  breakpoints, and "break on crash". Reflects anything not ours to the guest unchanged. Cost: a watched vector's
  exceptions take one exit each (so a hot vector is left unwatched).
- **Gap 2 -- read/write a switched-out thread's context.** Read (and, with care, write) the thread's saved kernel trap
  frame from its KTHREAD when it is not running, so x64dbg's Threads view and set-context work for every thread, not
  only the stopped one. Read path first (safe); write path behind confirmation.
- **Gap 3 -- mass-park (whole-process pause).** Enumerate the process's user threads and hold each at its current
  user-mode RIP (park on the page it is on). Resume releases them. Spins each held thread's core while paused.
- **Gap 4 -- shadow-page breakpoints (section 11).** The composition change: three per-vCPU views (resting /
  hook-active / step) as cached ASID-tagged contexts, swapped by `nCR3`/ASID as execution enters and leaves the page;
  the HV-private shadow page with `0xCC`; the `#BP` intercept re-applied at every L2 entry while hook-active; the
  straddle step; PUSHF/POPF/MOV SS emulation; write-fault resync; per-poll re-translation. Depends on gap 1 (`#BP`).
  The largest HV piece; its never-miss cases (11.3) each get a unit test and a negative control.
- **Gap 5 -- XSAVE/YMM in the snapshot.** Extend the capture to an XSAVE area for YMM/ZMM, not just FXSAVE/XMM.

Each ships with hosted unit tests, negative controls, a rebuilt image, and a prediction, and is reported before it
goes in (the operator's standing rule).

## 13. Snapshot double-check (operator asked)

The rev148 capture record already holds what the breakpoint snapshot needs: all GPRs + RIP/RFLAGS/RSP/CR2/CR3/EFER/
DR6/DR7, the six segment selectors and bases, FS/GS/KernelGS base, XMM0-15 + the FXSAVE header, up to 512 B of stack
from RSP, up to 256 B of code around RIP, PID/TID, and up to 128 B at **each register and the operand** it points to.
Depths are configurable (`stack_bytes`, `code_before/after`, `deref_bytes`). **One caveat vs "to a certain depth":** the
memory-at-registers is **one level** of indirection (the bytes *at* each register). Following a pointer chain
(`*reg`, `**reg`, ...) to N levels is a small enhancement if you want it -- say the word and I add a depth-N walk.
