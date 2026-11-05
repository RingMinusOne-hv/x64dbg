// TitanTuring.h -- what TitanTuring (x64dbg's HV Mode engine, TitanTuring.dll) exports beyond TitanEngine.h: HV Mode
// itself (the guard + the Win32 shim), and the pieces that answer Windows-style questions about the target from the
// hypervisor instead of from a handle. x64dbg.dll loads the DLL dynamically (hvmode.cpp); the test harness links it.
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>

#ifdef TITANTURING_BUILD
#define TT_API extern "C" __declspec(dllexport)
#else
#define TT_API extern "C" __declspec(dllimport)
#endif

typedef struct TT_MODULE { uint64_t base, size, entry; char name[40]; } TT_MODULE;
typedef struct TT_THREAD { DWORD tid; DWORD pad; uint64_t start; } TT_THREAD;
typedef struct TT_REGION { uint64_t base, size; uint32_t flags, pad; } TT_REGION;   // flags: THV_MEMORY_*

// one thing HV Mode refused (the guard's system-call refusals and the shim's operation refusals share one queue)
enum TT_REFUSAL_KIND
{
    TT_REFUSE_OPEN_PROCESS = 1,     // NtOpenProcess on another process
    TT_REFUSE_OPEN_THREAD = 2,      // NtOpenThread on a thread of another process
    TT_REFUSE_NEXT_PROCESS = 3,     // NtGetNextProcess (walks every process, returning a handle to each)
    TT_REFUSE_SHIM = 4,             // the Win32 shim refused an operation on the target (text in `what`)
    TT_WINDOWS_ACTION = 5,          // 2026-11-04: done through Windows because the user allowed it (text in `what`)
};
typedef struct TT_REFUSAL
{
    uint32_t kind;                  // TT_REFUSAL_KIND
    uint32_t pid;                   // the process asked for (or the thread's owner; 0 = unknown)
    uint32_t tid;                   // the thread asked for (TT_REFUSE_OPEN_THREAD)
    uint32_t access;                // the access mask asked for
    uint64_t caller;                // return address into whoever made the call
    char what[96];                  // TT_REFUSE_SHIM: which operation
} TT_REFUSAL;

// ---- HV Mode ----
// Enter: install the guard (fail closed -- false + `why` when it can't be guaranteed), route `modules`' imports
// through the shim, start refusing. While active, this process gets no handle to any other process or thread.
TT_API bool TT_EnterHvMode(const HMODULE* modules, DWORD count, char* why, DWORD whyLen);
TT_API bool TT_LeaveHvMode(char* why, DWORD whyLen);     // refused while attached
TT_API bool TT_HvModeActive();
TT_API bool TT_TakeRefusal(TT_REFUSAL* out);            // oldest first; false when none
TT_API DWORD TT_RefusalsDropped();                      // refused but not reported (queue was full)
TT_API int TT_RouteModule(HMODULE m);                   // route one more module's imports (e.g. loaded later)
// 2026-11-04: "allow visible Windows actions" -- x64dbg's [Engine] HvAllowWindows (command `hvwindows`), default OFF.
// On: what the hypervisor can't do -- allocate / free / protect memory, create a thread, kill a thread or the process,
// suspend / resume a thread, write a read-only page, other threads' registers, pause -- goes to Windows with a real
// handle opened for that one call (the target can see the handle and the action). Each is logged (TT_WINDOWS_ACTION).
TT_API void TT_SetAllowWindows(bool on);
TT_API bool TT_AllowWindows();
// Pause: the thread the pause will be reported on (the main thread; 0 = none), then the request -- rev151: the
// hypervisor's FREEZE holds every user thread invisibly (registers from each thread's snapshot); an image before
// rev151 and the switch on: the engine suspends the process through Windows (NtSuspendProcess) instead. Either way it
// reports EXCEPTION_BREAKPOINT on `tid` and, when x64dbg's handler returns (Run), lets the process go.
TT_API DWORD TT_PauseChooseThread();
TT_API bool TT_PauseRequest(DWORD tid);
TT_API bool TT_PausedByWindows();

// ---- the target, answered by the hypervisor ----
TT_API bool TT_IsTargetProcess(HANDLE h);      // one of our process pseudo-handles (any pid)
TT_API bool TT_IsTargetThread(HANDLE h);       // one of our thread pseudo-handles
TT_API DWORD TT_PseudoPid(HANDLE h);           // the pid a process pseudo-handle carries (0 = not one)
TT_API bool TT_IsTargetPseudo(HANDLE h);       // the ATTACHED target's pseudo-handle
TT_API bool TT_IsTargetTid(DWORD tid);         // a thread of the attached target
TT_API DWORD TT_StoppedTid();                  // the thread stopped at a breakpoint (0 = none)
TT_API DWORD TT_TargetPid();
TT_API DWORD TT_ParentPid();
TT_API bool TT_TargetAlive();
TT_API DWORD TT_ThreadIdOf(HANDLE h);
TT_API uint64_t TT_ThreadStart(DWORD tid);
TT_API const char* TT_LastMessage();
TT_API bool TT_TargetModules(TT_MODULE* out, DWORD max, DWORD* count);
TT_API bool TT_TargetThreads(TT_THREAD* out, DWORD max, DWORD* count);
TT_API bool TT_TargetRegions(TT_REGION* out, DWORD max, DWORD* count);
TT_API uint64_t TT_ImageBase();
TT_API const char* TT_ImageName();
TT_API DWORD TT_ModulePath(uint64_t base, wchar_t* out, DWORD n);              // from the target's loader list
TT_API DWORD TT_ProcessImagePath(DWORD pid, wchar_t* out, DWORD n, bool dos);  // any pid, no handle

// turing-hv rev150: THE NATIVE TRACE of the attached target. The first user-mode thread to reach `address` is followed
// by the hypervisor instruction by instruction (any page, into calls and out through returns) and each instruction's
// registers before it ran are recorded -- the thread is never stopped and never sees the trap flag. It ends before
// PUSHF / POPF / IRET / SYSCALL / INT n, at an interrupt or exception due for the thread, or after `maxRecords`
// (1..2048). stepOver: a callee runs (stepped) but unrecorded. One trace at a time.
typedef struct TT_TRACE_REC { uint64_t rip, rsp, rflags; uint64_t gpr[16]; } TT_TRACE_REC;   // RAX RCX RDX RBX RSP RBP RSI RDI R8..R15
typedef struct TT_TRACE_INFO
{
    uint32_t state, reason, count, max, flags, pauses, vcpu, pad;   // state 1 armed / 2 running / 3 done; reason: TT_TraceReason
    uint64_t steps, teb, pid, tid, cr3, start_tsc, end_tsc, tsc_hz;
} TT_TRACE_INFO;
TT_API bool TT_TraceStart(uint64_t address, uint32_t length, uint32_t maxRecords, bool stepOver, uint32_t* id, char* why, DWORD whyLen);
// every record taken so far (from the first) into recs (at most max), *count of them; info = the trace's state now.
TT_API bool TT_TraceRead(uint32_t id, TT_TRACE_INFO* info, TT_TRACE_REC* recs, uint32_t max, uint32_t* count);
TT_API void TT_TraceStop(uint32_t id);              // ends it (a running trace stops) and frees its watch
TT_API const char* TT_TraceReason(uint32_t reason); // why it ended, in words
