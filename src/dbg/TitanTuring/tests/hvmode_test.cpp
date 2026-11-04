// hvmode_test -- live test of HV Mode (TitanTuring.dll's guard + Win32 shim) against a real process; no x64dbg needed.
//   hvmode_test.exe <path\to\TitanTuring.dll> <pid>
// This program routes its OWN imports through the shim (as x64dbg.dll's are), so the plain Win32 calls below take the
// same path x64dbg's do. The target is only ever opened with PROCESS_QUERY_LIMITED_INFORMATION, and only outside HV Mode
// (the controls A1 / D1). Inside HV Mode nothing in the target is touched: no handle, no thread, no byte changed.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define TURINGHV_STATIC 1
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cwchar>
#include <string>
#include "../../TitanEngine/TitanEngine.h"
#include "../TitanTuring.h"

// statically imported from ntdll, so they go through this exe's import table (and so through the shim)
extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

#define FN(name) static decltype(&name) p_##name
FN(SetCustomHandler); FN(AttachDebugger); FN(DetachDebuggerEx); FN(GetPEBLocation); FN(IsFileBeingDebugged);
FN(TT_EnterHvMode); FN(TT_LeaveHvMode); FN(TT_HvModeActive); FN(TT_TakeRefusal); FN(TT_ImageBase); FN(TT_LastMessage);
FN(TT_ImageName);

static int g_fail;
static DWORD g_pid;
static PROCESS_INFORMATION g_pi;
static void check(bool ok, const char* what)
{
    printf("%s %s\n", ok ? "  ok  " : "  FAIL", what);
    if(!ok) g_fail++;
}

// drain the refusal queue looking for one of `kind` about `pid` (0 = any pid)
static bool refused(uint32_t kind, DWORD pid, const char* needle = nullptr)
{
    TT_REFUSAL r;
    bool found = false;
    while(p_TT_TakeRefusal(&r))
    {
        printf("        refusal kind %u pid %u tid %u access 0x%X %s\n", r.kind, r.pid, r.tid, r.access, r.what);
        if(r.kind == kind && (!pid || r.pid == pid) && (!needle || strstr(r.what, needle))) found = true;
    }
    return found;
}

static DWORD aThreadOf(DWORD pid)
{
    DWORD tid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);   // system-wide list: no handle on anyone
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    for(BOOL ok = Thread32First(s, &te); ok && !tid; ok = Thread32Next(s, &te))
        if(te.th32OwnerProcessID == pid) tid = te.th32ThreadID;
    CloseHandle(s);
    return tid;
}

static DWORD anotherProcess(DWORD notThis)
{
    DWORD pid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    for(BOOL ok = Process32FirstW(s, &pe); ok && !pid; ok = Process32NextW(s, &pe))
        if(pe.th32ProcessID > 4 && pe.th32ProcessID != notThis && pe.th32ProcessID != GetCurrentProcessId()) pid = pe.th32ProcessID;
    CloseHandle(s);
    return pid;
}

static DWORD WINAPI detachLater(LPVOID)
{
    Sleep(500);
    p_DetachDebuggerEx(g_pid);
    return 0;
}

static void cbCreateProcess(const void*) {}

// runs inside the attach, with the target attached through the hypervisor
static void cbAttach()
{
    printf("attached through the hypervisor (pseudo-handle %p); this exe's Win32 calls go through the shim:\n", g_pi.hProcess);
    HANDLE h = g_pi.hProcess;
    const uint64_t image = p_TT_ImageBase();
    check(GetProcessId(h) == g_pid, "GetProcessId(pseudo-handle) == the pid (routed)");

    unsigned char mz[2] = {};
    SIZE_T n = 0;
    check(ReadProcessMemory(h, reinterpret_cast<LPCVOID>(uintptr_t(image)), mz, 2, &n) && n == 2 && mz[0] == 'M' && mz[1] == 'Z',
          "ReadProcessMemory(pseudo-handle, image) reads 'MZ' through the hypervisor");
    uint32_t lfanew = 0;
    SIZE_T n2 = 0;
    check(NtReadVirtualMemory(h, reinterpret_cast<PVOID>(uintptr_t(image + 0x3C)), &lfanew, 4, &n2) == 0 && n2 == 4 && lfanew && lfanew < 0x1000,
          "NtReadVirtualMemory(pseudo-handle) reads e_lfanew");

    MEMORY_BASIC_INFORMATION mbi = {};
    check(VirtualQueryEx(h, reinterpret_cast<LPCVOID>(uintptr_t(image)), &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT &&
          mbi.Type == MEM_IMAGE && uintptr_t(mbi.AllocationBase) == image, "VirtualQueryEx(image) = committed image region based at the image");
    // a full memory-map walk, as x64dbg's MemUpdateMap does: must terminate and find committed memory
    uintptr_t a = 0x10000;
    int calls = 0, committed = 0, images = 0;
    for(; calls < 2000000; calls++)
    {
        MEMORY_BASIC_INFORMATION m = {};
        if(!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(a), &m, sizeof(m))) break;
        if(m.State == MEM_COMMIT) committed++;
        if(m.Type == MEM_IMAGE && m.State == MEM_COMMIT) images++;
        const uintptr_t next = uintptr_t(m.BaseAddress) + m.RegionSize;
        if(next <= a) { calls = -1; break; }
        a = next;
    }
    printf("        map walk: %d queries, %d committed regions (%d image), ended at %p\n", calls, committed, images, reinterpret_cast<void*>(a));
    check(calls > 0 && committed > 0 && images > 0 && a >= 0x00007FFFFFFF0000ull, "a VirtualQueryEx walk of the whole user space terminates and finds image + private memory");

    wchar_t path[MAX_PATH] = L"";
    const DWORD pl = GetModuleFileNameExW(h, nullptr, path, MAX_PATH);
    wprintf(L"        GetModuleFileNameExW: %ls\n", path);
    check(pl > 3 && path[1] == L':' && wcsstr(path, L"\\") != nullptr, "GetModuleFileNameExW(pseudo-handle) = the exe's DOS path (from the target's loader list)");
    wchar_t nt[MAX_PATH] = L"";
    GetProcessImageFileNameW(h, nt, MAX_PATH);
    wprintf(L"        GetProcessImageFileNameW: %ls\n", nt);
    check(wcsncmp(nt, L"\\Device\\", 8) == 0 && _wcsicmp(wcsrchr(nt, L'\\'), wcsrchr(path, L'\\')) == 0,
          "GetProcessImageFileNameW(pseudo-handle) = the same file as an NT path (no handle)");

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG rl = 0;
    check(NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof(pbi), &rl) == 0 &&
          uintptr_t(pbi.PebBaseAddress) == p_GetPEBLocation(h) && pbi.PebBaseAddress && pbi.UniqueProcessId == g_pid,
          "NtQueryInformationProcess(BasicInformation) = the hypervisor's PEB and the pid");
    BOOL wow = TRUE;
    check(IsWow64Process(h, &wow) && !wow, "IsWow64Process(pseudo-handle) = a 64-bit process");

    // operations that would leave a trace in the target: refused, and reported
    SetLastError(0);
    check(VirtualAllocEx(h, nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE) == nullptr && GetLastError() == ERROR_ACCESS_DENIED,
          "VirtualAllocEx in the target: refused");
    check(refused(TT_REFUSE_SHIM, g_pid, "allocate"), "  ...and reported");
    check(CreateRemoteThread(h, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(uintptr_t(image)), nullptr, 0, nullptr) == nullptr,
          "CreateRemoteThread in the target: refused");
    check(refused(TT_REFUSE_SHIM, g_pid, "thread"), "  ...and reported");
    check(!TerminateProcess(h, 1), "TerminateProcess(target): refused");
    check(refused(TT_REFUSE_SHIM, g_pid, "terminate"), "  ...and reported");
    HANDLE dup = nullptr;
    check(!DuplicateHandle(h, reinterpret_cast<HANDLE>(4), GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS), "DuplicateHandle out of the target: refused");
    check(refused(TT_REFUSE_SHIM, g_pid, "duplicate"), "  ...and reported");
    const DWORD runningTid = aThreadOf(g_pid);
    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, runningTid);
    check(th && GetThreadId(th) == runningTid, "OpenThread(a target thread) while attached = its pseudo-handle (no real handle)");
    check(SuspendThread(th) == DWORD(-1) && GetLastError() == ERROR_ACCESS_DENIED, "SuspendThread(a running target thread): refused");
    check(!refused(TT_REFUSE_SHIM, g_pid, "suspend"), "  ...quietly (x64dbg's internal register probe; its suspend commands explain)");
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if(GetThreadContext(th, &ctx))
    {
        unsigned char site[2] = {};
        SIZE_T n3 = 0;
        check(ctx.Rip && ReadProcessMemory(h, reinterpret_cast<LPCVOID>(uintptr_t(ctx.Rip - 2)), site, 2, &n3) && site[0] == 0x0F && site[1] == 0x05,
              "GetThreadContext(a waiting thread) = its trap frame: RIP right after a syscall");
    }
    else
        check(GetLastError() == ERROR_ACCESS_DENIED, "GetThreadContext(a running thread): refused, no registers invented");
    check(CloseHandle(th), "CloseHandle(thread pseudo-handle)");
    HANDLE again = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_pid);
    check(again && GetProcessId(again) == g_pid && (uintptr_t(again) & ~uintptr_t(0x00FFFFFF)) == 0x7E000000u,
          "OpenProcess(target) while attached = its pseudo-handle (no real handle)");
    check(CloseHandle(again), "CloseHandle(process pseudo-handle)");
    CreateThread(nullptr, 0, detachLater, nullptr, 0, nullptr);
}

int wmain(int argc, wchar_t** argv)
{
    if(argc < 3) { fwprintf(stderr, L"usage: %ls <TitanTuring.dll> <pid>\n", argv[0]); return 2; }
    HMODULE m = LoadLibraryW(argv[1]);
    if(!m) { printf("FAIL: cannot load %ls (%lu)\n", argv[1], GetLastError()); return 1; }
#define GET(name) p_##name = reinterpret_cast<decltype(p_##name)>(GetProcAddress(m, #name)); if(!p_##name) { printf("FAIL: export %s missing\n", #name); return 1; }
    GET(SetCustomHandler) GET(AttachDebugger) GET(DetachDebuggerEx) GET(GetPEBLocation) GET(IsFileBeingDebugged)
    GET(TT_EnterHvMode) GET(TT_LeaveHvMode) GET(TT_HvModeActive) GET(TT_TakeRefusal) GET(TT_ImageBase) GET(TT_LastMessage)
    GET(TT_ImageName)
    g_pid = DWORD(_wtoi(argv[2]));

    printf("A. before HV Mode\n");
    HANDLE ctl = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
    check(ctl != nullptr, "control: the target CAN be opened outside HV Mode (so a refusal below is the guard's doing)");
    if(ctl) CloseHandle(ctl);
    PROCESS_INFORMATION pi0 = {};
    check(!p_AttachDebugger(g_pid, false, &pi0, nullptr), "attach without HV Mode's guard: refused (fail closed)");
    printf("        %s\n", p_TT_LastMessage());

    printf("B. enter HV Mode (this exe's imports routed)\n");
    HMODULE self = GetModuleHandleW(nullptr);
    char why[512] = "";
    const bool entered = p_TT_EnterHvMode(&self, 1, why, sizeof(why));
    if(!entered) printf("        %s\n", why);
    check(entered && p_TT_HvModeActive(), "TT_EnterHvMode: the guard installed and active");
    SetLastError(0);
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
    check(!hp && GetLastError() == ERROR_ACCESS_DENIED, "OpenProcess(target) in HV Mode: refused");
    check(refused(TT_REFUSE_OPEN_PROCESS, g_pid), "  ...and reported (open process, the target's pid)");
    const DWORD tid = aThreadOf(g_pid);
    HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    check(tid && !ht, "OpenThread(a target thread) in HV Mode: refused");
    check(refused(TT_REFUSE_OPEN_THREAD, g_pid), "  ...and reported (open thread, owner = the target)");
    // ntdll directly (not through this exe's import table): the guard is in ntdll itself
    typedef NTSTATUS(NTAPI * NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
    auto ntOpen = reinterpret_cast<NtOpenProcess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess"));
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    CLIENT_ID cid = {};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(uintptr_t(g_pid));
    HANDLE hn = nullptr;
    check(ntOpen(&hn, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) == NTSTATUS(0xC0000022L) && !hn,
          "ntdll!NtOpenProcess called directly (bypassing any import table): STATUS_ACCESS_DENIED");
    refused(TT_REFUSE_OPEN_PROCESS, g_pid);
    const DWORD other = anotherProcess(g_pid);
    check(other && !OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, other), "OpenProcess(any OTHER process) in HV Mode: refused too");
    refused(TT_REFUSE_OPEN_PROCESS, other);
    HANDLE me = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    check(me != nullptr, "OpenProcess(ourselves) in HV Mode: allowed");
    if(me) CloseHandle(me);
    check(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, g_pid) == INVALID_HANDLE_VALUE, "a toolhelp MODULE snapshot of the target: refused");
    check(refused(TT_REFUSE_SHIM, g_pid, "toolhelp"), "  ...and reported");

    printf("C. attach through the hypervisor\n");
    p_SetCustomHandler(UE_CH_CREATEPROCESS, cbCreateProcess);
    const bool ok = p_AttachDebugger(g_pid, false, &g_pi, cbAttach);
    if(!ok) printf("        AttachDebugger failed: %s\n", p_TT_LastMessage());
    check(ok, "AttachDebugger (returns after the detach)");
    check(!p_IsFileBeingDebugged(), "detached");

    printf("D. leave HV Mode\n");
    check(p_TT_LeaveHvMode(why, sizeof(why)) && !p_TT_HvModeActive(), "TT_LeaveHvMode");
    HANDLE after = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
    check(after != nullptr, "OpenProcess(target) works again outside HV Mode -- and the target is still alive");
    if(after)
    {
        DWORD code = 0;
        check(GetExitCodeProcess(after, &code) && code == STILL_ACTIVE, "  ...still running (TerminateProcess above really was refused)");
        CloseHandle(after);
    }
    printf(g_fail ? "hvmode_test: FAIL (%d)\n" : "hvmode_test: PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
