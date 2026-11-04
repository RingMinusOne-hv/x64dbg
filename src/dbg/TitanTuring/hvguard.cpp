// hvguard.cpp -- HV Mode's guard.
//
// While HV Mode is on, x64dbg's process must obtain NO handle to any other process or thread. A handle is the first
// thing every classic debugger interaction needs (ReadProcessMemory, DebugActiveProcess, CreateRemoteThread,
// SuspendThread, VirtualAllocEx, ...), and creating the handle is itself what the target's side can observe: a kernel
// driver's ObRegisterCallbacks sees it, and a user-mode scan of the system handle table finds it. So the guard sits
// where every such handle is created -- the system calls:
//   NtOpenProcess     (OpenProcess, and everything built on it: toolhelp module/heap snapshots, psapi, dbghelp)
//   NtOpenThread      (OpenThread)
//   NtGetNextProcess  (walks every process, handing back a handle to each)
// NtDuplicateObject, NtGetNextThread, NtDebugActiveProcess, NtCreateThreadEx and NtReadVirtualMemory all need a
// process handle first, and none can exist, so the guard covers them without hooking them.
//
// The hooks are in x64dbg.exe's OWN copy of ntdll -- nothing in the target is touched -- which covers every module of
// our process at once: x64dbg.dll, the GUI, plugins, dbghelp, Qt. The only process we may open is our own.
//
// Mechanism (x64). Each hooked export is a Windows system-call stub:
//     4C 8B D1                  mov r10, rcx
//     B8 nn nn 00 00            mov eax, <service number>
//     F6 04 25 08 03 FE 7F 01   test byte ptr [7FFE0308h], 1
//     75 03 0F 05 C3            jne +3 / syscall / ret
// We verify exactly those bytes (anything else, e.g. another product's hook, refuses the install: fail closed), then
// replace the first 8 bytes in ONE atomic 8-byte store with `jmp rel32` to a relay page near ntdll. The relay jumps to
// our C++ hook; the trampoline that calls the original re-executes the two covered instructions and jumps back to
// ntdll+8, so the real system call still runs from inside ntdll. Other threads are suspended during the store; a thread
// caught between the two covered instructions is moved to the same spot in the trampoline.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "hvguard.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <atomic>
#include <cstring>
#include <cstdio>

#pragma intrinsic(_ReturnAddress)

namespace
{
    constexpr NTSTATUS ST_ACCESS_DENIED = NTSTATUS(0xC0000022L);
    constexpr NTSTATUS ST_ACCESS_VIOLATION = NTSTATUS(0xC0000005L);
    constexpr NTSTATUS ST_INFO_LENGTH_MISMATCH = NTSTATUS(0xC0000004L);

    typedef NTSTATUS(NTAPI* NtOpen_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
    typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    typedef NTSTATUS(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

    NtOpen_t realOpenProcess = nullptr, realOpenThread = nullptr;
    NtGetNextProcess_t realGetNextProcess = nullptr;
    NtQSI_t ntQSI = nullptr;

    std::atomic<bool> g_installed{false}, g_active{false};
    DWORD g_self = 0;
    SRWLOCK g_installLock = SRWLOCK_INIT;

    // ---- the refusal queue: many producers (any thread inside a hook), one consumer (x64dbg's watcher). A tiny spin
    // lock -- no system call, no heap, no CRT locks inside -- because a hook can run in any context.
    constexpr uint32_t QN = 128;
    TT_REFUSAL g_q[QN];
    uint32_t g_qHead = 0, g_qCount = 0;
    std::atomic<uint32_t> g_dropped{0};
    std::atomic_flag g_qLock = ATOMIC_FLAG_INIT;
    struct QGuard
    {
        QGuard() { while(g_qLock.test_and_set(std::memory_order_acquire)) YieldProcessor(); }
        ~QGuard() { g_qLock.clear(std::memory_order_release); }
    };

    bool allowedPid(DWORD pid) { return pid == g_self; }

    // The system's process list -> the process owning `tid` (0 = not found). A system-wide query: no handle opened.
    // SYSTEM_PROCESS_INFORMATION is 0x100 bytes on x64 (UniqueProcessId at +0x50), followed by its threads, 0x50 bytes
    // each (ClientId.UniqueThread at +0x30). Install() checks this parse against our own thread before trusting it.
    DWORD ownerOf(DWORD tid)
    {
        if(!ntQSI) return 0;
        SIZE_T size = 1u << 20;
        for(int attempt = 0; attempt < 6; attempt++, size *= 2)
        {
            auto* buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if(!buf) return 0;
            ULONG need = 0;
            const NTSTATUS st = ntQSI(5 /* SystemProcessInformation */, buf, ULONG(size), &need);
            if(st == ST_INFO_LENGTH_MISMATCH)
            {
                VirtualFree(buf, 0, MEM_RELEASE);
                continue;
            }
            DWORD owner = 0;
            if(st >= 0)
                for(uint8_t* p = buf; owner == 0;)
                {
                    const ULONG next = *reinterpret_cast<ULONG*>(p);
                    const ULONG nthreads = *reinterpret_cast<ULONG*>(p + 4);
                    const DWORD pid = DWORD(*reinterpret_cast<ULONG_PTR*>(p + 0x50));
                    const uint8_t* th = p + 0x100;
                    for(ULONG i = 0; i < nthreads; i++)
                        if(DWORD(*reinterpret_cast<const ULONG_PTR*>(th + i * 0x50 + 0x30)) == tid) { owner = pid; break; }
                    if(!next) break;
                    p += next;
                }
            VirtualFree(buf, 0, MEM_RELEASE);
            return owner;
        }
        return 0;
    }

    void record(uint32_t kind, uint32_t pid, uint32_t tid, uint32_t access, uint64_t caller, const char* what)
    {
        QGuard g;
        if(g_qCount == QN)
        {
            g_dropped.fetch_add(1);
            return;
        }
        TT_REFUSAL& r = g_q[(g_qHead + g_qCount) % QN];
        r.kind = kind;
        r.pid = pid;
        r.tid = tid;
        r.access = access;
        r.caller = caller;
        size_t i = 0;
        if(what)
            for(; what[i] && i + 1 < sizeof(r.what); i++) r.what[i] = what[i];
        r.what[i] = 0;
        g_qCount++;
    }

    // ---- the hooks: compare and forward; nothing that can block ----
    NTSTATUS NTAPI hkOpenProcess(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid)
    {
        if(g_active.load(std::memory_order_acquire))
        {
            DWORD pid = 0;
            __try
            {
                if(cid) pid = DWORD(ULONG_PTR(cid->UniqueProcess));
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return ST_ACCESS_VIOLATION;
            }
            if(!cid || !allowedPid(pid))
            {
                record(TT_REFUSE_OPEN_PROCESS, pid, 0, access, uint64_t(_ReturnAddress()), nullptr);
                return ST_ACCESS_DENIED;
            }
        }
        return realOpenProcess(h, access, oa, cid);
    }

    NTSTATUS NTAPI hkOpenThread(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid)
    {
        if(g_active.load(std::memory_order_acquire))
        {
            DWORD pid = 0, tid = 0;
            __try
            {
                if(cid)
                {
                    pid = DWORD(ULONG_PTR(cid->UniqueProcess));
                    tid = DWORD(ULONG_PTR(cid->UniqueThread));
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return ST_ACCESS_VIOLATION;
            }
            // a process named in the CLIENT_ID is checked by the kernel against the thread (a mismatch fails the
            // open), so it can be trusted here; otherwise look the thread's owner up
            const DWORD owner = !cid ? 0 : tid == GetCurrentThreadId() ? g_self : pid ? pid : ownerOf(tid);
            if(!allowedPid(owner))
            {
                record(TT_REFUSE_OPEN_THREAD, owner, tid, access, uint64_t(_ReturnAddress()), nullptr);
                return ST_ACCESS_DENIED;
            }
        }
        return realOpenThread(h, access, oa, cid);
    }

    NTSTATUS NTAPI hkGetNextProcess(HANDLE h, ACCESS_MASK access, ULONG attr, ULONG flags, PHANDLE out)
    {
        if(g_active.load(std::memory_order_acquire))
        {
            record(TT_REFUSE_NEXT_PROCESS, 0, 0, access, uint64_t(_ReturnAddress()), nullptr);
            return ST_ACCESS_DENIED;
        }
        return realGetNextProcess(h, access, attr, flags, out);
    }

    // ---- install ----
    bool stubOk(const uint8_t* p)
    {
        static const uint8_t tail[13] = {0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3};
        return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8 && p[6] == 0x00 && p[7] == 0x00 &&
               memcmp(p + 8, tail, sizeof(tail)) == 0;
    }

    // a page within +-2 GiB of `anchor` (a rel32 jump from ntdll must reach it), below first then above.
    // (Not named `near`: windef.h defines `near` as an empty macro, which turned the parameter into 0.)
    uint8_t* allocNear(const uint8_t* anchor, size_t size)
    {
        const uintptr_t gran = 0x10000;
        const uintptr_t base = uintptr_t(anchor) & ~(gran - 1);
        for(uintptr_t d = gran; d < 0x70000000u; d += gran)
        {
            if(d < base)
                if(void* p = VirtualAlloc(reinterpret_cast<void*>(base - d), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
                    return static_cast<uint8_t*>(p);
            if(void* p = VirtualAlloc(reinterpret_cast<void*>(base + d), size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
                return static_cast<uint8_t*>(p);
        }
        return nullptr;
    }

    bool fail(char* why, size_t n, const char* text)
    {
        if(why && n) snprintf(why, n, "%s", text);
        return false;
    }

    // our other threads, opened before any is suspended: between suspend and resume nothing may touch the heap (a
    // suspended thread may hold its lock)
    constexpr int MAXTH = 4096;
    HANDLE g_th[MAXTH];
    int g_nth = 0;

    void openOthers()
    {
        g_nth = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);   // system-wide: no handle on anyone
        if(snap == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        for(BOOL ok = Thread32First(snap, &te); ok && g_nth < MAXTH; ok = Thread32Next(snap, &te))
            if(te.th32OwnerProcessID == g_self && te.th32ThreadID != GetCurrentThreadId())
                if(HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID))
                    g_th[g_nth++] = h;
        CloseHandle(snap);
    }
}

namespace hvguard
{
    bool Installed() { return g_installed.load(); }
    void SetActive(bool on) { g_active.store(on && g_installed.load(), std::memory_order_release); }
    bool Active() { return g_active.load(std::memory_order_acquire); }
    void Record(uint32_t kind, uint32_t pid, uint32_t tid, uint32_t access, uint64_t caller, const char* what)
    {
        record(kind, pid, tid, access, caller, what);
    }
    bool Take(TT_REFUSAL* out)
    {
        QGuard g;
        if(!g_qCount) return false;
        *out = g_q[g_qHead];
        g_qHead = (g_qHead + 1) % QN;
        g_qCount--;
        return true;
    }
    uint32_t Dropped() { return g_dropped.load(); }
    DWORD OwnerOfThread(DWORD tid) { return ownerOf(tid); }

    bool Install(char* why, size_t whyLen)
    {
#ifndef _WIN64
        return fail(why, whyLen, "HV Mode's guard is x64 only");
#else
        AcquireSRWLockExclusive(&g_installLock);
        struct Unlock { ~Unlock() { ReleaseSRWLockExclusive(&g_installLock); } } unlock;
        if(g_installed.load()) return true;

        g_self = GetCurrentProcessId();
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        ntQSI = reinterpret_cast<NtQSI_t>(GetProcAddress(nt, "NtQuerySystemInformation"));
        if(!ntQSI || ownerOf(GetCurrentThreadId()) != g_self)
            return fail(why, whyLen, "cannot read the system's thread list (SystemProcessInformation layout?)");

        struct Spec { const char* name; void* hook; void** real; uint8_t* target; };
        Spec specs[] = {
            {"NtOpenProcess", reinterpret_cast<void*>(&hkOpenProcess), reinterpret_cast<void**>(&realOpenProcess), nullptr},
            {"NtOpenThread", reinterpret_cast<void*>(&hkOpenThread), reinterpret_cast<void**>(&realOpenThread), nullptr},
            {"NtGetNextProcess", reinterpret_cast<void*>(&hkGetNextProcess), reinterpret_cast<void**>(&realGetNextProcess), nullptr},
        };
        char msg[256];
        for(auto& s : specs)
        {
            s.target = reinterpret_cast<uint8_t*>(GetProcAddress(nt, s.name));
            if(!s.target)
            {
                snprintf(msg, sizeof(msg), "ntdll has no %s", s.name);
                return fail(why, whyLen, msg);
            }
            if((uintptr_t(s.target) & 7) != 0 || !stubOk(s.target))
            {
                const uint8_t* b = s.target;
                snprintf(msg, sizeof(msg), "ntdll!%s is not the plain system-call stub the guard verifies (starts %02X %02X %02X %02X %02X %02X %02X %02X)"
                         " -- another program may have patched it", s.name, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
                return fail(why, whyLen, msg);
            }
        }

        uint8_t* page = allocNear(specs[0].target, 4096);
        if(!page) return fail(why, whyLen, "no free page within 2 GiB of ntdll for the guard's relays");
        int64_t rel[3];
        for(int i = 0; i < 3; i++)
        {
            uint8_t* relay = page + i * 64;
            uint8_t* tramp = relay + 16;
            const uint64_t hook = uint64_t(specs[i].hook), back = uint64_t(specs[i].target + 8);
            // relay: jmp qword ptr [rip+0] ; <hook>
            relay[0] = 0xFF; relay[1] = 0x25; memset(relay + 2, 0, 4); memcpy(relay + 6, &hook, 8);
            // trampoline: the 8 covered bytes, then jmp qword ptr [rip+0] ; <target+8>
            memcpy(tramp, specs[i].target, 8);
            tramp[8] = 0xFF; tramp[9] = 0x25; memset(tramp + 10, 0, 4); memcpy(tramp + 14, &back, 8);
            rel[i] = int64_t(relay) - int64_t(specs[i].target + 5);
            if(rel[i] < INT32_MIN || rel[i] > INT32_MAX)
            {
                snprintf(msg, sizeof(msg), "the guard's relay page %p is out of rel32 reach of ntdll!%s at %p (distance %lld)",
                         static_cast<void*>(relay), specs[i].name, static_cast<void*>(specs[i].target), static_cast<long long>(rel[i]));
                return fail(why, whyLen, msg);
            }
        }
        DWORD old = 0;
        VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), page, 4096);
        for(int i = 0; i < 3; i++) *specs[i].real = page + i * 64 + 16;

        // the store, with every other thread of ours suspended
        openOthers();
        for(int k = 0; k < g_nth; k++) SuspendThread(g_th[k]);
        for(int i = 0; i < 3; i++)
        {
            uint8_t* t = specs[i].target;
            uint8_t* tramp = page + i * 64 + 16;
            for(int k = 0; k < g_nth; k++)
            {
                CONTEXT c = {};
                c.ContextFlags = CONTEXT_CONTROL;
                if(GetThreadContext(g_th[k], &c) && c.Rip > uintptr_t(t) && c.Rip < uintptr_t(t) + 8)
                {
                    c.Rip = uintptr_t(tramp) + (c.Rip - uintptr_t(t));   // the same instruction, in the trampoline
                    SetThreadContext(g_th[k], &c);
                }
            }
            uint8_t patch[8] = {0xE9, 0, 0, 0, 0, 0xCC, 0xCC, 0xCC};
            const int32_t r32 = int32_t(rel[i]);
            memcpy(patch + 1, &r32, 4);
            uint64_t v;
            memcpy(&v, patch, 8);
            DWORD prot = 0;
            VirtualProtect(t, 8, PAGE_EXECUTE_READWRITE, &prot);
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(t), LONG64(v));
            VirtualProtect(t, 8, prot, &prot);
        }
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
        for(int k = 0; k < g_nth; k++)
        {
            ResumeThread(g_th[k]);
            CloseHandle(g_th[k]);
        }
        g_nth = 0;

        // pin this DLL: the hooks now point into it, so it must never unload
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&hkOpenProcess), &self);

        // proof the trampolines work (the hooks are live but not refusing yet): opening ourselves goes
        // hook -> trampoline -> kernel. A failure leaves g_installed false, so HV Mode can never turn on.
        HANDLE hs = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_self);
        if(!hs) return fail(why, whyLen, "the guard's trampoline failed its self-test (OpenProcess on ourselves)");
        CloseHandle(hs);
        g_installed.store(true);
        return true;
#endif
    }
}
