// shim.cpp -- the Win32 shim: x64dbg's ~70 direct Windows calls about the debuggee, answered by the hypervisor.
//
// x64dbg.dll doesn't only talk to its engine: it also calls ReadProcessMemory, VirtualQueryEx, GetThreadContext,
// SuspendThread, NtQueryInformationProcess, ... directly with the handles the engine gave it. Our engine gives it
// PSEUDO-handles (no real handle to the game exists), so those calls are redirected here: at HV Mode entry the import
// table entries of x64dbg.dll (and of dbghelp.dll, which reads memory for stack walks) are pointed at these functions.
//   - a real handle      -> the real Windows function, unchanged
//   - a pseudo-handle    -> answered from the hypervisor (memory, regions, PEB/TEB, module paths, the stopped thread's
//                           registers) or REFUSED with a reason, when the operation would leave a trace in the target
//                           (allocate/protect/free its memory, create a thread in it, suspend/terminate/kill it, post
//                           it a window message, duplicate its handles)
// Refusals are queued with the guard's, so x64dbg reports them all the same way.
// No call site in x64dbg changes: the routing is the import table, set once (PORT-TURINGHV.md "Two layers").
#define TURINGHV_STATIC 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "../TitanEngine/TitanEngine.h"
#include "TitanTuring.h"
#include "hvguard.h"

#pragma intrinsic(_ReturnAddress)

namespace
{
    constexpr NTSTATUS ST_SUCCESS = 0;
    constexpr NTSTATUS ST_PARTIAL_COPY = NTSTATUS(0x8000000DL);
    constexpr NTSTATUS ST_ACCESS_DENIED = NTSTATUS(0xC0000022L);
    constexpr NTSTATUS ST_NOT_SUPPORTED = NTSTATUS(0xC00000BBL);
    constexpr NTSTATUS ST_INFO_LENGTH_MISMATCH = NTSTATUS(0xC0000004L);
    constexpr NTSTATUS ST_PENDING = NTSTATUS(0x00000103L);
    constexpr uint64_t USER_MIN = 0x10000, USER_END = 0x00007FFFFFFF0000ull;
    constexpr uint32_t REGION_USER = 1u << 3;          // THV_MEMORY_USER

    // ------------------------------------------------------------------------------------------ originals
    typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* NtQIT_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* NtRVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* NtQVM_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* NtProc_t)(HANDLE);
    typedef NTSTATUS(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

#define ORIG(fn) decltype(&::fn) o_##fn = nullptr
    ORIG(CloseHandle); ORIG(WaitForSingleObject); ORIG(ReadProcessMemory); ORIG(WriteProcessMemory);
    ORIG(VirtualQueryEx); ORIG(VirtualAllocEx); ORIG(VirtualFreeEx); ORIG(VirtualProtectEx); ORIG(IsWow64Process);
    ORIG(GetProcessId); ORIG(GetThreadId); ORIG(SuspendThread); ORIG(ResumeThread); ORIG(GetThreadContext);
    ORIG(SetThreadContext); ORIG(Wow64GetThreadContext); ORIG(TerminateThread); ORIG(TerminateProcess);
    ORIG(OpenProcess); ORIG(OpenThread); ORIG(DuplicateHandle); ORIG(CreateRemoteThread); ORIG(CreateRemoteThreadEx);
    ORIG(DebugBreakProcess); ORIG(GetThreadTimes); ORIG(GetThreadPriority); ORIG(SetThreadPriority);
    ORIG(CreateToolhelp32Snapshot); ORIG(GetExitCodeProcess); ORIG(GetExitCodeThread); ORIG(FlushInstructionCache);
    ORIG(K32GetModuleFileNameExW); ORIG(K32GetProcessImageFileNameW); ORIG(K32GetMappedFileNameW);
    ORIG(CheckRemoteDebuggerPresent); ORIG(DebugActiveProcess); ORIG(DebugActiveProcessStop); ORIG(OpenProcessToken);
    ORIG(PostThreadMessageA); ORIG(PostThreadMessageW);
#undef ORIG
    NtQIP_t o_NtQueryInformationProcess = nullptr;
    NtQIT_t o_NtQueryInformationThread = nullptr;
    NtRVM_t o_NtReadVirtualMemory = nullptr, o_NtWriteVirtualMemory = nullptr;
    NtQVM_t o_NtQueryVirtualMemory = nullptr;
    NtProc_t o_NtSuspendProcess = nullptr, o_NtResumeProcess = nullptr;
    NtQSI_t ntQSI = nullptr;

    // ------------------------------------------------------------------------------------------ helpers
    inline DWORD phPid(HANDLE h) { return TT_PseudoPid(h); }            // any process pseudo-handle (bit test)
    inline bool isPH(HANDLE h) { return phPid(h) != 0; }
    inline bool isTPH(HANDLE h) { return TT_IsTargetThread(h); }       // a thread pseudo-handle (bit test)

    // one refusal -> the guard's queue (identical refusals within 5 s are reported once: x64dbg retries in loops)
    void note(DWORD pid, const char* what, void* caller)
    {
        static SRWLOCK lk = SRWLOCK_INIT;
        static char last[96];
        static ULONGLONG lastTick;
        AcquireSRWLockExclusive(&lk);
        const ULONGLONG now = GetTickCount64();
        const bool dup = strcmp(last, what) == 0 && now - lastTick < 5000;
        if(!dup)
        {
            strncpy_s(last, what, _TRUNCATE);
            lastTick = now;
        }
        ReleaseSRWLockExclusive(&lk);
        if(!dup) hvguard::Record(TT_REFUSE_SHIM, pid, 0, 0, uint64_t(caller), what);
    }
#define REFUSE(pid, what) (note((pid), (what), _ReturnAddress()), SetLastError(ERROR_ACCESS_DENIED))

    // ---- the target's region map, as VirtualQueryEx would describe it, from the hypervisor's page-table walk ----
    struct RegionCache
    {
        std::mutex m;
        std::vector<TT_REGION> rg;     // user regions, sorted by base
        std::vector<TT_MODULE> mods;   // sorted by base
        struct Sec { uint64_t start, end; DWORD protect; };
        std::map<uint64_t, std::vector<Sec>> secs;   // module base -> header + sections (from its PE headers)
        ULONGLONG at = 0;
    } g_rc;

    void refreshRegions()
    {
        std::vector<TT_REGION> rg(16384);
        DWORD n = 0;
        for(int tries = 0; tries < 4; tries++)
        {
            if(!TT_TargetRegions(rg.data(), DWORD(rg.size()), &n)) { n = 0; break; }
            if(n <= rg.size()) break;
            rg.resize(n + 1024);
        }
        rg.resize(std::min<size_t>(n, rg.size()));
        rg.erase(std::remove_if(rg.begin(), rg.end(), [](const TT_REGION& r) { return !(r.flags & REGION_USER) || r.base >= USER_END; }), rg.end());
        std::sort(rg.begin(), rg.end(), [](const TT_REGION& a, const TT_REGION& b) { return a.base < b.base; });
        std::vector<TT_MODULE> mods(1024);
        DWORD nm = 0;
        if(TT_TargetModules(mods.data(), DWORD(mods.size()), &nm) && nm > mods.size())
        {
            mods.resize(nm + 64);
            TT_TargetModules(mods.data(), DWORD(mods.size()), &nm);
        }
        mods.resize(std::min<size_t>(nm, mods.size()));
        std::sort(mods.begin(), mods.end(), [](const TT_MODULE& a, const TT_MODULE& b) { return a.base < b.base; });
        g_rc.rg.swap(rg);
        g_rc.mods.swap(mods);
        g_rc.secs.clear();
        g_rc.at = GetTickCount64();
    }

    // Windows' protection for an image section that isn't resident (what VirtualQuery reports from the section object)
    DWORD sectionProtect(DWORD ch)
    {
        const bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0, w = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        return x ? (w ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE_READ) : (w ? PAGE_WRITECOPY : PAGE_READONLY);
    }

    // a module's header page + sections, read once per refresh through the hypervisor from the module's own PE headers
    const std::vector<RegionCache::Sec>& moduleSections(HANDLE h, const TT_MODULE& m)
    {
        auto found = g_rc.secs.find(m.base);
        if(found != g_rc.secs.end()) return found->second;
        std::vector<RegionCache::Sec> out;
        uint8_t hdr[0x1000];
        SIZE_T got = 0;
        if(MemoryReadSafe(h, reinterpret_cast<LPVOID>(uintptr_t(m.base)), hdr, sizeof(hdr), &got) && got == sizeof(hdr) && hdr[0] == 'M' && hdr[1] == 'Z')
        {
            const uint32_t lfanew = *reinterpret_cast<uint32_t*>(hdr + 0x3C);
            if(lfanew >= 0x40 && lfanew + 24 < sizeof(hdr) && *reinterpret_cast<uint32_t*>(hdr + lfanew) == IMAGE_NT_SIGNATURE)
            {
                const uint16_t nsec = *reinterpret_cast<uint16_t*>(hdr + lfanew + 4 + 2);
                const uint16_t optSize = *reinterpret_cast<uint16_t*>(hdr + lfanew + 4 + 16);
                const uint32_t table = lfanew + 4 + 20 + optSize;
                out.push_back({m.base, m.base + 0x1000, PAGE_READONLY});   // the headers
                for(uint32_t i = 0; i < nsec && table + (i + 1) * 40 <= sizeof(hdr); i++)
                {
                    const uint8_t* sh = hdr + table + i * 40;
                    const uint32_t vsize = *reinterpret_cast<const uint32_t*>(sh + 8), rva = *reinterpret_cast<const uint32_t*>(sh + 12);
                    const uint32_t ch = *reinterpret_cast<const uint32_t*>(sh + 36);
                    if(!vsize || !rva) continue;
                    const uint64_t start = m.base + rva, end = (m.base + rva + vsize + 0xFFF) & ~uint64_t(0xFFF);
                    if(end > m.base + m.size || start < m.base + 0x1000) continue;
                    out.push_back({start, end, sectionProtect(ch)});
                }
            }
        }
        return g_rc.secs.emplace(m.base, std::move(out)).first->second;
    }

    DWORD protectOf(uint32_t flags)
    {
        const bool w = (flags & 2) != 0, x = (flags & 4) != 0;
        return x ? (w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : (w ? PAGE_READWRITE : PAGE_READONLY);
    }

    // VirtualQueryEx for the target. Outside modules: a present run is committed private memory; a gap is free (the
    // hypervisor sees page tables, not VADs: committed-but-never-touched memory isn't visible). Inside a module the
    // whole image is committed, as Windows reports it whether or not a page is resident: a resident page has the
    // protection its page tables give it, a non-resident page its section's. One AllocationBase per image keeps x64dbg's
    // map merging the module into one entry before it splits it into sections.
    SIZE_T queryRegion(HANDLE h, uint64_t addr, MEMORY_BASIC_INFORMATION* mbi)
    {
        const uint64_t a = addr & ~uint64_t(0xFFF);
        if(a >= USER_END) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        std::lock_guard<std::mutex> g(g_rc.m);
        // a map walk starts low: refresh then, or when the cache is a second old
        if(g_rc.rg.empty() || a <= USER_MIN || GetTickCount64() - g_rc.at > 1000) refreshRegions();
        auto& rg = g_rc.rg;
        auto it = std::upper_bound(rg.begin(), rg.end(), a, [](uint64_t v, const TT_REGION& r) { return v < r.base + r.size; });
        const bool present = it != rg.end() && it->base <= a;
        const TT_MODULE* mod = nullptr;
        uint64_t nextMod = USER_END;
        for(auto& m : g_rc.mods)
        {
            if(a >= m.base && a < m.base + m.size) { mod = &m; break; }
            if(m.base > a) { nextMod = m.base; break; }
        }
        memset(mbi, 0, sizeof(*mbi));
        mbi->BaseAddress = reinterpret_cast<PVOID>(uintptr_t(a));
        if(mod)
        {
            uint64_t end = mod->base + mod->size;
            DWORD prot = PAGE_READONLY;
            for(auto& sec : moduleSections(h, *mod))
            {
                if(a >= sec.start && a < sec.end) { end = std::min(end, sec.end); prot = sec.protect; break; }
                if(sec.start > a) end = std::min(end, sec.start);
            }
            if(present)
            {
                prot = protectOf(it->flags);
                end = std::min(end, it->base + it->size);
            }
            else if(it != rg.end())
                end = std::min(end, it->base);
            mbi->AllocationBase = reinterpret_cast<PVOID>(uintptr_t(mod->base));
            mbi->AllocationProtect = PAGE_EXECUTE_WRITECOPY;
            mbi->RegionSize = SIZE_T(end - a);
            mbi->State = MEM_COMMIT;
            mbi->Protect = prot;
            mbi->Type = MEM_IMAGE;
        }
        else if(present)
        {
            const uint64_t end = std::min(it->base + it->size, nextMod);
            const DWORD prot = protectOf(it->flags);
            mbi->AllocationBase = reinterpret_cast<PVOID>(uintptr_t(it->base));
            mbi->AllocationProtect = prot;
            mbi->RegionSize = SIZE_T(end - a);
            mbi->State = MEM_COMMIT;
            mbi->Protect = prot;
            mbi->Type = MEM_PRIVATE;
        }
        else
        {
            const uint64_t next = std::min(it != rg.end() ? it->base : USER_END, nextMod);
            mbi->RegionSize = SIZE_T(next - a);
            mbi->State = MEM_FREE;
            mbi->Protect = PAGE_NOACCESS;
        }
        return sizeof(MEMORY_BASIC_INFORMATION);
    }

    // the stopped thread's fake suspend count: x64dbg suspends "the active thread" around stack walks; the parked
    // thread is already stopped, so only the count is kept (nothing is done to the real thread)
    std::mutex g_suspM;
    std::map<DWORD, DWORD> g_susp;

    bool isOwnThread(DWORD tid) { return tid == GetCurrentThreadId() || hvguard::OwnerOfThread(tid) == GetCurrentProcessId(); }

    // ------------------------------------------------------------------------------------------ the shims
    BOOL WINAPI sh_CloseHandle(HANDLE h)
    {
        if(isPH(h) || isTPH(h)) return TRUE;
        return o_CloseHandle(h);
    }

    DWORD WINAPI sh_WaitForSingleObject(HANDLE h, DWORD ms)
    {
        if(!isPH(h) && !isTPH(h)) return o_WaitForSingleObject(h, ms);
        if(isPH(h) && !TT_IsTargetPseudo(h)) { SetLastError(ERROR_INVALID_HANDLE); return WAIT_FAILED; }
        const ULONGLONG start = GetTickCount64();
        for(;;)
        {
            const bool alive = isPH(h) ? TT_TargetAlive() : TT_IsTargetTid(TT_ThreadIdOf(h));
            if(!alive) return WAIT_OBJECT_0;
            const ULONGLONG gone = GetTickCount64() - start;
            if(ms != INFINITE && gone >= ms) return WAIT_TIMEOUT;
            Sleep(ms == INFINITE ? 50 : DWORD(std::min<ULONGLONG>(50, ms - gone)));
        }
    }

    BOOL WINAPI sh_ReadProcessMemory(HANDLE h, LPCVOID a, LPVOID b, SIZE_T n, SIZE_T* done)
    {
        if(!isPH(h)) return o_ReadProcessMemory(h, a, b, n, done);
        if(MemoryReadSafe(h, const_cast<LPVOID>(a), b, n, done)) return TRUE;
        SetLastError(ERROR_PARTIAL_COPY);
        return FALSE;
    }

    BOOL WINAPI sh_WriteProcessMemory(HANDLE h, LPVOID a, LPCVOID b, SIZE_T n, SIZE_T* done)
    {
        if(!isPH(h)) return o_WriteProcessMemory(h, a, b, n, done);
        if(MemoryWriteSafe(h, a, b, n, done)) return TRUE;
        SetLastError(ERROR_PARTIAL_COPY);
        return FALSE;
    }

    NTSTATUS NTAPI sh_NtReadVirtualMemory(HANDLE h, PVOID a, PVOID b, SIZE_T n, PSIZE_T done)
    {
        if(!isPH(h)) return o_NtReadVirtualMemory(h, a, b, n, done);
        SIZE_T d = 0;
        const bool ok = MemoryReadSafe(h, a, b, n, &d);
        if(done) *done = d;
        return ok ? ST_SUCCESS : ST_PARTIAL_COPY;
    }

    NTSTATUS NTAPI sh_NtWriteVirtualMemory(HANDLE h, PVOID a, PVOID b, SIZE_T n, PSIZE_T done)
    {
        if(!isPH(h)) return o_NtWriteVirtualMemory(h, a, b, n, done);
        SIZE_T d = 0;
        const bool ok = MemoryWriteSafe(h, a, b, n, &d);
        if(done) *done = d;
        return ok ? ST_SUCCESS : ST_PARTIAL_COPY;
    }

    SIZE_T WINAPI sh_VirtualQueryEx(HANDLE h, LPCVOID a, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len)
    {
        if(!isPH(h)) return o_VirtualQueryEx(h, a, mbi, len);
        if(!TT_IsTargetPseudo(h) || !mbi || len < sizeof(MEMORY_BASIC_INFORMATION)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        return queryRegion(h, uint64_t(uintptr_t(a)), mbi);
    }

    NTSTATUS NTAPI sh_NtQueryVirtualMemory(HANDLE h, PVOID a, ULONG cls, PVOID buf, SIZE_T len, PSIZE_T ret)
    {
        if(!isPH(h)) return o_NtQueryVirtualMemory(h, a, cls, buf, len, ret);
        if(cls != 0 /* MemoryBasicInformation */ || !TT_IsTargetPseudo(h)) return ST_NOT_SUPPORTED;
        if(len < sizeof(MEMORY_BASIC_INFORMATION)) return ST_INFO_LENGTH_MISMATCH;
        const SIZE_T r = queryRegion(h, uint64_t(uintptr_t(a)), static_cast<MEMORY_BASIC_INFORMATION*>(buf));
        if(ret) *ret = r;
        return r ? ST_SUCCESS : NTSTATUS(0xC000000DL) /* STATUS_INVALID_PARAMETER */;
    }

    LPVOID WINAPI sh_VirtualAllocEx(HANDLE h, LPVOID a, SIZE_T n, DWORD t, DWORD p)
    {
        if(!isPH(h)) return o_VirtualAllocEx(h, a, n, t, p);
        REFUSE(phPid(h), "allocate memory in the target (it would see a new region appear)");
        return nullptr;
    }

    BOOL WINAPI sh_VirtualFreeEx(HANDLE h, LPVOID a, SIZE_T n, DWORD t)
    {
        if(!isPH(h)) return o_VirtualFreeEx(h, a, n, t);
        REFUSE(phPid(h), "free memory in the target");
        return FALSE;
    }

    BOOL WINAPI sh_VirtualProtectEx(HANDLE h, LPVOID a, SIZE_T n, DWORD p, PDWORD old)
    {
        if(!isPH(h)) return o_VirtualProtectEx(h, a, n, p, old);
        REFUSE(phPid(h), "change a page protection in the target");
        return FALSE;
    }

    BOOL WINAPI sh_IsWow64Process(HANDLE h, PBOOL wow)
    {
        if(!isPH(h)) return o_IsWow64Process(h, wow);
        if(wow) *wow = FALSE;          // P0: 64-bit targets only (FEATURE-MAP)
        return TRUE;
    }

    DWORD WINAPI sh_GetProcessId(HANDLE h) { return isPH(h) ? phPid(h) : o_GetProcessId(h); }
    DWORD WINAPI sh_GetThreadId(HANDLE h) { return isTPH(h) ? TT_ThreadIdOf(h) : o_GetThreadId(h); }

    DWORD WINAPI sh_SuspendThread(HANDLE h)
    {
        if(!isTPH(h)) return o_SuspendThread(h);
        const DWORD tid = TT_ThreadIdOf(h);
        if(tid && tid == TT_StoppedTid())
        {
            std::lock_guard<std::mutex> g(g_suspM);
            return g_susp[tid]++;
        }
        // Not reported: x64dbg suspends a running thread internally to read its registers (call-stack panel, suspend
        // count) every refresh. Refused all the same -- a real suspend changes the thread's suspend count, which the
        // target can read. The user's own suspend commands explain HV Mode themselves.
        SetLastError(ERROR_ACCESS_DENIED);
        return DWORD(-1);
    }

    DWORD WINAPI sh_ResumeThread(HANDLE h)
    {
        if(!isTPH(h)) return o_ResumeThread(h);
        const DWORD tid = TT_ThreadIdOf(h);
        std::lock_guard<std::mutex> g(g_suspM);
        auto it = g_susp.find(tid);
        if(it == g_susp.end() || it->second == 0) return 0;     // never suspended by anyone through us
        return it->second--;
    }

    BOOL WINAPI sh_GetThreadContext(HANDLE h, LPCONTEXT c)
    {
        if(!isTPH(h)) return o_GetThreadContext(h, c);
        TITAN_ENGINE_CONTEXT_t t;
        if(!c || !GetFullContextDataEx(h, &t))
        {
            SetLastError(ERROR_ACCESS_DENIED);     // only the thread stopped at a breakpoint has registers
            return FALSE;
        }
        c->Rax = t.cax; c->Rcx = t.ccx; c->Rdx = t.cdx; c->Rbx = t.cbx; c->Rsp = t.csp; c->Rbp = t.cbp; c->Rsi = t.csi; c->Rdi = t.cdi;
        c->R8 = t.r8; c->R9 = t.r9; c->R10 = t.r10; c->R11 = t.r11; c->R12 = t.r12; c->R13 = t.r13; c->R14 = t.r14; c->R15 = t.r15;
        c->Rip = t.cip;
        c->EFlags = DWORD(t.eflags);
        c->SegCs = t.cs; c->SegSs = t.ss; c->SegDs = t.ds; c->SegEs = t.es; c->SegFs = t.fs; c->SegGs = t.gs;
        c->Dr0 = c->Dr1 = c->Dr2 = c->Dr3 = c->Dr6 = c->Dr7 = 0;     // never used
        c->FltSave.ControlWord = t.x87fpu.ControlWord;
        c->FltSave.StatusWord = t.x87fpu.StatusWord;
        c->FltSave.TagWord = BYTE(t.x87fpu.TagWord);
        c->FltSave.MxCsr = t.MxCsr;
        c->MxCsr = t.MxCsr;
        for(int i = 0; i < 16; i++) memcpy(&(&c->Xmm0)[i], &t.XmmRegisters[i], 16);
        return TRUE;
    }

    BOOL WINAPI sh_SetThreadContext(HANDLE h, const CONTEXT* c)
    {
        if(!isTPH(h)) return o_SetThreadContext(h, c);
        TITAN_ENGINE_CONTEXT_t t;
        if(!c || !GetFullContextDataEx(h, &t)) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
        t.cax = c->Rax; t.ccx = c->Rcx; t.cdx = c->Rdx; t.cbx = c->Rbx; t.csp = c->Rsp; t.cbp = c->Rbp; t.csi = c->Rsi; t.cdi = c->Rdi;
        t.r8 = c->R8; t.r9 = c->R9; t.r10 = c->R10; t.r11 = c->R11; t.r12 = c->R12; t.r13 = c->R13; t.r14 = c->R14; t.r15 = c->R15;
        t.cip = c->Rip;                // GPRs + RIP go back through the HV; flags / segments / vectors: read-only (P0)
        return SetFullContextDataEx(h, &t) ? TRUE : FALSE;
    }

    BOOL WINAPI sh_Wow64GetThreadContext(HANDLE h, PWOW64_CONTEXT c)
    {
        if(!isTPH(h)) return o_Wow64GetThreadContext(h, c);
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    BOOL WINAPI sh_TerminateThread(HANDLE h, DWORD code)
    {
        if(!isTPH(h)) return o_TerminateThread(h, code);
        REFUSE(TT_TargetPid(), "terminate a thread of the target");
        return FALSE;
    }

    BOOL WINAPI sh_TerminateProcess(HANDLE h, UINT code)
    {
        if(!isPH(h)) return o_TerminateProcess(h, code);
        REFUSE(phPid(h), "terminate the target (the debugger never kills it; Stop detaches)");
        return FALSE;
    }

    HANDLE WINAPI sh_OpenProcess(DWORD access, BOOL inherit, DWORD pid)
    {
        // the attached target: its pseudo-handle, so later calls route here. Anything else goes to Windows, where
        // HV Mode's guard decides.
        if(pid && IsFileBeingDebugged() && pid == TT_TargetPid()) return TitanOpenProcess(access, inherit != FALSE, pid);
        return o_OpenProcess(access, inherit, pid);
    }

    HANDLE WINAPI sh_OpenThread(DWORD access, BOOL inherit, DWORD tid)
    {
        if(TT_IsTargetTid(tid)) return TitanOpenThread(access, inherit != FALSE, tid);
        return o_OpenThread(access, inherit, tid);
    }

    BOOL WINAPI sh_DuplicateHandle(HANDLE sp, HANDLE sh, HANDLE tp, LPHANDLE out, DWORD access, BOOL inherit, DWORD opt)
    {
        if(isPH(sp) || isPH(tp))
        {
            REFUSE(isPH(sp) ? phPid(sp) : phPid(tp), "duplicate a handle into or out of the target");
            return FALSE;
        }
        if(isPH(sh) || isTPH(sh))
        {
            if(sp != GetCurrentProcess() || tp != GetCurrentProcess()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
            if(out) *out = sh;             // a pseudo-handle duplicates to itself
            return TRUE;
        }
        return o_DuplicateHandle(sp, sh, tp, out, access, inherit, opt);
    }

    HANDLE WINAPI sh_CreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES sa, SIZE_T st, LPTHREAD_START_ROUTINE fn, LPVOID p, DWORD f, LPDWORD tid)
    {
        if(!isPH(h)) return o_CreateRemoteThread(h, sa, st, fn, p, f, tid);
        REFUSE(phPid(h), "create a thread in the target");
        return nullptr;
    }

    HANDLE WINAPI sh_CreateRemoteThreadEx(HANDLE h, LPSECURITY_ATTRIBUTES sa, SIZE_T st, LPTHREAD_START_ROUTINE fn, LPVOID p, DWORD f,
                                          LPPROC_THREAD_ATTRIBUTE_LIST al, LPDWORD tid)
    {
        if(!isPH(h)) return o_CreateRemoteThreadEx(h, sa, st, fn, p, f, al, tid);
        REFUSE(phPid(h), "create a thread in the target");
        return nullptr;
    }

    BOOL WINAPI sh_DebugBreakProcess(HANDLE h)
    {
        if(!isPH(h)) return o_DebugBreakProcess(h);
        REFUSE(phPid(h), "break into the target with DebugBreakProcess (it injects a thread)");
        return FALSE;
    }

    BOOL WINAPI sh_GetThreadTimes(HANDLE h, LPFILETIME a, LPFILETIME b, LPFILETIME c, LPFILETIME d)
    {
        if(!isTPH(h)) return o_GetThreadTimes(h, a, b, c, d);
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    int WINAPI sh_GetThreadPriority(HANDLE h)
    {
        if(!isTPH(h)) return o_GetThreadPriority(h);
        SetLastError(ERROR_NOT_SUPPORTED);
        return THREAD_PRIORITY_ERROR_RETURN;
    }

    BOOL WINAPI sh_SetThreadPriority(HANDLE h, int p)
    {
        if(!isTPH(h)) return o_SetThreadPriority(h, p);
        REFUSE(TT_TargetPid(), "change a thread priority in the target");
        return FALSE;
    }

    HANDLE WINAPI sh_CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
    {
        if(hvguard::Active() && pid && pid != GetCurrentProcessId() &&
                (flags & (TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)))
        {
            REFUSE(pid, "a toolhelp module / heap snapshot of another process (it opens it; a heap snapshot also injects a thread)");
            return INVALID_HANDLE_VALUE;
        }
        return o_CreateToolhelp32Snapshot(flags, pid);
    }

    BOOL WINAPI sh_GetExitCodeProcess(HANDLE h, LPDWORD code)
    {
        if(!isPH(h)) return o_GetExitCodeProcess(h, code);
        if(code) *code = (!TT_IsTargetPseudo(h) || TT_TargetAlive()) ? STILL_ACTIVE : 0;
        return TRUE;
    }

    BOOL WINAPI sh_GetExitCodeThread(HANDLE h, LPDWORD code)
    {
        if(!isTPH(h)) return o_GetExitCodeThread(h, code);
        if(code) *code = TT_IsTargetTid(TT_ThreadIdOf(h)) ? STILL_ACTIVE : 0;
        return TRUE;
    }

    BOOL WINAPI sh_FlushInstructionCache(HANDLE h, LPCVOID a, SIZE_T n)
    {
        if(!isPH(h)) return o_FlushInstructionCache(h, a, n);
        return TRUE;                       // the hypervisor's writes are coherent
    }

    DWORD WINAPI sh_K32GetModuleFileNameExW(HANDLE h, HMODULE m, LPWSTR out, DWORD n)
    {
        if(!isPH(h)) return o_K32GetModuleFileNameExW(h, m, out, n);
        DWORD r = 0;
        if(TT_IsTargetPseudo(h)) r = TT_ModulePath(uint64_t(uintptr_t(m)), out, n);
        if(!r && !m) r = TT_ProcessImagePath(phPid(h), out, n, true);
        if(!r) SetLastError(ERROR_INVALID_PARAMETER);
        return r;
    }

    DWORD WINAPI sh_K32GetProcessImageFileNameW(HANDLE h, LPWSTR out, DWORD n)
    {
        if(!isPH(h)) return o_K32GetProcessImageFileNameW(h, out, n);
        const DWORD r = TT_ProcessImagePath(phPid(h), out, n, false);
        if(!r) SetLastError(ERROR_INVALID_PARAMETER);
        return r;
    }

    DWORD WINAPI sh_K32GetMappedFileNameW(HANDLE h, LPVOID a, LPWSTR out, DWORD n)
    {
        if(!isPH(h)) return o_K32GetMappedFileNameW(h, a, out, n);
        SetLastError(ERROR_NOT_SUPPORTED);     // callers fall back to GetModuleFileNameEx (the loader list)
        return 0;
    }

    BOOL WINAPI sh_CheckRemoteDebuggerPresent(HANDLE h, PBOOL present)
    {
        if(!isPH(h)) return o_CheckRemoteDebuggerPresent(h, present);
        SetLastError(ERROR_NOT_SUPPORTED);     // unknown without a handle; irrelevant to a hypervisor attach
        return FALSE;
    }

    BOOL WINAPI sh_DebugActiveProcess(DWORD pid)
    {
        if(!hvguard::Active()) return o_DebugActiveProcess(pid);
        REFUSE(pid, "attach the Windows debugger (DebugActiveProcess)");
        return FALSE;
    }

    BOOL WINAPI sh_DebugActiveProcessStop(DWORD pid)
    {
        if(!hvguard::Active()) return o_DebugActiveProcessStop(pid);
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    BOOL WINAPI sh_OpenProcessToken(HANDLE h, DWORD access, PHANDLE tok)
    {
        if(!isPH(h)) return o_OpenProcessToken(h, access, tok);
        REFUSE(phPid(h), "open the target's token");
        return FALSE;
    }

    BOOL postRefused(DWORD tid, void* caller)
    {
        if(!hvguard::Active() || isOwnThread(tid)) return FALSE;
        note(hvguard::OwnerOfThread(tid), "post a window message to a thread of another process", caller);
        SetLastError(ERROR_ACCESS_DENIED);
        return TRUE;
    }
    BOOL WINAPI sh_PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
    {
        if(postRefused(tid, _ReturnAddress())) return FALSE;
        return o_PostThreadMessageA(tid, msg, w, l);
    }
    BOOL WINAPI sh_PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
    {
        if(postRefused(tid, _ReturnAddress())) return FALSE;
        return o_PostThreadMessageW(tid, msg, w, l);
    }

    NTSTATUS NTAPI sh_NtQueryInformationProcess(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG ret)
    {
        if(!isPH(h)) return o_NtQueryInformationProcess(h, cls, buf, len, ret);
        switch(cls)
        {
        case 0:     // ProcessBasicInformation
        {
            if(len < sizeof(PROCESS_BASIC_INFORMATION)) return ST_INFO_LENGTH_MISMATCH;
            auto* p = static_cast<PROCESS_BASIC_INFORMATION*>(buf);
            memset(p, 0, sizeof(*p));
            p->Reserved1 = reinterpret_cast<PVOID>(uintptr_t(ST_PENDING));        // ExitStatus of a live process
            p->PebBaseAddress = reinterpret_cast<PPEB>(GetPEBLocation(h));
            p->UniqueProcessId = ULONG_PTR(phPid(h));
            p->Reserved3 = reinterpret_cast<PVOID>(uintptr_t(TT_IsTargetPseudo(h) ? TT_ParentPid() : 0));
            if(ret) *ret = sizeof(*p);
            return ST_SUCCESS;
        }
        case 26:    // ProcessWow64Information: a 64-bit process
        {
            if(len < sizeof(ULONG_PTR)) return ST_INFO_LENGTH_MISMATCH;
            *static_cast<ULONG_PTR*>(buf) = 0;
            if(ret) *ret = sizeof(ULONG_PTR);
            return ST_SUCCESS;
        }
        case 27:    // ProcessImageFileName (NT path)
        case 43:    // ProcessImageFileNameWin32
        {
            if(len < sizeof(UNICODE_STRING) + 2) return ST_INFO_LENGTH_MISMATCH;
            auto* us = static_cast<UNICODE_STRING*>(buf);
            auto* chars = reinterpret_cast<wchar_t*>(us + 1);
            const DWORD room = DWORD((len - sizeof(UNICODE_STRING)) / sizeof(wchar_t));
            const DWORD n = TT_ProcessImagePath(phPid(h), chars, room, cls == 43);
            if(!n) return ST_NOT_SUPPORTED;
            us->Buffer = chars;
            us->Length = USHORT(n * sizeof(wchar_t));
            us->MaximumLength = USHORT(room * sizeof(wchar_t));
            if(ret) *ret = ULONG(sizeof(UNICODE_STRING) + (n + 1) * sizeof(wchar_t));
            return ST_SUCCESS;
        }
        default:
            return ST_NOT_SUPPORTED;       // e.g. ProcessCookie: not known without a handle
        }
    }

    NTSTATUS NTAPI sh_NtQueryInformationThread(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG ret)
    {
        if(!isTPH(h)) return o_NtQueryInformationThread(h, cls, buf, len, ret);
        const DWORD tid = TT_ThreadIdOf(h);
        switch(cls)
        {
        case 0:     // ThreadBasicInformation
        {
            struct TBI { NTSTATUS ExitStatus; PVOID TebBaseAddress; CLIENT_ID ClientId; ULONG_PTR AffinityMask; LONG Priority; LONG BasePriority; };
            if(len < sizeof(TBI)) return ST_INFO_LENGTH_MISMATCH;
            auto* t = static_cast<TBI*>(buf);
            memset(t, 0, sizeof(*t));
            t->ExitStatus = ST_PENDING;
            t->TebBaseAddress = reinterpret_cast<PVOID>(GetTEBLocation(h));
            t->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(uintptr_t(TT_TargetPid()));
            t->ClientId.UniqueThread = reinterpret_cast<HANDLE>(uintptr_t(tid));
            if(ret) *ret = sizeof(*t);
            return ST_SUCCESS;
        }
        case 9:     // ThreadQuerySetWin32StartAddress
        {
            if(len < sizeof(PVOID)) return ST_INFO_LENGTH_MISMATCH;
            *static_cast<PVOID*>(buf) = reinterpret_cast<PVOID>(uintptr_t(TT_ThreadStart(tid)));
            if(ret) *ret = sizeof(PVOID);
            return ST_SUCCESS;
        }
        case 35:    // ThreadSuspendCount: nobody suspends the target's threads (the stopped one keeps a local count)
        {
            if(len < sizeof(ULONG)) return ST_INFO_LENGTH_MISMATCH;
            std::lock_guard<std::mutex> g(g_suspM);
            auto it = g_susp.find(tid);
            *static_cast<ULONG*>(buf) = it == g_susp.end() ? 0 : it->second;
            if(ret) *ret = sizeof(ULONG);
            return ST_SUCCESS;
        }
        default:
            return ST_NOT_SUPPORTED;
        }
    }

    NTSTATUS NTAPI sh_NtSuspendProcess(HANDLE h)
    {
        if(!isPH(h)) return o_NtSuspendProcess(h);
        REFUSE(phPid(h), "suspend the whole target (whole-process pause is HV gap 3)");
        return ST_ACCESS_DENIED;
    }

    NTSTATUS NTAPI sh_NtResumeProcess(HANDLE h)
    {
        if(!isPH(h)) return o_NtResumeProcess(h);
        return ST_ACCESS_DENIED;
    }

    // ------------------------------------------------------------------------------------------ the routing table
    struct Route { const char* name; const wchar_t* home; const char* homeName; void* shim; void** orig; };
// R: the import name is the export name; RA: an alias import (psapi's name) whose original is the kernel32 K32 export
#define R(name, home, origVar) {name, home, name, reinterpret_cast<void*>(&sh_##origVar), reinterpret_cast<void**>(&o_##origVar)}
#define RA(name, home, homeName, origVar) {name, home, homeName, reinterpret_cast<void*>(&sh_##origVar), reinterpret_cast<void**>(&o_##origVar)}
    Route g_routes[] = {
        R("CloseHandle", L"kernel32.dll", CloseHandle),
        R("WaitForSingleObject", L"kernel32.dll", WaitForSingleObject),
        R("ReadProcessMemory", L"kernel32.dll", ReadProcessMemory),
        R("WriteProcessMemory", L"kernel32.dll", WriteProcessMemory),
        R("VirtualQueryEx", L"kernel32.dll", VirtualQueryEx),
        R("VirtualAllocEx", L"kernel32.dll", VirtualAllocEx),
        R("VirtualFreeEx", L"kernel32.dll", VirtualFreeEx),
        R("VirtualProtectEx", L"kernel32.dll", VirtualProtectEx),
        R("IsWow64Process", L"kernel32.dll", IsWow64Process),
        R("GetProcessId", L"kernel32.dll", GetProcessId),
        R("GetThreadId", L"kernel32.dll", GetThreadId),
        R("SuspendThread", L"kernel32.dll", SuspendThread),
        R("ResumeThread", L"kernel32.dll", ResumeThread),
        R("GetThreadContext", L"kernel32.dll", GetThreadContext),
        R("SetThreadContext", L"kernel32.dll", SetThreadContext),
        R("Wow64GetThreadContext", L"kernel32.dll", Wow64GetThreadContext),
        R("TerminateThread", L"kernel32.dll", TerminateThread),
        R("TerminateProcess", L"kernel32.dll", TerminateProcess),
        R("OpenProcess", L"kernel32.dll", OpenProcess),
        R("OpenThread", L"kernel32.dll", OpenThread),
        R("DuplicateHandle", L"kernel32.dll", DuplicateHandle),
        R("CreateRemoteThread", L"kernel32.dll", CreateRemoteThread),
        R("CreateRemoteThreadEx", L"kernel32.dll", CreateRemoteThreadEx),
        R("DebugBreakProcess", L"kernel32.dll", DebugBreakProcess),
        R("GetThreadTimes", L"kernel32.dll", GetThreadTimes),
        R("GetThreadPriority", L"kernel32.dll", GetThreadPriority),
        R("SetThreadPriority", L"kernel32.dll", SetThreadPriority),
        R("CreateToolhelp32Snapshot", L"kernel32.dll", CreateToolhelp32Snapshot),
        R("GetExitCodeProcess", L"kernel32.dll", GetExitCodeProcess),
        R("GetExitCodeThread", L"kernel32.dll", GetExitCodeThread),
        R("FlushInstructionCache", L"kernel32.dll", FlushInstructionCache),
        R("K32GetModuleFileNameExW", L"kernel32.dll", K32GetModuleFileNameExW),
        RA("GetModuleFileNameExW", L"kernel32.dll", "K32GetModuleFileNameExW", K32GetModuleFileNameExW),
        R("K32GetProcessImageFileNameW", L"kernel32.dll", K32GetProcessImageFileNameW),
        RA("GetProcessImageFileNameW", L"kernel32.dll", "K32GetProcessImageFileNameW", K32GetProcessImageFileNameW),
        R("K32GetMappedFileNameW", L"kernel32.dll", K32GetMappedFileNameW),
        RA("GetMappedFileNameW", L"kernel32.dll", "K32GetMappedFileNameW", K32GetMappedFileNameW),
        R("CheckRemoteDebuggerPresent", L"kernel32.dll", CheckRemoteDebuggerPresent),
        R("DebugActiveProcess", L"kernel32.dll", DebugActiveProcess),
        R("DebugActiveProcessStop", L"kernel32.dll", DebugActiveProcessStop),
        R("OpenProcessToken", L"advapi32.dll", OpenProcessToken),
        R("PostThreadMessageA", L"user32.dll", PostThreadMessageA),
        R("PostThreadMessageW", L"user32.dll", PostThreadMessageW),
        R("NtQueryInformationProcess", L"ntdll.dll", NtQueryInformationProcess),
        R("NtQueryInformationThread", L"ntdll.dll", NtQueryInformationThread),
        R("NtReadVirtualMemory", L"ntdll.dll", NtReadVirtualMemory),
        R("NtWriteVirtualMemory", L"ntdll.dll", NtWriteVirtualMemory),
        R("NtQueryVirtualMemory", L"ntdll.dll", NtQueryVirtualMemory),
        R("NtSuspendProcess", L"ntdll.dll", NtSuspendProcess),
        R("NtResumeProcess", L"ntdll.dll", NtResumeProcess),
    };
#undef R
#undef RA

    // the originals come from the exporting DLL itself (what an unpatched import would have called)
    bool resolveOriginals(char* why, size_t n)
    {
        for(auto& r : g_routes)
        {
            if(*r.orig) continue;
            HMODULE m = GetModuleHandleW(r.home);
            if(!m) m = LoadLibraryW(r.home);
            void* f = m ? reinterpret_cast<void*>(GetProcAddress(m, r.homeName)) : nullptr;
            if(!f)
            {
                snprintf(why, n, "the shim cannot find %s in %ls", r.homeName, r.home);
                return false;
            }
            *r.orig = f;
        }
        return true;
    }

    // point every import of `m` that the table names at its shim; returns how many entries were redirected
    int patchImports(HMODULE m)
    {
        auto* base = reinterpret_cast<uint8_t*>(m);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if(dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if(!dir.VirtualAddress) return 0;
        int patched = 0;
        for(auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); imp->Name; imp++)
        {
            auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
            for(; names->u1.AddressOfData; names++, iat++)
            {
                if(IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
                const char* fn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData)->Name;
                for(auto& r : g_routes)
                {
                    if(strcmp(fn, r.name) != 0) continue;
                    if(reinterpret_cast<void*>(iat->u1.Function) != r.shim)
                    {
                        DWORD old = 0;
                        VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), PAGE_READWRITE, &old);
                        InterlockedExchangePointer(reinterpret_cast<PVOID*>(&iat->u1.Function), r.shim);
                        VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), old, &old);
                    }
                    patched++;
                    break;
                }
            }
        }
        return patched;
    }
}

// ================================================================================================== exports
extern "C" {

// A process's image path WITHOUT opening it: NtQuerySystemInformation(SystemProcessIdInformation = 0x58) returns the NT
// path for a pid; `dos` converts \Device\HarddiskVolumeN\... to C:\... via QueryDosDevice. Length in characters.
__declspec(dllexport) DWORD TT_ProcessImagePath(DWORD pid, wchar_t* out, DWORD n, bool dos)
{
    if(!out || !n) return 0;
    out[0] = 0;
    if(!ntQSI) ntQSI = reinterpret_cast<NtQSI_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    struct { HANDLE ProcessId; UNICODE_STRING ImageName; } info = {};
    std::vector<wchar_t> buf(32768);
    info.ProcessId = reinterpret_cast<HANDLE>(uintptr_t(pid));
    info.ImageName.MaximumLength = USHORT((buf.size() - 1) * sizeof(wchar_t) > 0xFFFE ? 0xFFFE : (buf.size() - 1) * sizeof(wchar_t));
    info.ImageName.Buffer = buf.data();
    if(!ntQSI || ntQSI(0x58, &info, sizeof(info), nullptr) < 0) return 0;
    std::wstring path(info.ImageName.Buffer, info.ImageName.Length / sizeof(wchar_t));
    if(dos)
    {
        wchar_t drive[3] = L"A:", target[MAX_PATH];
        for(wchar_t d = L'A'; d <= L'Z'; d++)
        {
            drive[0] = d;
            if(!QueryDosDeviceW(drive, target, MAX_PATH)) continue;
            const std::wstring dev = std::wstring(target) + L"\\";
            if(path.compare(0, dev.size(), dev) == 0)
            {
                path = std::wstring(drive) + L"\\" + path.substr(dev.size());
                break;
            }
        }
    }
    const DWORD len = DWORD(std::min<size_t>(path.size(), n - 1));
    memcpy(out, path.data(), len * sizeof(wchar_t));
    out[len] = 0;
    return len;
}

// Enter HV Mode: install the guard (fail closed), route the given modules' imports through the shim, start refusing.
__declspec(dllexport) bool TT_EnterHvMode(const HMODULE* modules, DWORD count, char* why, DWORD whyLen)
{
    char local[512] = "";
    if(!why || !whyLen) { why = local; whyLen = sizeof(local); }
    why[0] = 0;
    if(!hvguard::Install(why, whyLen)) return false;
    if(!resolveOriginals(why, whyLen)) return false;
    for(DWORD i = 0; i < count; i++)
        if(modules[i] && patchImports(modules[i]) < 0)
        {
            snprintf(why, whyLen, "module %p is not a PE image; its imports cannot be routed", static_cast<void*>(modules[i]));
            return false;
        }
    hvguard::SetActive(true);
    return true;
}

__declspec(dllexport) bool TT_LeaveHvMode(char* why, DWORD whyLen)
{
    if(IsFileBeingDebugged())
    {
        if(why && whyLen) snprintf(why, whyLen, "detach from the target first");
        return false;
    }
    hvguard::SetActive(false);       // the hooks and the routing stay: they only refuse / route pseudo-handles
    return true;
}

__declspec(dllexport) bool TT_HvModeActive() { return hvguard::Active(); }
__declspec(dllexport) bool TT_TakeRefusal(TT_REFUSAL* out) { return out && hvguard::Take(out); }
__declspec(dllexport) DWORD TT_RefusalsDropped() { return hvguard::Dropped(); }
__declspec(dllexport) int TT_RouteModule(HMODULE m) { return m ? patchImports(m) : -1; }

} // extern "C"
