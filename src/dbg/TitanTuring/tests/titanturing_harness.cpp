// titanturing_harness -- plays x64dbg against our engine (TitanTuring.dll), live, with no x64dbg build:
// registers the callbacks x64dbg registers, attaches to a process through the hypervisor, and checks the attach event
// storm (CREATE_PROCESS, threads, modules), reads through the pseudo-handle, PEB / TEB location and the region map,
// then detaches. Nothing in the target is touched: it never gets a debug port, a handle, a thread or a byte changed.
//   titanturing_harness.exe <path\to\TitanTuring.dll> <pid>
// It enters HV Mode first (the engine refuses to attach without the guard) but routes none of its own imports, so
// its Windows calls on the pseudo-handle reach real Windows -- proving Windows doesn't recognise it.
#define TURINGHV_STATIC 1
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include "../../TitanEngine/TitanEngine.h"
#include "../TitanTuring.h"

#define FN(name) static decltype(&name) p_##name
FN(SetCustomHandler); FN(AttachDebugger); FN(DetachDebuggerEx); FN(MemoryReadSafe); FN(GetPEBLocation);
FN(GetTEBLocation); FN(GetDebugData); FN(GetContextDataEx); FN(IsFileBeingDebugged); FN(InitDebugW);
FN(EngineCheckStructAlignment); FN(TitanOpenThread);
static decltype(&TT_TargetThreads) p_TT_TargetThreads;
static decltype(&TT_TargetRegions) p_TT_TargetRegions;
static decltype(&TT_TargetModules) p_TT_TargetModules;
static decltype(&TT_LastMessage) p_TT_LastMessage;
static decltype(&TT_ImageName) p_TT_ImageName;
static decltype(&TT_EnterHvMode) p_TT_EnterHvMode;

static PROCESS_INFORMATION g_pi;
static int g_createProcess, g_threads, g_dlls, g_exitThreads, g_unloads;
static uint64_t g_imageBase;
static int g_fail;
static void check(bool ok, const char* what) { printf("%s %s\n", ok ? "  ok  " : "  FAIL", what); if(!ok) g_fail++; }

static void cbCreateProcess(const void* p)
{
    auto* c = static_cast<const CREATE_PROCESS_DEBUG_INFO*>(p);
    g_createProcess++;
    g_imageBase = uint64_t(uintptr_t(c->lpBaseOfImage));
    printf("  CREATE_PROCESS image %016llx, hProcess %p (a pseudo-handle), hFile %p\n", (unsigned long long)g_imageBase,
           c->hProcess, c->hFile);
}
static void cbCreateThread(const void*) { g_threads++; }
static void cbExitThread(const void*) { g_exitThreads++; }
static void cbLoadDll(const void*) { g_dlls++; }
static void cbUnloadDll(const void*) { g_unloads++; }
static void cbExitProcess(const void*) { printf("  EXIT_PROCESS\n"); }

static DWORD WINAPI detachLater(LPVOID)
{
    Sleep(1500);
    p_DetachDebuggerEx(g_pi.dwProcessId);
    return 0;
}

static void cbAttach()
{
    printf("attach callback (x64dbg would now show the process RUNNING):\n");
    check(p_IsFileBeingDebugged(), "IsFileBeingDebugged after attach");
    check(GetProcessId(g_pi.hProcess) == 0, "hProcess is a pseudo-handle Windows doesn't recognise (no real handle opened)");
    unsigned char mz[2] = {};
    SIZE_T n = 0;
    check(p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(uintptr_t(g_imageBase)), mz, 2, &n) && n == 2 && mz[0] == 'M' && mz[1] == 'Z',
          "MemoryReadSafe(pseudo-handle, image base) reads 'MZ' through the hypervisor");
    const ULONG_PTR peb = p_GetPEBLocation(g_pi.hProcess);
    uint64_t pebImage = 0;
    const bool pebOk = peb && p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(peb + 0x10), &pebImage, 8, &n) && pebImage == g_imageBase;
    printf("  PEB %p, PEB.ImageBaseAddress %016llx\n", reinterpret_cast<void*>(peb), (unsigned long long)pebImage);
    check(pebOk, "GetPEBLocation finds the PEB, and PEB.ImageBaseAddress == the image base");
    const ULONG_PTR teb = p_GetTEBLocation(g_pi.hThread);
    uint64_t tebSelf = 0;
    const bool tebOk = teb && p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(teb + 0x30), &tebSelf, 8, &n) && tebSelf == teb;
    printf("  TEB %p of thread %lu, TEB.Self %016llx\n", reinterpret_cast<void*>(teb), g_pi.dwThreadId, (unsigned long long)tebSelf);
    check(tebOk, "GetTEBLocation finds the TEB, and TEB.NtTib.Self == the TEB");
    // other threads: registers from each one's kernel trap frame -- checked here independently of the engine's own
    // validation: RIP inside a module and right after a syscall, RSP inside that thread's own stack (TEB bounds)
    {
        static TT_THREAD th[4096];
        static TT_MODULE md[4096];
        DWORD nt = 0, nm = 0;
        p_TT_TargetThreads(th, 4096, &nt);
        p_TT_TargetModules(md, 4096, &nm);
        int with = 0, good = 0, unverified = 0;
        for(DWORD i = 0; i < nt && i < 4096; i++)
        {
            HANDLE h = p_TitanOpenThread(0, false, th[i].tid);
            const uint64_t rip = p_GetContextDataEx(h, UE_CIP), rsp = p_GetContextDataEx(h, UE_CSP);
            if(!rip) continue;
            with++;
            bool inMod = false;
            for(DWORD k = 0; k < nm && k < 4096; k++) inMod = inMod || (rip >= md[k].base && rip < md[k].base + md[k].size);
            unsigned char site[2] = {};
            SIZE_T n2 = 0;
            const bool sc = p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(uintptr_t(rip - 2)), site, 2, &n2) && site[0] == 0x0F && site[1] == 0x05;
            // the thread's whole stack reservation: [TEB.DeallocationStack (+0x1478), TEB.NtTib.StackBase (+0x08)) --
            // StackLimit (+0x10) is only the committed bottom and can lag behind a deeper stack
            const ULONG_PTR teb = p_GetTEBLocation(h);
            uint64_t base = 0, limit = 0, dealloc = 0;
            const bool rd = teb && p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(teb + 8), &base, 8, &n2) &&
                            p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(teb + 0x10), &limit, 8, &n2) &&
                            p_MemoryReadSafe(g_pi.hProcess, reinterpret_cast<LPVOID>(teb + 0x1478), &dealloc, 8, &n2);
            if(!rd || !base)
            {
                unverified++;          // its TEB isn't resident now: no bounds to check against
                continue;
            }
            const bool stk = rsp >= dealloc && rsp < base;
            if(inMod && sc && stk) good++;
            else printf("  thread %lu: rip %llx rsp %llx stack [%llx..%llx) limit %llx (module %d, syscall %d, stack %d)\n", th[i].tid,
                        (unsigned long long)rip, (unsigned long long)rsp, (unsigned long long)dealloc, (unsigned long long)base,
                        (unsigned long long)limit, inMod, sc, stk);
        }
        printf("  %d of %lu threads have registers from their trap frame; %d pass every independent check, %d unverifiable (TEB not resident)\n",
               with, nt, good, unverified);
        check(good > 0 && good + unverified == with, "other threads' registers (trap frames): RIP in a module after a syscall, RSP in the thread's own stack");
    }
    static TT_REGION rg[8192];
    DWORD nreg = 0;
    check(p_TT_TargetRegions(rg, 8192, &nreg) && nreg > 0, "the region map comes from the hypervisor");
    printf("  %lu regions, %d threads, %d modules reported, image '%s'\n", nreg, g_threads + 1, g_dlls, p_TT_ImageName());
    CreateThread(nullptr, 0, detachLater, nullptr, 0, nullptr);
}

int wmain(int argc, wchar_t** argv)
{
    if(argc < 3) { fwprintf(stderr, L"usage: %ls <TitanEngine.dll> <pid>\n", argv[0]); return 2; }
    HMODULE m = LoadLibraryW(argv[1]);
    if(!m) { printf("FAIL: cannot load %ls (%lu)\n", argv[1], GetLastError()); return 1; }
#define GET(name) p_##name = reinterpret_cast<decltype(p_##name)>(GetProcAddress(m, #name)); if(!p_##name) { printf("FAIL: export %s missing\n", #name); return 1; }
    GET(SetCustomHandler) GET(AttachDebugger) GET(DetachDebuggerEx) GET(MemoryReadSafe) GET(GetPEBLocation)
    GET(GetTEBLocation) GET(GetDebugData) GET(GetContextDataEx) GET(IsFileBeingDebugged) GET(InitDebugW)
    GET(EngineCheckStructAlignment) GET(TT_TargetRegions) GET(TT_TargetModules) GET(TT_LastMessage) GET(TT_ImageName)
    GET(TT_EnterHvMode) GET(TitanOpenThread) GET(TT_TargetThreads)

    check(p_EngineCheckStructAlignment(UE_STRUCT_TITAN_ENGINE_CONTEXT, sizeof(TITAN_ENGINE_CONTEXT_t)), "context struct layout matches x64dbg's");
    check(p_InitDebugW(L"c:\\x.exe", L"", L"") == nullptr, "start-under-debugger refused (attach only)");

    p_SetCustomHandler(UE_CH_CREATEPROCESS, cbCreateProcess);
    p_SetCustomHandler(UE_CH_CREATETHREAD, cbCreateThread);
    p_SetCustomHandler(UE_CH_EXITTHREAD, cbExitThread);
    p_SetCustomHandler(UE_CH_LOADDLL, cbLoadDll);
    p_SetCustomHandler(UE_CH_UNLOADDLL, cbUnloadDll);
    p_SetCustomHandler(UE_CH_EXITPROCESS, cbExitProcess);

    char why[512] = "";
    const bool hv = p_TT_EnterHvMode(nullptr, 0, why, sizeof(why));
    if(!hv) printf("  %s\n", why);
    check(hv, "HV Mode entered (guard installed; no imports routed)");
    const DWORD pid = DWORD(_wtoi(argv[2]));
    printf("attaching to pid %lu through the hypervisor...\n", pid);
    const bool ok = p_AttachDebugger(pid, false, &g_pi, cbAttach);   // returns after the detach
    if(!ok) printf("  AttachDebugger failed: %s\n", p_TT_LastMessage());
    check(ok, "AttachDebugger");
    check(g_createProcess == 1, "exactly one CREATE_PROCESS");
    check(g_threads > 0, "existing threads reported as CREATE_THREAD");
    check(g_dlls > 0, "loaded modules reported as LOAD_DLL");
    check(!p_IsFileBeingDebugged(), "detached");
    printf(g_fail ? "titanturing_harness: FAIL (%d)\n" : "titanturing_harness: PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
