// TitanTuring.cpp -- a drop-in TitanEngine.dll for x64dbg, backed by the turing-hv hypervisor.
//
// x64dbg's core (src/dbg) talks to its debug engine only through TitanEngine.h. This file implements that exact API
// over thvbridge.exe (ThvClient), so the debuggee is never a Windows debuggee: no DebugActiveProcess, no debug port,
// no int3 written into its code, no debug registers, no handle opened on it, no thread injected into it.
//
// Model (PORT-TURINGHV.md, FEATURE-MAP.md):
//   - attach = resolve the target's page-table root through the hypervisor; x64dbg then sees the process RUNNING.
//   - a breakpoint is a rev149 parking breakpoint: the thread that reaches it stops (only that thread); x64dbg's
//     breakpoint callback runs and blocks until Run / Step, then we release / step the parked thread.
//   - memory / hardware data breakpoints are rev146b data watches (P0: hits are reported, the thread is not stopped).
//   - registers are the parked thread's capture snapshot; edits go back through SETREG / SETRIP.
//   - DebugLoop polls the hypervisor and synthesizes the Windows debug events x64dbg expects.
#define TURINGHV_STATIC 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "../TitanEngine/TitanEngine.h"
#include "thvclient.h"
#include "TitanTuring.h"
#include "hvguard.h"
#include <zydis_wrapper.h>     // x64dbg's own Zydis: where a step will land (cross-page steps)
#include <map>
#include <set>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
#include <atomic>
#include <cstring>

namespace
{
    // ---------------------------------------------------------------------------------------------- state
    ThvClient g_thv;
    std::recursive_mutex g_lock;

    struct Target
    {
        DWORD pid = 0;
        uint64_t cr3 = 0, eprocess = 0, imageBase = 0, imageSize = 0, peb = 0, ppid = 0;
        char name[16] = {};
        bool attached = false;
    } g_t;

    uint64_t g_kcr3 = 0;          // the kernel's root (the System process's), for EPROCESS / ETHREAD reads
    int g_pebOff = -1;            // EPROCESS.Peb, learned from our own process
    int g_tebOff = -1;            // ETHREAD/KTHREAD.Teb, learned from our own thread

    // pseudo-handles: values no real handle table produces (handles are multiples of 4 below 2^26). A process
    // pseudo-handle carries its pid (pids are multiples of 4 below 2^24), so x64dbg can "open" a process before the
    // attach -- its attach command asks for the image path and bitness first -- without any real handle existing.
    constexpr uintptr_t PH_PROC = 0x7E000000u;
    constexpr uintptr_t PH_THREAD = 0x7F000000u;
    constexpr uintptr_t PH_LOW = 0x00FFFFFFu;
    inline HANDLE procHandleOf(DWORD pid) { return reinterpret_cast<HANDLE>(PH_PROC | (uintptr_t(pid) & PH_LOW)); }
    inline HANDLE threadHandle(DWORD tid) { return reinterpret_cast<HANDLE>(PH_THREAD | (uintptr_t(tid) << 2)); }
    inline bool isProcPH(HANDLE h) { return (reinterpret_cast<uintptr_t>(h) & ~PH_LOW) == PH_PROC; }
    inline DWORD pidOfPH(HANDLE h) { return DWORD(reinterpret_cast<uintptr_t>(h) & PH_LOW); }
    inline bool isThreadPH(HANDLE h) { return (reinterpret_cast<uintptr_t>(h) & ~PH_LOW) == PH_THREAD; }
    inline DWORD threadOf(HANDLE h) { return DWORD((reinterpret_cast<uintptr_t>(h) & PH_LOW) >> 2); }
    inline bool pidFits(DWORD pid) { return pid && (pid & 3) == 0 && pid <= PH_LOW; }
    inline HANDLE procHandle() { return procHandleOf(g_t.pid); }
    // the attached target's pseudo-handle (a pre-attach pseudo-handle has no address space to read yet)
    inline bool isTargetPH(HANDLE h) { return isProcPH(h) && g_t.attached && pidOfPH(h) == g_t.pid; }

    // breakpoints (rev149 parking) and data watches (rev146b); every one is a hypervisor watch slot (4 in all)
    struct Bpx { ULONG_PTR addr; DWORD type; TITANCBSOFTBP cb; uint32_t hv; uint64_t lastSeq; ULONGLONG lastRearm; };
    std::map<ULONG_PTR, Bpx> g_bpx;
    struct MemBp { ULONG_PTR start; SIZE_T size; DWORD type; bool restore; TITANCBMEMBP cb; uint32_t hv; uint32_t seen; };
    std::map<ULONG_PTR, MemBp> g_membp;
    struct HwBp { bool used; ULONG_PTR addr; DWORD type; DWORD size; TITANCBHWBP cb; uint32_t hv; bool isBreak; uint64_t lastSeq; uint32_t seen; ULONGLONG lastRearm; };
    HwBp g_hw[4] = {};

    TITANCALLBACKARG g_handlers[32] = {};
    DEBUG_EVENT g_ev = {};
    DWORD g_continue = DBG_CONTINUE;

    // the stopped thread (x64dbg's "current" thread while its breakpoint callback runs)
    uint64_t g_stoppedTid = 0;
    uint32_t g_stoppedHv = 0;
    thv_capture_rec g_ctx = {};
    bool g_ctxValid = false;

    TITANCBSTEP g_stepCb = nullptr;
    bool g_stepPending = false;
    uint32_t g_stepHv = 0;
    uint64_t g_stepTid = 0;
    uint64_t g_stepSeq = 0;
    // a cross-page step's temporary breakpoint (stepViaTemp)
    uint32_t g_tempHv = 0;          // its watch (0 = none)
    ULONG_PTR g_tempAddr = 0;
    uint64_t g_tempSeq = 0;         // its last reported hold

    std::atomic<bool> g_stop{false};
    std::set<uint64_t> g_threads;                 // tids reported to x64dbg
    std::map<uint64_t, std::string> g_modules;    // base -> name reported
    std::string g_lastMsg;

    // ---------------------------------------------------------------------------------------------- helpers
    bool readK(uint64_t va, void* out, size_t n)
    {
        size_t done = 0;
        return g_kcr3 && g_thv.Read(g_kcr3, va, out, n, &done) == THV_OK && done == n;
    }
    bool readT(uint64_t va, void* out, size_t n)
    {
        size_t done = 0;
        return g_t.cr3 && g_thv.Read(g_t.cr3, va, out, n, &done) == THV_OK && done == n;
    }
    bool validRoot(uint64_t cr3, uint64_t image)
    {
        if(!cr3 || !image) return false;
        uint8_t hdr[64];
        size_t done = 0;
        if(g_thv.Read(cr3, image, hdr, sizeof(hdr), &done) != THV_OK || done != sizeof(hdr)) return false;
        if(hdr[0] != 'M' || hdr[1] != 'Z') return false;
        const uint32_t lfanew = *reinterpret_cast<uint32_t*>(&hdr[0x3c]);
        if(!lfanew || lfanew > 0x1000) return false;
        uint32_t sig = 0;
        return g_thv.Read(cr3, image + lfanew, &sig, 4, &done) == THV_OK && sig == 0x00004550;
    }

    std::wstring brokerPath()
    {
        wchar_t buf[MAX_PATH] = {};
        if(GetEnvironmentVariableW(L"TURINGHV_BRIDGE", buf, MAX_PATH) && GetFileAttributesW(buf) != INVALID_FILE_ATTRIBUTES)
            return buf;
        HMODULE self = nullptr;           // thvbridge.exe next to this DLL
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&brokerPath), &self);
        if(self && GetModuleFileNameW(self, buf, MAX_PATH))
        {
            std::wstring p(buf);
            p = p.substr(0, p.find_last_of(L"\\/") + 1) + L"thvbridge.exe";
            if(GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
        }
        return L"C:\\projs\\cheatengine-mod\\Cheat Engine\\bin\\thvbridge.exe";
    }

    bool ensureBridge()
    {
        if(g_thv.Alive()) return true;
        if(!g_thv.Start(brokerPath()))
        {
            g_lastMsg = "turing-hv: " + g_thv.LastError();
            return false;
        }
        if(g_thv.OpenStatus() != THV_OK)
        {
            g_lastMsg = "turing-hv: the hypervisor refused thvbridge.exe a session (status " + std::to_string(g_thv.OpenStatus()) +
                        ") -- trust it in UMBRA > Trusted programs";
            return false;
        }
        thv_process_info sys = {};
        if(g_thv.ProcessInfo(4, &sys) == THV_OK) g_kcr3 = sys.dirbase;
        return true;
    }

    // EPROCESS.Peb / ETHREAD.Teb offsets, learned once from our own process and thread (Windows tells us those)
    typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    void learnOffsets()
    {
        if(g_pebOff >= 0 && g_tebOff >= 0) return;
        auto ntqip = reinterpret_cast<NtQIP_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        thv_process_info self = {};
        if(g_thv.ProcessInfo(GetCurrentProcessId(), &self) != THV_OK || !self.eprocess) return;
        std::vector<uint8_t> buf(0xA00);
        if(g_pebOff < 0 && ntqip && readK(self.eprocess, buf.data(), buf.size()))
        {
            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG len = 0;
            if(ntqip(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &len) >= 0)
                for(int off = 0x100; off + 8 <= int(buf.size()); off += 8)
                    if(*reinterpret_cast<uint64_t*>(&buf[off]) == uint64_t(uintptr_t(pbi.PebBaseAddress))) { g_pebOff = off; break; }
        }
        if(g_tebOff < 0)
        {
            std::vector<thv_thread> th;
            g_thv.EnumThreads(self.eprocess, th);
            const uint64_t myTeb = uint64_t(uintptr_t(NtCurrentTeb()));
            for(auto& t : th)
                if(t.tid == GetCurrentThreadId() && readK(t.ethread, buf.data(), buf.size()))
                {
                    for(int off = 0x40; off + 8 <= int(buf.size()); off += 8)
                        if(*reinterpret_cast<uint64_t*>(&buf[off]) == myTeb) { g_tebOff = off; break; }
                    break;
                }
        }
    }

    uint64_t threadEthread(uint64_t tid)
    {
        std::vector<thv_thread> th;
        if(g_thv.EnumThreads(g_t.eprocess, th) != THV_OK) return 0;
        for(auto& t : th) if(t.tid == tid) return t.ethread;
        return 0;
    }

    // ---------------------------------------------------------------------------------------------- other threads
    // A thread that is NOT stopped at a breakpoint: its user-mode registers as Windows saved them when it last entered
    // the kernel by a system call -- the KTRAP_FRAME at the top of its kernel stack (KTHREAD.InitialStack - 0x190,
    // else KTHREAD.TrapFrame). Read-only, through the hypervisor: nothing in the target is touched. Reported ONLY when
    // the frame proves itself -- CS = 0x33, RSP in user space, RIP in user space directly after a `syscall` (0F 05) --
    // and never for a thread the kernel says is running. A system call keeps RIP, RSP, RBP, RFLAGS, RBX, RSI and RDI
    // in that frame; every other register is reported as 0, not invented.
    //   The two locations are redundant: measured 2026-11-02 on explorer.exe (Win10 19045), each alone found the same
    //   ~41 of 170 threads (the rest: kernel stack not resident / running / not in a system call -> no registers).
    //   KTHREAD: InitialStack +0x28, TrapFrame +0x90.   KTRAP_FRAME (0x190): Rbx +0x140, Rdi +0x148, Rsi +0x150,
    //   Rbp +0x158, Rip +0x168, SegCs +0x170, EFlags +0x178, Rsp +0x180.
    struct TrapCtx { bool ok = false; uint64_t rip = 0, rsp = 0, rbp = 0, rflags = 0, rbx = 0, rsi = 0, rdi = 0; ULONGLONG at = 0; };
    std::map<uint64_t, TrapCtx> g_trap;
    struct ThreadRow { uint64_t ethread; uint32_t state; };
    std::map<uint64_t, ThreadRow> g_rows;
    ULONGLONG g_rowsAt = 0;
    constexpr uint64_t USER_TOP = 0x00007FFFFFFF0000ull, KERNEL_BOTTOM = 0xFFFF800000000000ull;

    bool trapFrameAt(uint64_t f, TrapCtx& c)
    {
        uint8_t tf[0x190];
        if(!readK(f, tf, sizeof(tf))) return false;
        auto q = [&tf](int off) { uint64_t v; memcpy(&v, tf + off, 8); return v; };
        uint16_t cs;
        memcpy(&cs, tf + 0x170, 2);
        const uint64_t rip = q(0x168), rsp = q(0x180);
        if(cs != 0x33 || rip < 0x10000 || rip >= USER_TOP || rsp < 0x10000 || rsp >= USER_TOP) return false;
        uint8_t site[2] = {};
        if(!readT(rip - 2, site, 2) || site[0] != 0x0F || site[1] != 0x05) return false;
        c.rip = rip; c.rsp = rsp; c.rbp = q(0x158); c.rflags = q(0x178); c.rbx = q(0x140); c.rdi = q(0x148); c.rsi = q(0x150);
        c.ok = true;
        return true;
    }

    bool trapContext(uint64_t tid, TrapCtx& out)
    {
        const ULONGLONG now = GetTickCount64();
        auto hit = g_trap.find(tid);
        if(hit != g_trap.end() && now - hit->second.at < 250) { out = hit->second; return out.ok; }
        if(now - g_rowsAt >= 250)
        {
            std::vector<thv_thread> th;
            g_rows.clear();
            if(g_thv.EnumThreads(g_t.eprocess, th) == THV_OK)
                for(auto& t : th) g_rows[t.tid] = ThreadRow{t.ethread, t.state};
            g_rowsAt = now;
        }
        TrapCtx c;
        c.at = now;
        auto row = g_rows.find(tid);
        if(row != g_rows.end() && row->second.ethread && row->second.state != 2 /* Running */)
        {
            uint64_t initial = 0, frame = 0;
            if(readK(row->second.ethread + 0x28, &initial, 8) && initial >= KERNEL_BOTTOM) trapFrameAt(initial - 0x190, c);
            if(!c.ok && readK(row->second.ethread + 0x90, &frame, 8) && frame >= KERNEL_BOTTOM) trapFrameAt(frame, c);
        }
        g_trap[tid] = c;
        out = c;
        return c.ok;
    }

    void ctxFromTrap(const TrapCtx& t, TITAN_ENGINE_CONTEXT_t* c)
    {
        memset(c, 0, sizeof(*c));
        c->cip = ULONG_PTR(t.rip);
        c->csp = ULONG_PTR(t.rsp);
        c->cbp = ULONG_PTR(t.rbp);
        c->eflags = ULONG_PTR(t.rflags);
        c->cbx = ULONG_PTR(t.rbx);
        c->csi = ULONG_PTR(t.rsi);
        c->cdi = ULONG_PTR(t.rdi);
        c->cs = 0x33; c->ss = 0x2B; c->ds = 0x2B; c->es = 0x2B; c->fs = 0x53; c->gs = 0x2B;
    }

    // ---------------------------------------------------------------------------------------------- events
    void fire(TitanCustomHandler h, const void* arg)
    {
        if(g_handlers[h]) g_handlers[h](arg);
    }
    void setEvent(DWORD code, DWORD tid)
    {
        memset(&g_ev, 0, sizeof(g_ev));
        g_ev.dwDebugEventCode = code;
        g_ev.dwProcessId = g_t.pid;
        g_ev.dwThreadId = tid;
        g_continue = DBG_CONTINUE;
    }

    void reportThread(uint64_t tid, uint64_t start, bool create)
    {
        if(create)
        {
            setEvent(CREATE_THREAD_DEBUG_EVENT, DWORD(tid));
            g_ev.u.CreateThread.hThread = threadHandle(DWORD(tid));
            g_ev.u.CreateThread.lpStartAddress = reinterpret_cast<LPTHREAD_START_ROUTINE>(uintptr_t(start));
            fire(UE_CH_CREATETHREAD, &g_ev.u.CreateThread);
        }
        else
        {
            setEvent(EXIT_THREAD_DEBUG_EVENT, DWORD(tid));
            fire(UE_CH_EXITTHREAD, &g_ev.u.ExitThread);
        }
    }

    void reportModule(uint64_t base, bool load)
    {
        if(load)
        {
            setEvent(LOAD_DLL_DEBUG_EVENT, DWORD(g_stoppedTid ? g_stoppedTid : 0));
            g_ev.u.LoadDll.lpBaseOfDll = reinterpret_cast<LPVOID>(uintptr_t(base));
            g_ev.u.LoadDll.hFile = nullptr;   // never a handle on the game's files either: names come from the module list
            fire(UE_CH_LOADDLL, &g_ev.u.LoadDll);
        }
        else
        {
            setEvent(UNLOAD_DLL_DEBUG_EVENT, 0);
            g_ev.u.UnloadDll.lpBaseOfDll = reinterpret_cast<LPVOID>(uintptr_t(base));
            fire(UE_CH_UNLOADDLL, &g_ev.u.UnloadDll);
        }
    }

    // Events are COLLECTED while g_lock is held and FIRED after it is released: an x64dbg callback may wait on its GUI
    // thread, and that thread may be calling into us (GetContextDataEx, MemoryReadSafe) -- holding the lock across a
    // callback would deadlock the two.
    typedef std::vector<std::function<void()>> Events;

    // threads and modules have no debug events here: they are polled and the differences reported
    void pollThreadsModules(Events& ev)
    {
        std::vector<thv_thread> th;
        if(g_thv.EnumThreads(g_t.eprocess, th) == THV_OK)
        {
            std::set<uint64_t> now;
            for(auto& t : th)
            {
                now.insert(t.tid);
                if(!g_threads.count(t.tid))
                {
                    g_threads.insert(t.tid);
                    const uint64_t tid = t.tid, start = t.start_address;
                    ev.push_back([tid, start] { reportThread(tid, start, true); });
                }
            }
            for(auto it = g_threads.begin(); it != g_threads.end();)
                if(!now.count(*it))
                {
                    const uint64_t tid = *it;
                    it = g_threads.erase(it);
                    ev.push_back([tid] { reportThread(tid, 0, false); });
                }
                else ++it;
        }
        std::vector<thv_module> mods;
        if(g_thv.EnumModules(g_t.pid, mods) == THV_OK)
        {
            std::set<uint64_t> now;
            for(auto& m : mods)
            {
                now.insert(m.base);
                if(!g_modules.count(m.base))
                {
                    g_modules[m.base] = m.name;
                    const uint64_t b = m.base;
                    if(b != g_t.imageBase) ev.push_back([b] { reportModule(b, true); });   // the exe came with CREATE_PROCESS
                }
            }
            for(auto it = g_modules.begin(); it != g_modules.end();)
                if(!now.count(it->first))
                {
                    const uint64_t b = it->first;
                    it = g_modules.erase(it);
                    ev.push_back([b] { reportModule(b, false); });
                }
                else ++it;
        }
    }

    bool targetAlive()
    {
        thv_process_info pi = {};
        return g_thv.ProcessInfo(g_t.pid, &pi) == THV_OK && pi.eprocess == g_t.eprocess;
    }

    void clearAllHv()
    {
        thv_dwatch_status st;
        for(auto& b : g_bpx) if(b.second.hv) g_thv.DwatchClear(b.second.hv, &st);
        for(auto& m : g_membp) if(m.second.hv) g_thv.DwatchClear(m.second.hv, &st);
        for(auto& h : g_hw) if(h.used && h.hv) g_thv.DwatchClear(h.hv, &st);
        if(g_tempHv) g_thv.DwatchClear(g_tempHv, &st);
        g_tempHv = 0; g_tempAddr = 0; g_tempSeq = 0;
        g_bpx.clear();
        g_membp.clear();
        for(auto& h : g_hw) h = HwBp{};
    }

    // A parked thread at a breakpoint: tell x64dbg, let its callback decide, then release or step the thread. The
    // shared state is set under g_lock; the callback itself runs WITHOUT it (it blocks until the user's Run / Step,
    // during which x64dbg's GUI thread calls back into us).
    void handleParked(uint32_t hv, const thv_capture_rec& rec, TITANCBSOFTBP softCb, TITANCBHWBP hwCb, ULONG_PTR addr)
    {
        bool isStep;
        TITANCBSTEP stepCb = nullptr;
        {
            std::lock_guard<std::recursive_mutex> g(g_lock);
            g_stoppedTid = rec.tid;
            g_stoppedHv = hv;
            g_ctx = rec;
            g_ctxValid = true;
            g_threads.insert(rec.tid);
            isStep = g_stepPending && g_stepTid == rec.tid;
            if(isStep)
            {
                stepCb = g_stepCb;
                g_stepPending = false;
                g_stepCb = nullptr;
            }
            setEvent(EXCEPTION_DEBUG_EVENT, DWORD(rec.tid));
            g_ev.u.Exception.dwFirstChance = TRUE;
            g_ev.u.Exception.ExceptionRecord.ExceptionCode = isStep ? EXCEPTION_SINGLE_STEP : EXCEPTION_BREAKPOINT;
            g_ev.u.Exception.ExceptionRecord.ExceptionAddress = reinterpret_cast<PVOID>(uintptr_t(rec.rip));
        }
        if(isStep) { if(stepCb) stepCb(); }    // x64dbg's step callback: blocks until the next Run / Step
        else if(softCb) softCb();              // x64dbg's breakpoint callback: likewise
        else if(hwCb) hwCb(reinterpret_cast<const void*>(addr));
        // the callback returned. A Step issued meanwhile already sent its command; otherwise the thread runs on.
        std::lock_guard<std::recursive_mutex> g(g_lock);
        if(!g_stepPending && !g_stop)
        {
            thv_break_cmd c = {};
            c.tid = rec.tid;
            c.cmd = THV_BKC_CONTINUE;
            thv_dwatch_status st;
            g_thv.BreakCmd(hv, c, &st);
        }
        g_ctxValid = false;
        g_stoppedTid = 0;
    }

    struct Hit { uint32_t hv; ULONG_PTR addr; TITANCBSOFTBP soft; TITANCBHWBP hw; bool oneShot; int hwSlot; };

    // which armed parking breakpoints hold a thread that x64dbg hasn't been told about yet (decided under g_lock)
    // A hold's number is status.entries (rev149; rev149b also puts it in rec.seq -- rec.seq on rev149 is the capture's
    // own, always 0, which made every hit look "already reported": the 2026-11-02 bp test's "stopped at 0").
    // The stepping thread is found by TID (index 0 is only the most recently parked thread).
    bool takeHit(uint32_t hv, uint64_t& lastSeq, Hit& out, thv_capture_rec& rec)
    {
        thv_dwatch_status st;
        if(g_thv.BreakRead(hv, 0, &rec, &st) != THV_OK || !st.count) return false;
        const bool stepping = g_stepPending && g_stepHv == hv;
        const uint32_t n = st.count;
        for(uint32_t i = 0; i < n; i++)
        {
            if(i && g_thv.BreakRead(hv, i, &rec, &st) != THV_OK) return false;
            if(st.paused != THV_BKS_HELD) continue;
            const uint64_t hold = st.entries;
            rec.seq = hold;                                   // what the rest of the engine compares
            if(stepping)
            {
                if(rec.tid != g_stepTid) continue;
                if(hold == g_stepSeq) return false;           // the step hasn't landed yet
                lastSeq = hold;
                (void)out;
                return true;
            }
            if(hold == lastSeq) continue;                     // already reported
            lastSeq = hold;
            (void)out;
            return true;
        }
        return false;
    }

    // rev149 can lose a held thread (an executable translation left behind after a step: it runs on as if released)
    // and the step then never lands. rev149b re-arms on its own; on rev149 we re-arm here after a few seconds, and the
    // thread stops at the breakpoint again (reported as a breakpoint hit: the step itself is lost, and said so).
    ULONGLONG g_stepT0 = 0;
    void rearmBreak(ULONG_PTR addr, uint32_t& hv)
    {
        thv_dwatch_status st;
        g_thv.DwatchClear(hv, &st);
        uint32_t id = 0;
        if(g_thv.BreakArm(g_t.cr3, addr, 1, nullptr, &id, &st) == THV_OK && id) hv = id;
    }
    // rev149 also loses a thread after a CONTINUE (it then runs the breakpoint's page without faulting, for good): an
    // idle breakpoint -- nothing parked, no step -- is armed again every 2 s (every vCPU drops the page), so the next
    // run of it is caught. rev149b's escape guard does the same in the hypervisor.
    void rearmIdle()
    {
        std::lock_guard<std::recursive_mutex> g(g_lock);
        const ULONGLONG now = GetTickCount64();
        auto idle = [&](uint32_t hv, ULONGLONG& last) -> bool {
            if(!hv || (g_stepPending && g_stepHv == hv) || (g_ctxValid && g_stoppedHv == hv) || now - last < 2000) return false;
            thv_dwatch_status st;
            thv_capture_rec rec;
            if(g_thv.BreakRead(hv, 0, &rec, &st) != THV_OK || st.count) return false;
            last = now;
            return true;
        };
        for(auto& b : g_bpx) if(idle(b.second.hv, b.second.lastRearm)) rearmBreak(b.first, b.second.hv);
        for(auto& h : g_hw) if(h.used && h.isBreak && idle(h.hv, h.lastRearm)) rearmBreak(h.addr, h.hv);
    }
    // another execute breakpoint of ours on that 4 KiB page (the hypervisor watches pages: the second would never fire)
    ULONG_PTR breakOnPage(ULONG_PTR addr)
    {
        for(auto& b : g_bpx) if((b.first & ~ULONG_PTR(0xFFF)) == (addr & ~ULONG_PTR(0xFFF))) return b.first;
        for(auto& h : g_hw) if(h.used && h.isBreak && (h.addr & ~ULONG_PTR(0xFFF)) == (addr & ~ULONG_PTR(0xFFF))) return h.addr;
        return 0;
    }
    // ---- a step that leaves the stopped thread's page (2026-11-03) --------------------------------------------------
    // The hypervisor holds a parked thread only on its breakpoint's own 4 KiB page: a step whose instruction goes
    // elsewhere (a call or jump to another page, a ret to the caller, code running off the page's end) used to let the
    // thread run free until the breakpoint was hit again. Such a step is done with a TEMPORARY breakpoint at the landing
    // instead: armed, the thread released, and the thread's hold there reported as the step. The temporary breakpoint
    // goes as soon as the thread is let go from it (Run, or a step that lands on yet another page). It lives for the
    // microseconds the thread needs to get there -- not the minutes a user looks at a stop -- which matters when the
    // landing is a system DLL page shared by every process (each run of that page pays a fault while it is armed).
    uint32_t freeSlots();

    // Where the instruction at the stopped thread's RIP sends it: the next instruction, a taken branch's target, an
    // indirect call / jump through a register or memory, a ret's return address. `over` = step over (a call lands on
    // the next instruction). 0 = it can't be told (the hypervisor's own step is used, as before).
    uint64_t stepLanding(const thv_capture_rec& r, bool over)
    {
        uint8_t code[MAX_DISASM_BUFFER] = {};
        size_t got = 0;
        if(g_thv.Read(g_t.cr3, r.rip, code, sizeof(code), &got) != THV_OK || !got) return 0;
        Zydis z(true);
        if(!z.Disassemble(r.rip, code, got)) return 0;
        const uint64_t next = r.rip + z.Size();
        auto reg = [&r](ZydisRegister rg) -> uint64_t {
            if(rg == ZYDIS_REGISTER_NONE) return 0;
            if(rg == ZYDIS_REGISTER_RIP) return r.rip;
            const ZydisRegister big = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, rg);
            if(big < ZYDIS_REGISTER_RAX || big > ZYDIS_REGISTER_R15) return 0;
            const uint64_t v = r.gpr[big - ZYDIS_REGISTER_RAX];   // RAX RCX RDX RBX RSP RBP RSI RDI R8..R15: Zydis's order
            const ZydisRegisterWidth w = ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, rg);
            return w >= 64 ? v : (v & ((1ull << w) - 1));
        };
        auto read64 = [](uint64_t va, uint64_t& out) -> bool {
            size_t n = 0;
            return g_thv.Read(g_t.cr3, va, &out, sizeof(out), &n) == THV_OK && n == sizeof(out);
        };
        auto target = [&]() -> uint64_t {
            const uint64_t direct = z.BranchDestination();
            if(direct) return direct;
            const auto& op = z.GetInstr()->operands[0];
            if(op.type == ZYDIS_OPERAND_TYPE_REGISTER) return reg(op.reg.value);
            if(op.type != ZYDIS_OPERAND_TYPE_MEMORY) return 0;
            uint64_t ea = z.ResolveOpValue(0, reg);
            if(op.mem.segment == ZYDIS_REGISTER_GS) ea += r.gs.base;
            else if(op.mem.segment == ZYDIS_REGISTER_FS) ea += r.fs.base;
            uint64_t t = 0;
            return read64(ea, t) ? t : 0;
        };
        if(z.IsRet())
        {
            uint64_t ra = 0;
            return read64(r.gpr[4], ra) ? ra : 0;
        }
        if(z.IsCall()) return over ? next : target();
        if(z.IsJump() || z.IsLoop())
        {
            if(!z.IsBranchGoingToExecute(uint32_t(r.rflags), r.gpr[1])) return next;
            return target();
        }
        return next;
    }

    // Arm the temporary breakpoint at `landing` and let the stopped thread go to it (g_lock held). false = not possible
    // (another breakpoint of ours on that page, no free watch): the caller falls back to the hypervisor's own step.
    bool stepViaTemp(uint64_t landing)
    {
        if(breakOnPage(ULONG_PTR(landing))) return false;                    // ours on that page: one per page
        if(g_tempHv && (g_tempAddr & ~ULONG_PTR(0xFFF)) == (ULONG_PTR(landing) & ~ULONG_PTR(0xFFF))) return false;
        const uint32_t old = g_tempHv;
        const bool heldOnTemp = old && old == g_stoppedHv;
        if(!old && !freeSlots()) return false;                               // (the old one's slot is reused)
        uint32_t id = 0;
        thv_dwatch_status st;
        if(g_thv.BreakArm(g_t.cr3, landing, 1, nullptr, &id, &st) != THV_OK || !id) return false;
        g_tempHv = id; g_tempAddr = ULONG_PTR(landing); g_tempSeq = 0;
        if(heldOnTemp || (old && old != g_stoppedHv))
            g_thv.DwatchClear(old, &st);                                    // releases the thread held on it, if any
        if(!heldOnTemp)
        {
            thv_break_cmd c = {};
            c.tid = g_stoppedTid;
            c.cmd = THV_BKC_CONTINUE;
            g_thv.BreakCmd(g_stoppedHv, c, &st);
        }
        return true;
    }
    // the temporary breakpoint is no longer needed (its thread let go): gone (g_lock held)
    void dropTemp()
    {
        if(!g_tempHv) return;
        thv_dwatch_status st;
        g_thv.DwatchClear(g_tempHv, &st);
        g_tempHv = 0; g_tempAddr = 0; g_tempSeq = 0;
    }
    // Another thread of the process parked on the temporary breakpoint (it ran that address too): let it go at once --
    // it is nobody's stop. g_lock held.
    void releaseStrangersOnTemp()
    {
        if(!g_tempHv) return;
        thv_dwatch_status st;
        thv_capture_rec rec;
        if(g_thv.BreakRead(g_tempHv, 0, &rec, &st) != THV_OK || !st.count) return;
        const uint32_t n = st.count;
        for(uint32_t i = 0; i < n; i++)
        {
            if(i && g_thv.BreakRead(g_tempHv, i, &rec, &st) != THV_OK) return;
            if(st.paused != THV_BKS_HELD) continue;
            const bool ours = (g_stepPending && g_stepHv == g_tempHv && rec.tid == g_stepTid) ||
                              (g_ctxValid && g_stoppedHv == g_tempHv && rec.tid == g_stoppedTid);
            if(ours) continue;
            thv_break_cmd c = {};
            c.tid = rec.tid;
            c.cmd = THV_BKC_CONTINUE;
            g_thv.BreakCmd(g_tempHv, c, &st);
        }
    }

    void recoverLostStep()
    {
        std::lock_guard<std::recursive_mutex> g(g_lock);
        if(!g_stepPending || GetTickCount64() - g_stepT0 < 3000) return;
        if(g_tempHv && g_stepHv == g_tempHv)
        {
            // the thread did not reach the step's landing (an exception on the way, or it went elsewhere): it runs on
            g_lastMsg = "turing-hv: the step left the breakpoint's page and the thread did not reach the next instruction "
                        "within 3 s; it runs on until a breakpoint";
            dropTemp();
            g_stepPending = false;
            g_stepCb = nullptr;
            return;
        }
        const uint32_t old = g_stepHv;
        for(auto& b : g_bpx) if(b.second.hv == old) { rearmBreak(b.first, b.second.hv); b.second.lastSeq = 0; }
        for(auto& h : g_hw) if(h.used && h.isBreak && h.hv == old) { rearmBreak(h.addr, h.hv); h.lastSeq = 0; }
        g_lastMsg = "turing-hv: the step did not land in 3 s (the hypervisor lost the held thread); the breakpoint was "
                    "re-armed and the thread will stop there again -- install rev149b";
        g_stepPending = false;
        g_stepCb = nullptr;
    }

    void pollBreakpoints()
    {
        recoverLostStep();
        rearmIdle();
        for(;;)
        {
            Hit hit = {};
            thv_capture_rec rec;
            bool found = false;
            {
                std::lock_guard<std::recursive_mutex> g(g_lock);
                if(g_stop) return;
                for(auto it = g_bpx.begin(); it != g_bpx.end() && !found; ++it)
                    if(takeHit(it->second.hv, it->second.lastSeq, hit, rec))
                    {
                        hit = Hit{it->second.hv, it->first, it->second.cb, nullptr, (it->second.type & UE_SINGLESHOOT) != 0, -1};
                        found = true;
                        if(hit.oneShot) g_bpx.erase(it);   // gone from the table first: it can't fire twice
                    }
                for(int i = 0; i < 4 && !found; i++)
                    if(g_hw[i].used && g_hw[i].isBreak && takeHit(g_hw[i].hv, g_hw[i].lastSeq, hit, rec))
                    {
                        hit = Hit{g_hw[i].hv, g_hw[i].addr, nullptr, g_hw[i].cb, false, i};
                        found = true;
                    }
                // the temporary breakpoint of a cross-page step: only the stepping thread's hold there is an event
                releaseStrangersOnTemp();
                if(!found && g_tempHv && g_stepPending && g_stepHv == g_tempHv && takeHit(g_tempHv, g_tempSeq, hit, rec))
                {
                    hit = Hit{g_tempHv, g_tempAddr, nullptr, nullptr, false, -1};
                    found = true;
                }
            }
            if(!found) return;
            handleParked(hit.hv, rec, hit.soft, hit.hw, hit.addr);
            {
                // let go from the temporary breakpoint (Run): it goes. A step from it on the same page keeps it.
                std::lock_guard<std::recursive_mutex> g(g_lock);
                if(hit.hv == g_tempHv && !(g_stepPending && g_stepHv == g_tempHv)) dropTemp();
            }
            if(hit.oneShot)
            {
                thv_dwatch_status s2;
                g_thv.DwatchClear(hit.hv, &s2);   // the one-shot's watch goes only after its thread was released
            }
        }
    }

    // data watches: a hit is reported (P0: the accessing thread already ran on -- see FEATURE-MAP gap list). Each new
    // instruction the watch recorded becomes one event, collected here and fired by the loop without g_lock.
    void pollWatches(Events& ev)
    {
        auto collect = [&ev](uint32_t hv, uint32_t& seen, TITANCBMEMBP memCb, TITANCBHWBP hwCb, ULONG_PTR addr) {
            std::vector<thv_dwatch_entry> ents;
            thv_dwatch_status st;
            if(g_thv.DwatchRead(hv, 0, ents, &st) != THV_OK) return;
            for(size_t k = seen; k < ents.size(); k++)
            {
                const uint64_t rip = ents[k].rip, acc = ents[k].addr;
                ev.push_back([rip, acc, memCb, hwCb, addr] {
                    setEvent(EXCEPTION_DEBUG_EVENT, 0);
                    g_ev.u.Exception.dwFirstChance = TRUE;
                    g_ev.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_SINGLE_STEP;
                    g_ev.u.Exception.ExceptionRecord.ExceptionAddress = reinterpret_cast<PVOID>(uintptr_t(rip));
                    if(memCb) memCb(reinterpret_cast<const void*>(uintptr_t(acc)));
                    else if(hwCb) hwCb(reinterpret_cast<const void*>(addr));
                });
            }
            if(ents.size() > seen) seen = uint32_t(ents.size());
        };
        for(auto& m : g_membp) collect(m.second.hv, m.second.seen, m.second.cb, nullptr, m.second.start);
        for(int i = 0; i < 4; i++)
            if(g_hw[i].used && !g_hw[i].isBreak) collect(g_hw[i].hv, g_hw[i].seen, nullptr, g_hw[i].cb, g_hw[i].addr);
    }

    // fill a TITAN_ENGINE_CONTEXT_t from the parked thread's snapshot. Debug registers are never used: zero.
    void ctxFromSnapshot(const thv_capture_rec& r, TITAN_ENGINE_CONTEXT_t* c)
    {
        memset(c, 0, sizeof(*c));
#ifdef _WIN64
        c->cax = r.gpr[0]; c->ccx = r.gpr[1]; c->cdx = r.gpr[2]; c->cbx = r.gpr[3];
        c->csp = r.gpr[4]; c->cbp = r.gpr[5]; c->csi = r.gpr[6]; c->cdi = r.gpr[7];
        c->r8 = r.gpr[8]; c->r9 = r.gpr[9]; c->r10 = r.gpr[10]; c->r11 = r.gpr[11];
        c->r12 = r.gpr[12]; c->r13 = r.gpr[13]; c->r14 = r.gpr[14]; c->r15 = r.gpr[15];
#else
        c->cax = ULONG_PTR(r.gpr[0]); c->ccx = ULONG_PTR(r.gpr[1]); c->cdx = ULONG_PTR(r.gpr[2]); c->cbx = ULONG_PTR(r.gpr[3]);
        c->csp = ULONG_PTR(r.gpr[4]); c->cbp = ULONG_PTR(r.gpr[5]); c->csi = ULONG_PTR(r.gpr[6]); c->cdi = ULONG_PTR(r.gpr[7]);
#endif
        c->cip = ULONG_PTR(r.rip);
        c->eflags = ULONG_PTR(r.rflags);
        c->gs = r.gs.sel; c->fs = r.fs.sel; c->es = r.es.sel; c->ds = r.ds.sel; c->cs = r.cs.sel; c->ss = r.ss.sel;
        if(r.flags & THV_CAPF_SSE)
        {
            // FXSAVE header: FCW(0) FSW(2) FTW(4) ... MXCSR(24)
            c->x87fpu.ControlWord = *reinterpret_cast<const WORD*>(&r.fxsave_hdr[0]);
            c->x87fpu.StatusWord = *reinterpret_cast<const WORD*>(&r.fxsave_hdr[2]);
            c->x87fpu.TagWord = r.fxsave_hdr[4];
            c->MxCsr = *reinterpret_cast<const DWORD*>(&r.fxsave_hdr[24]);
            const int nx = int(sizeof(c->XmmRegisters) / sizeof(c->XmmRegisters[0]));
            for(int i = 0; i < nx && i < 16; i++)
                memcpy(&c->XmmRegisters[i], &r.xmm[i * 16], 16);
        }
    }

    // TitanEngine register index -> our GPR slot (RAX RCX RDX RBX RSP RBP RSI RDI R8..R15); -1 = not a GPR
    int gprOf(DWORD reg)
    {
        switch(reg)
        {
        case UE_EAX: case UE_RAX: return 0;
        case UE_ECX: case UE_RCX: return 1;
        case UE_EDX: case UE_RDX: return 2;
        case UE_EBX: case UE_RBX: return 3;
        case UE_ESP: case UE_RSP: case UE_CSP: return 4;
        case UE_EBP: case UE_RBP: return 5;
        case UE_ESI: case UE_RSI: return 6;
        case UE_EDI: case UE_RDI: return 7;
        case UE_R8: return 8; case UE_R9: return 9; case UE_R10: return 10; case UE_R11: return 11;
        case UE_R12: return 12; case UE_R13: return 13; case UE_R14: return 14; case UE_R15: return 15;
        default: return -1;
        }
    }

    bool isStopped(HANDLE hThread)
    {
        if(!g_ctxValid) return false;
        if(isThreadPH(hThread)) return threadOf(hThread) == g_stoppedTid;
        return hThread == nullptr;              // "the active thread" when x64dbg passes none
    }

    uint32_t freeSlots()
    {
        thv_dwatch_status st = {};
        // HVDW_MAX = 4 watches in the hypervisor, shared by breakpoints, data watches and captures
        uint32_t used = uint32_t(g_bpx.size() + g_membp.size());
        for(auto& h : g_hw) if(h.used) used++;
        if(g_tempHv) used++;                    // a cross-page step's temporary breakpoint
        (void)st;
        return used >= 4 ? 0 : 4 - used;
    }
}

// ================================================================================================== the exports

extern "C" {

__declspec(dllexport) bool MemoryReadSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    if(!isProcPH(hProcess))
        return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead) != FALSE;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
    if(!isTargetPH(hProcess)) { SetLastError(ERROR_ACCESS_DENIED); return false; }
    size_t done = 0;
    const uint32_t r = g_thv.Read(g_t.cr3, uint64_t(uintptr_t(lpBaseAddress)), lpBuffer, nSize, &done);
    if(lpNumberOfBytesRead) *lpNumberOfBytesRead = done;
    return r == THV_OK && done == nSize;
}

__declspec(dllexport) bool MemoryWriteSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    if(!isProcPH(hProcess))
        return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) != FALSE;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
    if(!isTargetPH(hProcess)) { SetLastError(ERROR_ACCESS_DENIED); return false; }
    size_t done = 0;
    const uint32_t r = g_thv.Write(g_t.cr3, uint64_t(uintptr_t(lpBaseAddress)), lpBuffer, nSize, &done);
    if(lpNumberOfBytesWritten) *lpNumberOfBytesWritten = done;
    return r == THV_OK && done == nSize;
}

__declspec(dllexport) ULONG_PTR GetPEBLocation(HANDLE hProcess)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!isTargetPH(hProcess)) return 0;
    if(g_t.peb) return ULONG_PTR(g_t.peb);
    learnOffsets();
    uint64_t peb = 0;
    if(g_pebOff > 0 && readK(g_t.eprocess + uint64_t(g_pebOff), &peb, 8)) g_t.peb = peb;
    return ULONG_PTR(g_t.peb);
}

__declspec(dllexport) ULONG_PTR GetTEBLocation(HANDLE hThread)
{
    if(!isThreadPH(hThread)) return 0;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    const uint64_t tid = threadOf(hThread);
    if(g_ctxValid && tid == g_stoppedTid && g_ctx.gs_base) return ULONG_PTR(g_ctx.gs_base);   // user GS base = TEB
    learnOffsets();
    const uint64_t eth = threadEthread(tid);
    uint64_t teb = 0;
    if(eth && g_tebOff > 0) readK(eth + uint64_t(g_tebOff), &teb, 8);
    return ULONG_PTR(teb);
}

// "open an EXE and debug it from the start" needs the Windows debugger: not offered (attach to a running process)
__declspec(dllexport) PROCESS_INFORMATION* InitDebugW(const wchar_t*, const wchar_t*, const wchar_t*)
{
    g_lastMsg = "turing-hv: start-under-debugger is not available; start the program normally and attach";
    SetLastError(ERROR_NOT_SUPPORTED);
    return nullptr;
}

__declspec(dllexport) bool StopDebug()
{
    g_stop = true;                             // first, without the lock: the loop may hold it through an enumeration
    std::lock_guard<std::recursive_mutex> g(g_lock);
    clearAllHv();                              // every parked thread is released with its watch
    return true;
}

__declspec(dllexport) void SetBPXOptions(TitanBreakpointType) {}

__declspec(dllexport) bool IsBPXEnabled(ULONG_PTR bpxAddress)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return g_bpx.count(bpxAddress) != 0;
}

__declspec(dllexport) bool SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, TITANCBSOFTBP bpxCallBack)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!g_t.attached) return false;
    if(g_bpx.count(bpxAddress)) return true;
    if(!freeSlots())
    {
        g_lastMsg = "turing-hv: the hypervisor holds 4 breakpoints / watches at once; remove one first";
        return false;
    }
    if(const ULONG_PTR other = breakOnPage(bpxAddress))
    {
        char m[200];
        sprintf_s(m, "turing-hv: there is already a breakpoint on this 4 KiB page (at %llx): the hypervisor watches "
                     "whole pages, one breakpoint per page", (unsigned long long)other);
        g_lastMsg = m;
        return false;
    }
    uint32_t id = 0;
    thv_dwatch_status st;
    if(g_thv.BreakArm(g_t.cr3, bpxAddress, 1, nullptr, &id, &st) != THV_OK || !id) return false;
    g_bpx[bpxAddress] = Bpx{bpxAddress, bpxType, bpxCallBack, id, 0, GetTickCount64()};
    return true;
}

__declspec(dllexport) bool DeleteBPX(ULONG_PTR bpxAddress)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    auto it = g_bpx.find(bpxAddress);
    if(it == g_bpx.end()) return false;
    thv_dwatch_status st;
    g_thv.DwatchClear(it->second.hv, &st);     // a thread parked there is released with it
    g_bpx.erase(it);
    return true;
}

__declspec(dllexport) bool SetMemoryBPXEx(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, TitanMemoryBreakpointType BreakPointType, bool RestoreOnHit, TITANCBMEMBP bpxCallBack)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!g_t.attached || !SizeOfMemory) return false;
    if(BreakPointType == UE_MEMORY_EXECUTE)
    {
        g_lastMsg = "turing-hv: execute memory breakpoints are not available yet -- use a breakpoint on the instruction";
        return false;
    }
    if(!freeSlots()) { g_lastMsg = "turing-hv: 4 breakpoints / watches already"; return false; }
    const uint32_t kind = BreakPointType == UE_MEMORY_WRITE ? THV_DWATCH_WRITE : THV_DWATCH_ACCESS;
    const uint32_t len = SizeOfMemory > THV_DWATCH_LEN_MAX ? THV_DWATCH_LEN_MAX : uint32_t(SizeOfMemory);
    uint32_t id = 0;
    thv_dwatch_status st;
    if(g_thv.DwatchArm(g_t.cr3, MemoryStart, len, kind, &id, &st) != THV_OK || !id) return false;
    g_membp[MemoryStart] = MemBp{MemoryStart, SizeOfMemory, DWORD(BreakPointType), RestoreOnHit, bpxCallBack, id, 0};
    return true;
}

__declspec(dllexport) bool RemoveMemoryBPX(ULONG_PTR MemoryStart, SIZE_T)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    auto it = g_membp.find(MemoryStart);
    if(it == g_membp.end()) return false;
    thv_dwatch_status st;
    g_thv.DwatchClear(it->second.hv, &st);
    g_membp.erase(it);
    return true;
}

__declspec(dllexport) bool GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!titcontext) return false;
    if(!isStopped(hActiveThread))
    {
        TrapCtx t;
        if(isThreadPH(hActiveThread) && trapContext(threadOf(hActiveThread), t))
        {
            ctxFromTrap(t, titcontext);              // a waiting thread: from its kernel trap frame (partial)
            return true;
        }
        memset(titcontext, 0, sizeof(*titcontext)); // running, or no frame that proves itself: nothing invented
        return false;
    }
    ctxFromSnapshot(g_ctx, titcontext);
    return true;
}

__declspec(dllexport) bool SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!titcontext || !isStopped(hActiveThread)) return false;
    TITAN_ENGINE_CONTEXT_t cur;
    ctxFromSnapshot(g_ctx, &cur);
    const ULONG_PTR* now = &titcontext->cax;
    const ULONG_PTR* was = &cur.cax;
#ifdef _WIN64
    const int ngpr = 16;
#else
    const int ngpr = 8;
#endif
    thv_dwatch_status st;
    for(int i = 0; i < ngpr; i++)
        if(now[i] != was[i])
        {
            thv_break_cmd c = {};
            c.tid = g_stoppedTid; c.cmd = THV_BKC_SETREG; c.reg = uint32_t(i); c.value = now[i];
            g_thv.BreakCmd(g_stoppedHv, c, &st);
            g_ctx.gpr[i] = now[i];
        }
    if(titcontext->cip != cur.cip)
    {
        thv_break_cmd c = {};
        c.tid = g_stoppedTid; c.cmd = THV_BKC_SETRIP; c.value = titcontext->cip;
        g_thv.BreakCmd(g_stoppedHv, c, &st);
        g_ctx.rip = titcontext->cip;
    }
    return true;
}

__declspec(dllexport) ULONG_PTR GetContextDataEx(HANDLE hActiveThread, TitanRegister IndexOfRegister)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!isStopped(hActiveThread))
    {
        TrapCtx t;
        if(!isThreadPH(hActiveThread) || !trapContext(threadOf(hActiveThread), t)) return 0;
        switch(IndexOfRegister)                     // a waiting thread: what its system call kept
        {
        case UE_EIP: case UE_RIP: case UE_CIP: return ULONG_PTR(t.rip);
        case UE_ESP: case UE_RSP: case UE_CSP: return ULONG_PTR(t.rsp);
        case UE_EBP: case UE_RBP: return ULONG_PTR(t.rbp);
        case UE_EBX: case UE_RBX: return ULONG_PTR(t.rbx);
        case UE_ESI: case UE_RSI: return ULONG_PTR(t.rsi);
        case UE_EDI: case UE_RDI: return ULONG_PTR(t.rdi);
        case UE_EFLAGS: case UE_RFLAGS: return ULONG_PTR(t.rflags);
        case UE_SEG_CS: return 0x33;
        case UE_SEG_SS: case UE_SEG_DS: case UE_SEG_ES: case UE_SEG_GS: return 0x2B;
        case UE_SEG_FS: return 0x53;
        default: return 0;
        }
    }
    const int gi = gprOf(IndexOfRegister);
    if(gi >= 0) return ULONG_PTR(g_ctx.gpr[gi]);
    switch(IndexOfRegister)
    {
    case UE_EIP: case UE_RIP: case UE_CIP: return ULONG_PTR(g_ctx.rip);
    case UE_EFLAGS: case UE_RFLAGS: return ULONG_PTR(g_ctx.rflags);
    case UE_SEG_GS: return g_ctx.gs.sel;
    case UE_SEG_FS: return g_ctx.fs.sel;
    case UE_SEG_ES: return g_ctx.es.sel;
    case UE_SEG_DS: return g_ctx.ds.sel;
    case UE_SEG_CS: return g_ctx.cs.sel;
    case UE_SEG_SS: return g_ctx.ss.sel;
    default: return 0;                         // DR0-7: never used; x87/MMX/XMM: via GetFullContextDataEx
    }
}

__declspec(dllexport) bool SetContextDataEx(HANDLE hActiveThread, TitanRegister IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!isStopped(hActiveThread)) return false;
    thv_break_cmd c = {};
    c.tid = g_stoppedTid;
    const int gi = gprOf(IndexOfRegister);
    if(gi >= 0) { c.cmd = THV_BKC_SETREG; c.reg = uint32_t(gi); c.value = NewRegisterValue; g_ctx.gpr[gi] = NewRegisterValue; }
    else if(IndexOfRegister == UE_EIP || IndexOfRegister == UE_RIP || IndexOfRegister == UE_CIP)
    {
        c.cmd = THV_BKC_SETRIP; c.value = NewRegisterValue; g_ctx.rip = NewRegisterValue;
    }
    else return false;                         // flags / segments / vector registers: not editable through the HV yet
    thv_dwatch_status st;
    return g_thv.BreakCmd(g_stoppedHv, c, &st) == THV_OK;
}

__declspec(dllexport) bool GetAVXContext(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    return GetFullContextDataEx(hActiveThread, titcontext);   // YMM upper halves: gap 5 (zero)
}
__declspec(dllexport) bool SetAVXContext(HANDLE, TITAN_ENGINE_CONTEXT_t*) { return false; }
__declspec(dllexport) bool GetAVX512Context(HANDLE, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext)
{
    if(titcontext) memset(titcontext, 0, sizeof(*titcontext));
    return false;
}
__declspec(dllexport) bool SetAVX512Context(HANDLE, TITAN_ENGINE_CONTEXT_AVX512_t*) { return false; }

__declspec(dllexport) const DEBUG_EVENT* GetDebugData() { return &g_ev; }

__declspec(dllexport) void SetCustomHandler(TitanCustomHandler ExceptionId, TITANCALLBACKARG CallBack)
{
    if(unsigned(ExceptionId) < 32) g_handlers[ExceptionId] = CallBack;
}

// The length of an indirect near call (FF /2) at b[0..n), or 0 when it isn't one. 64-bit code: ModRM / SIB / disp in
// the 32/64-bit forms (16-bit addressing doesn't exist in long mode -- rev149's hypervisor got that wrong, so a step
// over `call [rip+x]` there trapped a return 4 bytes short and lost the thread).
static unsigned indirectCallLen(const uint8_t* b, unsigned n, bool mode64)
{
    unsigned i = 0;
    bool has67 = false;
    for(; i < n; i++)
    {
        const uint8_t p = b[i];
        if(p == 0x66 || p == 0xF0 || p == 0xF2 || p == 0xF3 || p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65) continue;
        if(p == 0x67) { has67 = true; continue; }
        break;
    }
    if(mode64 && i < n && (b[i] & 0xF0) == 0x40) i++;     // REX
    if(i + 1 >= n || b[i] != 0xFF || ((b[i + 1] >> 3) & 7) != 2) return 0;
    i++;
    const uint8_t modrm = b[i++], mod = modrm >> 6, rm = modrm & 7;
    if(mod == 3) return i;
    if(!mode64 && has67)                                   // 16-bit addressing (compat mode only)
    {
        if(mod == 0 && rm == 6) return i + 2;
        return i + (mod == 1 ? 1 : mod == 2 ? 2 : 0);
    }
    uint8_t base = rm;
    if(rm == 4) { if(i >= n) return 0; base = b[i++] & 7; }
    if(mod == 0 && (rm == 5 || (rm == 4 && base == 5))) return i + 4;
    return i + (mod == 1 ? 1 : mod == 2 ? 4 : 0);
}

static void issueStep(TITANCBSTEP cb, uint32_t cmd)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!g_ctxValid || !g_stoppedHv) return;    // no stopped thread to step
    thv_break_cmd c = {};
    c.tid = g_stoppedTid;
    c.cmd = cmd;
    if(cmd == THV_BKC_STEPOVER)
    {
        // an indirect call: run to the instruction after it instead (right on every image; the hypervisor's own
        // step over handles `call rel32` -- and, from rev149b, the indirect forms too, with the RSP check)
        uint8_t code[16] = {};
        size_t got = 0;
        g_thv.Read(g_t.cr3, g_ctx.rip, code, sizeof(code), &got);
        const unsigned len = indirectCallLen(code, unsigned(got), (g_ctx.efer & (1ull << 10)) && g_ctx.cs.sel == 0x33);
        if(len) { c.cmd = THV_BKC_RUNTO; c.value = g_ctx.rip + len; }
    }
    // 2026-11-03: a step that leaves this page goes by a temporary breakpoint at its landing (see stepViaTemp)
    {
        const uint64_t landing = stepLanding(g_ctx, cmd == THV_BKC_STEPOVER);
        if(landing && (landing & ~0xFFFull) != (g_ctx.rip & ~0xFFFull) && stepViaTemp(landing))
        {
            g_stepCb = cb;
            g_stepPending = true;
            g_stepHv = g_tempHv;
            g_stepTid = g_stoppedTid;
            g_stepSeq = 0;                          // a new watch: the thread's first hold on it is the landing
            g_stepT0 = GetTickCount64();
            return;
        }
    }
    thv_dwatch_status st;
    if(g_thv.BreakCmd(g_stoppedHv, c, &st) != THV_OK) return;
    g_stepCb = cb;
    g_stepPending = true;
    g_stepHv = g_stoppedHv;
    g_stepTid = g_stoppedTid;
    g_stepSeq = g_ctx.seq;
    g_stepT0 = GetTickCount64();
}

__declspec(dllexport) void StepInto(TITANCBSTEP traceCallBack) { issueStep(traceCallBack, THV_BKC_STEP); }
__declspec(dllexport) void StepOver(TITANCBSTEP traceCallBack) { issueStep(traceCallBack, THV_BKC_STEPOVER); }

__declspec(dllexport) bool GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    for(DWORD i = 0; i < 4; i++)
        if(!g_hw[i].used) { if(RegisterIndex) *RegisterIndex = i; return freeSlots() > 0; }
    return false;
}

// "hardware" breakpoints never touch a debug register: execute -> parking breakpoint, write/access -> data watch
__declspec(dllexport) bool SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, TitanHardwareBreakpointType bpxType, TitanHardwareBreakpointSize bpxSize, TITANCBHWBP bpxCallBack)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!g_t.attached || IndexOfRegister >= 4 || g_hw[IndexOfRegister].used || !freeSlots()) return false;
    HwBp h = {};
    h.addr = bpxAddress; h.type = bpxType; h.size = bpxSize; h.cb = bpxCallBack;
    uint32_t id = 0;
    thv_dwatch_status st;
    if(bpxType == UE_HARDWARE_EXECUTE)
    {
        h.isBreak = true;
        if(breakOnPage(bpxAddress))
        {
            g_lastMsg = "turing-hv: there is already a breakpoint on this 4 KiB page (one per page)";
            return false;
        }
        if(g_thv.BreakArm(g_t.cr3, bpxAddress, 1, nullptr, &id, &st) != THV_OK || !id) return false;
        h.lastRearm = GetTickCount64();
    }
    else
    {
        const uint32_t len = bpxSize == UE_HARDWARE_SIZE_1 ? 1 : bpxSize == UE_HARDWARE_SIZE_2 ? 2 : bpxSize == UE_HARDWARE_SIZE_4 ? 4 : 8;
        const uint32_t kind = bpxType == UE_HARDWARE_WRITE ? THV_DWATCH_WRITE : THV_DWATCH_ACCESS;
        if(g_thv.DwatchArm(g_t.cr3, bpxAddress, len, kind, &id, &st) != THV_OK || !id) return false;
    }
    h.hv = id;
    h.used = true;
    g_hw[IndexOfRegister] = h;
    return true;
}

__declspec(dllexport) bool DeleteHardwareBreakPoint(DWORD IndexOfRegister)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(IndexOfRegister >= 4 || !g_hw[IndexOfRegister].used) return false;
    thv_dwatch_status st;
    g_thv.DwatchClear(g_hw[IndexOfRegister].hv, &st);
    g_hw[IndexOfRegister] = HwBp{};
    return true;
}

__declspec(dllexport) bool RemoveAllBreakPoints(TitanBreakpointRemoveOption)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    clearAllHv();
    return true;
}

__declspec(dllexport) void SetNextDbgContinueStatus(DWORD SetDbgCode) { g_continue = SetDbgCode; }

// The debug loop: poll the hypervisor and turn what it reports into the events x64dbg's callbacks expect. Runs until
// StopDebug / DetachDebuggerEx, or the process exits.
__declspec(dllexport) void DebugLoop()
{
    ULONGLONG lastEnum = GetTickCount64();
    while(!g_stop)
    {
        bool exited = false;
        {
            std::lock_guard<std::recursive_mutex> g(g_lock);
            if(!g_t.attached) break;
            exited = !targetAlive();
        }
        if(exited)
        {
            setEvent(EXIT_PROCESS_DEBUG_EVENT, 0);
            fire(UE_CH_EXITPROCESS, &g_ev.u.ExitProcess);
            break;
        }
        pollBreakpoints();          // x64dbg's breakpoint callbacks run without g_lock (they wait for the user)
        if(g_stop) break;
        Events ev;
        {
            std::lock_guard<std::recursive_mutex> g(g_lock);
            pollWatches(ev);
            if(GetTickCount64() - lastEnum >= 500)
            {
                pollThreadsModules(ev);
                lastEnum = GetTickCount64();
            }
        }
        for(auto& e : ev)           // fired with no lock held
        {
            if(g_stop) break;
            e();
        }
        Sleep(10);
    }
    std::lock_guard<std::recursive_mutex> g(g_lock);
    clearAllHv();
    g_t.attached = false;
}

__declspec(dllexport) bool AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, TITANCALLBACK CallBack)
{
    (void)KillOnExit;                          // we never kill the target
    {
        std::lock_guard<std::recursive_mutex> g(g_lock);
        g_stop = false;
        // fail closed: no attach unless HV Mode's guard is refusing handle opens (TT_EnterHvMode)
        if(!hvguard::Active())
        {
            g_lastMsg = "turing-hv: HV Mode's guard is not active, so nothing stops this process opening the target -- "
                        "attach refused (TT_EnterHvMode first)";
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        if(!pidFits(ProcessId))
        {
            g_lastMsg = "turing-hv: process id " + std::to_string(ProcessId) + " is outside the pseudo-handle range";
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        if(!ensureBridge()) { SetLastError(ERROR_ACCESS_DENIED); return false; }
        thv_process_info pi = {};
        if(g_thv.ProcessInfo(ProcessId, &pi) != THV_OK || !pi.eprocess)
        {
            g_lastMsg = "turing-hv: the hypervisor doesn't see that process";
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        g_t = Target{};
        g_t.pid = ProcessId;
        g_t.eprocess = pi.eprocess;
        g_t.imageBase = pi.image_base;
        g_t.imageSize = pi.image_size;
        g_t.ppid = pi.ppid;
        memcpy(g_t.name, pi.name, sizeof(g_t.name));
        // the page-table root: EPROCESS's (validated by reading the image), else the hypervisor's CR3 tracker
        if(validRoot(pi.dirbase, pi.image_base))
            g_t.cr3 = pi.dirbase;
        else
        {
            thv_cr3_query q = {};
            thv_cr3_result r = {};
            q.accept = THV_CR3_ACCEPT_ALL;
            q.pid = ProcessId;
            if(g_thv.Cr3Query(q, &r) == THV_OK && validRoot(r.cr3, pi.image_base)) g_t.cr3 = r.cr3;
        }
        if(!g_t.cr3)
        {
            g_lastMsg = "turing-hv: could not find that process's page-table root";
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
        g_t.attached = true;
        g_threads.clear();
        g_modules.clear();
    }
    auto* info = static_cast<PROCESS_INFORMATION*>(DebugInfo);

    // CREATE_PROCESS (the exe), then every thread and module that already exists -- each fired with no lock held
    std::vector<thv_thread> th;
    g_thv.EnumThreads(g_t.eprocess, th);
    const DWORD firstTid = th.empty() ? 0 : DWORD(th.front().tid);
    if(info)
    {
        info->hProcess = procHandle();
        info->hThread = threadHandle(firstTid);
        info->dwProcessId = ProcessId;
        info->dwThreadId = firstTid;
    }
    const ULONG_PTR teb = GetTEBLocation(threadHandle(firstTid));
    {
        std::lock_guard<std::recursive_mutex> g(g_lock);
        g_threads.insert(firstTid);
        g_modules[g_t.imageBase] = g_t.name;
    }
    setEvent(CREATE_PROCESS_DEBUG_EVENT, firstTid);
    auto& cp = g_ev.u.CreateProcessInfo;
    cp.hFile = nullptr;                        // no handle on the game's files: the name comes from the module list
    cp.hProcess = procHandle();
    cp.hThread = threadHandle(firstTid);
    cp.lpBaseOfImage = reinterpret_cast<LPVOID>(uintptr_t(g_t.imageBase));
    cp.lpStartAddress = th.empty() ? nullptr : reinterpret_cast<LPTHREAD_START_ROUTINE>(uintptr_t(th.front().start_address));
    cp.lpThreadLocalBase = reinterpret_cast<LPVOID>(teb);
    fire(UE_CH_CREATEPROCESS, &cp);
    Events ev;
    {
        std::lock_guard<std::recursive_mutex> g(g_lock);
        pollThreadsModules(ev);                // every other existing thread and every module: reported once each
    }
    for(auto& e : ev) e();
    // no system breakpoint: stock attach gets one from a thread it injects into the game, which we never do.
    // x64dbg's attach callback runs next and shows the process RUNNING.
    setEvent(EXCEPTION_DEBUG_EVENT, firstTid);
    if(CallBack) CallBack();
    DebugLoop();
    return true;
}

__declspec(dllexport) bool DetachDebuggerEx(DWORD)
{
    g_stop = true;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    clearAllHv();
    return true;
}

__declspec(dllexport) bool IsFileBeingDebugged() { return g_t.attached; }

// A process the hypervisor sees: a pseudo-handle carrying its pid. NEVER a real OpenProcess -- this engine is only
// loaded in HV Mode, where x64dbg holds no handle to another process (the guard would refuse it anyway).
__declspec(dllexport) HANDLE TitanOpenProcess(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(g_t.attached && dwProcessId == g_t.pid) return procHandle();
    if(!pidFits(dwProcessId) || dwProcessId == GetCurrentProcessId())
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    if(!ensureBridge()) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
    thv_process_info pi = {};
    if(g_thv.ProcessInfo(dwProcessId, &pi) != THV_OK || !pi.eprocess)
    {
        g_lastMsg = "turing-hv: the hypervisor doesn't see process " + std::to_string(dwProcessId);
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    return procHandleOf(dwProcessId);
}

// a thread of the attached target: its pseudo-handle; anything else is refused (never a real OpenThread)
__declspec(dllexport) HANDLE TitanOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(g_t.attached && g_threads.count(dwThreadId)) return threadHandle(dwThreadId);
    SetLastError(ERROR_ACCESS_DENIED);
    return nullptr;
}

__declspec(dllexport) void SetEngineVariable(TitanEngineVariable, bool) {}

__declspec(dllexport) bool EngineCheckStructAlignment(TitanStructureType StructureType, ULONG_PTR StructureSize)
{
    if(StructureType == UE_STRUCT_TITAN_ENGINE_CONTEXT) return StructureSize == sizeof(TITAN_ENGINE_CONTEXT_t);
    return false;
}

// ---- TitanTuring extras (the Win32 shim and the harness use these) ----
__declspec(dllexport) bool TT_IsTargetProcess(HANDLE h) { return isProcPH(h); }
__declspec(dllexport) bool TT_IsTargetThread(HANDLE h) { return isThreadPH(h); }
__declspec(dllexport) DWORD TT_TargetPid() { return g_t.pid; }
__declspec(dllexport) DWORD TT_ThreadIdOf(HANDLE h) { return isThreadPH(h) ? threadOf(h) : 0; }
__declspec(dllexport) const char* TT_LastMessage() { return g_lastMsg.c_str(); }
__declspec(dllexport) bool TT_TargetModules(TT_MODULE* out, DWORD max, DWORD* count)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    std::vector<thv_module> mods;
    if(!g_t.attached || g_thv.EnumModules(g_t.pid, mods) != THV_OK) return false;
    DWORD n = 0;
    for(auto& m : mods)
    {
        if(n < max && out)
        {
            out[n].base = m.base; out[n].size = m.size; out[n].entry = m.entry;
            memcpy(out[n].name, m.name, sizeof(out[n].name));
        }
        n++;
    }
    if(count) *count = n;
    return true;
}
__declspec(dllexport) bool TT_TargetThreads(TT_THREAD* out, DWORD max, DWORD* count)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    std::vector<thv_thread> th;
    if(!g_t.attached || g_thv.EnumThreads(g_t.eprocess, th) != THV_OK) return false;
    DWORD n = 0;
    for(auto& t : th)
    {
        if(n < max && out) { out[n].tid = DWORD(t.tid); out[n].start = t.start_address; }
        n++;
    }
    if(count) *count = n;
    return true;
}
__declspec(dllexport) bool TT_TargetRegions(TT_REGION* out, DWORD max, DWORD* count)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    std::vector<thv_memory_region> rg;
    if(!g_t.attached || g_thv.EnumMemory(g_t.cr3, rg) != THV_OK) return false;
    DWORD n = 0;
    for(auto& r : rg)
    {
        if(n < max && out) { out[n].base = r.base; out[n].size = r.size; out[n].flags = r.flags; }
        n++;
    }
    if(count) *count = n;
    return true;
}
// rev150: the native trace (TitanTuring.h)
static_assert(sizeof(TT_TRACE_REC) == sizeof(thv_trace_rec) && sizeof(TT_TRACE_INFO) == sizeof(thv_trace_info), "TT_TRACE_* drift");
__declspec(dllexport) bool TT_TraceStart(uint64_t address, uint32_t length, uint32_t maxRecords, bool stepOver, uint32_t* id, char* why, DWORD whyLen)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    auto say = [&](const std::string & s) { if(why && whyLen) { strncpy_s(why, whyLen, s.c_str(), _TRUNCATE); } return false; };
    if(id) *id = 0;
    if(!g_t.attached || !g_t.cr3) return say("not attached to a process through the hypervisor");
    if(address >= 0x800000000000ull) return say("user-mode addresses only");
    if(!length || length > 15) length = 1;
    if(!maxRecords) maxRecords = THV_TRACE_MAX / 2;
    if(maxRecords > THV_TRACE_MAX) maxRecords = THV_TRACE_MAX;
    thv_dwatch_status st = {};
    const uint32_t r = g_thv.TraceArm(g_t.cr3, address, length, maxRecords, stepOver ? THV_TRF_OVER : 0, id, &st);
    switch(r)
    {
    case THV_OK: return true;
    case THV_E_NO_SPACE: return say("another trace is running (one at a time), or all 4 hypervisor watches are in use");
    case THV_E_BAD_POINTER: return say("the instruction's page is not in memory right now (paged out?)");
    case THV_E_BAD_ARGUMENT: return say("the hypervisor refused it (an image older than rev150 has no native trace)");
    case THV_E_BAD_COMMAND: return say("thvbridge.exe is older than rev150 (install the rev150 image, then its bridge)");
    default: return say("the hypervisor would not arm it (status " + std::to_string(r) + ")");
    }
}
__declspec(dllexport) bool TT_TraceRead(uint32_t id, TT_TRACE_INFO* info, TT_TRACE_REC* recs, uint32_t max, uint32_t* count)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(count) *count = 0;
    if(info) memset(info, 0, sizeof(*info));
    uint32_t n = 0;
    thv_dwatch_status st = {};
    thv_trace_info ti = {};
    std::vector<thv_trace_rec> part;
    for(int guard = 0; guard < int(THV_TRACE_MAX); guard++)
    {
        const uint32_t want = (recs && n < max) ? max - n : 0;
        if(g_thv.TraceRead(id, n, want, &ti, part, &st) != THV_OK)
        {
            if(!n) return false;        // nothing read: the trace is gone
            break;                      // keep what was read
        }
        if(part.empty()) break;
        memcpy(recs + n, part.data(), part.size() * sizeof(thv_trace_rec));
        n += uint32_t(part.size());
        if(n >= st.entries || n >= max) break;
    }
    if(info) memcpy(info, &ti, sizeof(ti));
    if(count) *count = n;
    return true;
}
__declspec(dllexport) void TT_TraceStop(uint32_t id)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    thv_dwatch_status st = {};
    if(id) g_thv.DwatchClear(id, &st);
}
__declspec(dllexport) const char* TT_TraceReason(uint32_t reason)
{
    switch(reason)
    {
    case THV_TRE_COUNT: return "the records asked for are taken";
    case THV_TRE_NOSTEP: return "the next instruction can't be stepped unseen (PUSHF / POPF / IRET / SYSCALL / INT n)";
    case THV_TRE_EVENT: return "an interrupt was due for the thread";
    case THV_TRE_EXCEPTION: return "the instruction raised an exception";
    case THV_TRE_GUEST_TF: return "the thread single-steps itself (its own trap flag)";
    case THV_TRE_LEFT: return "the thread left the process or user mode";
    case THV_TRE_L1: return "Hyper-V kept the vCPU too long";
    case THV_TRE_EMULATED: return "an instruction was emulated by Hyper-V";
    case THV_TRE_CLEARED: return "stopped";
    case 0: return "still running";
    default: return "stopped (other)";
    }
}

__declspec(dllexport) uint64_t TT_ImageBase() { return g_t.imageBase; }
__declspec(dllexport) const char* TT_ImageName() { return g_t.name; }

__declspec(dllexport) DWORD TT_PseudoPid(HANDLE h) { return isProcPH(h) ? pidOfPH(h) : 0; }
__declspec(dllexport) bool TT_IsTargetPseudo(HANDLE h)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return isTargetPH(h);
}
__declspec(dllexport) bool TT_IsTargetTid(DWORD tid)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return g_t.attached && g_threads.count(tid) != 0;
}
__declspec(dllexport) DWORD TT_StoppedTid()
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return g_ctxValid ? DWORD(g_stoppedTid) : 0;
}
__declspec(dllexport) DWORD TT_ParentPid()
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return g_t.attached ? DWORD(g_t.ppid) : 0;
}
__declspec(dllexport) bool TT_TargetAlive()
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    return g_t.attached && targetAlive();
}
__declspec(dllexport) uint64_t TT_ThreadStart(DWORD tid)
{
    std::lock_guard<std::recursive_mutex> g(g_lock);
    std::vector<thv_thread> th;
    if(!g_t.attached || g_thv.EnumThreads(g_t.eprocess, th) != THV_OK) return 0;
    for(auto& t : th)
        if(t.tid == tid) return t.start_address;
    return 0;
}

// A module's full path, from the target's own loader list (PEB.Ldr.InLoadOrderModuleList) read through the
// hypervisor -- what GetModuleFileNameEx reads, without a handle. base 0 = the exe. Returns the length in characters.
//   PEB.Ldr +0x18; PEB_LDR_DATA.InLoadOrderModuleList +0x10;
//   LDR_DATA_TABLE_ENTRY: InLoadOrderLinks.Flink +0x00, DllBase +0x30, FullDllName {Length +0x48, Buffer +0x50}
__declspec(dllexport) DWORD TT_ModulePath(uint64_t base, wchar_t* out, DWORD n)
{
    if(!out || !n) return 0;
    out[0] = 0;
    std::lock_guard<std::recursive_mutex> g(g_lock);
    if(!g_t.attached) return 0;
    if(!base) base = g_t.imageBase;
    const uint64_t peb = GetPEBLocation(procHandle());
    uint64_t ldr = 0, link = 0;
    if(!peb || !readT(peb + 0x18, &ldr, 8) || !ldr) return 0;
    const uint64_t head = ldr + 0x10;
    if(!readT(head, &link, 8)) return 0;
    for(int i = 0; i < 8192 && link && link != head; i++)
    {
        uint8_t e[0x58];
        if(!readT(link, e, sizeof(e))) return 0;
        if(*reinterpret_cast<uint64_t*>(e + 0x30) == base)
        {
            const uint16_t bytes = *reinterpret_cast<uint16_t*>(e + 0x48);
            const uint64_t buf = *reinterpret_cast<uint64_t*>(e + 0x50);
            DWORD chars = bytes / 2;
            if(chars >= n) chars = n - 1;
            if(!buf || !readT(buf, out, size_t(chars) * 2)) { out[0] = 0; return 0; }
            out[chars] = 0;
            return chars;
        }
        link = *reinterpret_cast<uint64_t*>(e + 0x00);
    }
    return 0;
}

} // extern "C"
