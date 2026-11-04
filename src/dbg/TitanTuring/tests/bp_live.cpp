// bp_live.cpp -- the rev149 parking breakpoint, driven directly through thvbridge (no x64dbg, no TitanTuring):
// arm on adbg_target's hot_target, wait for a thread to park, then run a script of commands against it.
// Tells whether a failure is in the hypervisor / bridge or in the engine layer above it.
//   bp_live.exe <thvbridge.exe> <adbg_target.exe> [script]
// script: comma-separated  s = step into, o = step over, r<hex> = run to hot_target+hex, c = continue (expects the
//         thread back at hot_target), w<ms> = just wait, h<ms> = HOLD CHECK: read the hold every 100 ms for <ms> and
//         fail if it moves (a new hold number or another RIP: the held thread got away -- rev150d's re-arm escapes),
//         q<ms> = QUIET HOLD: no hypervisor read at all for <ms> (so nothing re-arms), Windows' view of the held thread
//         sampled every 10 ms instead -- a held thread spins on its fault (running / ready), one that got away sleeps
//         (waiting, DelayExecution). Fails if it is ever seen waiting. Keep <ms> under 10000: a watch nobody reads
//         for HVDW_ABANDON_S (10 s) is abandoned by design.
//         Default "s,s,o,r30,c".
// Each command must land within 3 s: a new hold (status.entries changes; the record's own seq is the capture's).
// Exit 0 = every command landed where it should.
#include "../thvclient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

static const char* bks(uint32_t s)
{
    switch(s)
    {
    case THV_BKS_HELD: return "HELD";
    case THV_BKS_STEPPING: return "STEPPING";
    case THV_BKS_RANOUT: return "RANOUT";
    default: return "?";
    }
}

static void show(const char* what, uint32_t r, const thv_dwatch_status& st, const thv_capture_rec* rec)
{
    printf("  %-8s r=%08x pages=%u entries=%u count=%u state=%s", what, r, st.pages, st.entries, st.count, bks(st.paused));
    if(rec && st.count) printf("  tid=%llu rip=%llx", (unsigned long long)rec->tid, (unsigned long long)rec->rip);
    // 2026-11-03: which kind of wrong landing is it? hot_target(x) gets a new x (RCX) every call, push rbp lowers RSP by
    // 8, mov rbp,rsp makes RBP == RSP: an instruction that never ran leaves all three as they were; a thread that ran
    // free and came round again shows a new RCX; a step that ran but was reported at the old RIP shows RBP == RSP.
    if(rec && st.count)
        printf("  rsp=%llx rbp=%llx rcx=%llx rax=%llx rfl=%llx seq=%llu tsc=%llu", (unsigned long long)rec->gpr[4],
               (unsigned long long)rec->gpr[5], (unsigned long long)rec->gpr[1], (unsigned long long)rec->gpr[0],
               (unsigned long long)rec->rflags, (unsigned long long)rec->seq, (unsigned long long)rec->tsc);
    // rev150e: the breakpoint's diagnostics (0 on older hypervisors): re-arms, escapes from a hold, busy retries,
    // faults while the vCPU was already letting an instruction through, faults left to run
    if(st.hits | st.other | st.elsewhere | st.dropped | st.unstepped)
        printf("  [rearm=%llu escaped=%llu busy-retry=%llu in-letthrough=%llu loose=%llu last-escape: vcpu %u (held on %u), %u ms away]",
               (unsigned long long)st.hits, (unsigned long long)st.other, (unsigned long long)st.elsewhere,
               (unsigned long long)st.dropped, (unsigned long long)st.unstepped, st.throttled & 0xFFu,
               (st.throttled >> 8) & 0xFFu, st.throttled >> 16);
    printf("\n");
}

// SystemProcessInformation: the thread's state, wait reason and CPU times
typedef LONG(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
static void threadState(DWORD pid, DWORD tid)
{
    static NtQSI_t q = reinterpret_cast<NtQSI_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    std::vector<uint8_t> buf(1 << 22);
    ULONG ret = 0;
    if(q(5, buf.data(), ULONG(buf.size()), &ret) != 0) { printf("    (NtQSI failed)\n"); return; }
    for(size_t off = 0;;)
    {
        const uint8_t* p = buf.data() + off;
        const ULONG next = *reinterpret_cast<const ULONG*>(p);
        const ULONG nthreads = *reinterpret_cast<const ULONG*>(p + 4);
        const uintptr_t upid = *reinterpret_cast<const uintptr_t*>(p + 0x50);
        if(upid == pid)
        {
            const uint8_t* th = p + 0x100;          // SYSTEM_THREAD_INFORMATION[] (0x50 each on x64)
            for(ULONG i = 0; i < nthreads; i++, th += 0x50)
            {
                const uintptr_t utid = *reinterpret_cast<const uintptr_t*>(th + 0x30);
                if(utid != tid) continue;
                const LONGLONG kt = *reinterpret_cast<const LONGLONG*>(th + 0x00);
                const LONGLONG ut = *reinterpret_cast<const LONGLONG*>(th + 0x08);
                const ULONG state = *reinterpret_cast<const ULONG*>(th + 0x44);
                const ULONG wr = *reinterpret_cast<const ULONG*>(th + 0x48);
                printf("    thread %lu: state %lu (2=running 1=ready 5=waiting) wait %lu, kernel %lld ms, user %lld ms\n",
                       tid, state, wr, kt / 10000, ut / 10000);
            }
            return;
        }
        if(!next) break;
        off += next;
    }
}

// one sample of the thread: 0 = not found
static int threadSample(DWORD pid, DWORD tid, ULONG* state, ULONG* wr, LONGLONG* ut, ULONG* cs)
{
    static NtQSI_t q = reinterpret_cast<NtQSI_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    static std::vector<uint8_t> buf(1 << 22);
    ULONG ret = 0;
    if(q(5, buf.data(), ULONG(buf.size()), &ret) != 0) return 0;
    for(size_t off = 0;;)
    {
        const uint8_t* p = buf.data() + off;
        const ULONG next = *reinterpret_cast<const ULONG*>(p);
        const ULONG nthreads = *reinterpret_cast<const ULONG*>(p + 4);
        if(*reinterpret_cast<const uintptr_t*>(p + 0x50) == pid)
        {
            const uint8_t* th = p + 0x100;
            for(ULONG i = 0; i < nthreads; i++, th += 0x50)
            {
                if(*reinterpret_cast<const uintptr_t*>(th + 0x30) != tid) continue;
                *ut = *reinterpret_cast<const LONGLONG*>(th + 0x08);
                *cs = *reinterpret_cast<const ULONG*>(th + 0x40);
                *state = *reinterpret_cast<const ULONG*>(th + 0x44);
                *wr = *reinterpret_cast<const ULONG*>(th + 0x48);
                return 1;
            }
            return 0;
        }
        if(!next) return 0;
        off += next;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if(argc < 3) { printf("usage: bp_live <thvbridge.exe> <adbg_target.exe> [script]\n"); return 2; }
    std::string script = "s,s,o,r30,c";
    if(argc > 3) { script.clear(); for(const wchar_t* p = argv[3]; *p; p++) script += char(*p); }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    CreatePipe(&rd, &wr, &sa, 0);
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + std::wstring(argv[2]) + L"\" --seconds 60 --quiet";
    if(!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) { printf("target start failed\n"); return 1; }
    CloseHandle(wr);
    std::string out;
    uint64_t hot = 0;
    for(DWORD t0 = GetTickCount(); !hot && GetTickCount() - t0 < 10000;)
    {
        char buf[512]; DWORD n = 0;
        if(!ReadFile(rd, buf, sizeof(buf) - 1, &n, nullptr) || !n) break;
        buf[n] = 0; out += buf;
        size_t p = out.find("hot_target=");
        if(p != std::string::npos && out.find(' ', p) != std::string::npos) hot = _strtoui64(out.c_str() + p + 11, nullptr, 16);
    }
    if(!hot) { printf("no bait line\n"); TerminateProcess(pi.hProcess, 0); return 1; }

    ThvClient c;
    if(!c.Start(argv[1]) || c.OpenStatus() != THV_OK) { printf("bridge: %s (open %08x)\n", c.LastError().c_str(), c.OpenStatus()); TerminateProcess(pi.hProcess, 0); return 1; }
    thv_process_info info = {};
    c.ProcessInfo(pi.dwProcessId, &info);
    printf("target pid %lu hot_target %llx, broker SDK %08x, script %s\n", pi.dwProcessId, (unsigned long long)hot, c.BrokerSdkVersion(), script.c_str());

    int fails = 0;
    uint32_t id = 0;
    thv_dwatch_status st = {};
    uint32_t r = c.BreakArm(info.dirbase, hot, 1, nullptr, &id, &st);
    if(r != THV_OK || !id) { printf("arm failed %08x\n", r); TerminateProcess(pi.hProcess, 0); return 1; }

    thv_capture_rec rec = {};
    auto waitHeld = [&](const char* what, uint32_t notSeq, DWORD ms) -> bool {
        for(DWORD t0 = GetTickCount(); GetTickCount() - t0 < ms; Sleep(20))
        {
            r = c.BreakRead(id, 0, &rec, &st);
            if(r == THV_OK && st.count && st.paused == THV_BKS_HELD && st.entries != notSeq) { show(what, r, st, &rec); return true; }
        }
        show(what, r, st, &rec);
        return false;
    };
    if(!waitHeld("park", ~0u, 5000) || rec.rip != hot) { printf("FAIL: no thread parked at hot_target\n"); fails++; }
    else
    {
        const uint64_t tid = rec.tid;
        size_t pos = 0;
        while(pos < script.size())
        {
            size_t e = script.find(',', pos);
            std::string op = script.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
            pos = e == std::string::npos ? script.size() : e + 1;
            if(op.empty()) continue;
            const uint32_t seq = st.entries;
            const uint64_t rip0 = rec.rip;
            thv_break_cmd k = {};
            k.tid = tid;
            uint64_t want = 0;          // 0 = anywhere but rip0
            switch(op[0])
            {
            case 's': k.cmd = THV_BKC_STEP; break;
            case 'o': k.cmd = THV_BKC_STEPOVER; break;
            case 'r': k.cmd = THV_BKC_RUNTO; k.value = want = hot + _strtoui64(op.c_str() + 1, nullptr, 16); break;
            case 'c': k.cmd = THV_BKC_CONTINUE; want = hot; break;
            case 'w': Sleep(DWORD(atoi(op.c_str() + 1))); r = c.BreakRead(id, 0, &rec, &st); show("wait", r, st, &rec); continue;
            case 'h':
            {
                // 2026-11-04: a held thread must stay held however often it is read (rev150d let it go ~1 in 4 re-arms)
                const DWORD ms = DWORD(atoi(op.c_str() + 1));
                const uint64_t rip1 = rec.rip;
                const uint32_t seq1 = st.entries;
                int moved = 0;
                for(DWORD t0 = GetTickCount(); GetTickCount() - t0 < ms && !moved; Sleep(100))
                {
                    r = c.BreakRead(id, 0, &rec, &st);
                    if(r != THV_OK || !st.count || st.entries != seq1 || rec.rip != rip1 || st.paused != THV_BKS_HELD) moved = 1;
                }
                show(moved ? "MOVED" : "held", r, st, &rec);
                if(moved) { printf("FAIL: the held thread got away within %lu ms (hold %u at %llx)\n", ms, seq1, (unsigned long long)rip1); fails++; }
                continue;
            }
            case 'q':
            {
                // 2026-11-04 (rev150e run): is a held thread ever running free while NOTHING re-arms? No hypervisor read
                // for <ms>; Windows' view of the thread every 10 ms. Spinning on its fault = running (2) or ready (1);
                // got away = mostly waiting (5) in its Sleep(2) (DelayExecution, 4).
                const DWORD ms = DWORD(atoi(op.c_str() + 1));
                const uint64_t rip1 = rec.rip;
                const uint32_t seq1 = st.entries;
                unsigned n = 0, running = 0, ready = 0, waiting = 0, other = 0, firstWait = 0;
                ULONG cs0 = 0, cs1 = 0;
                LONGLONG ut0 = 0, ut1 = 0;
                const DWORD t0 = GetTickCount();
                for(; GetTickCount() - t0 < ms; Sleep(10))
                {
                    ULONG sta = 0, wr = 0, cs = 0; LONGLONG ut = 0;
                    if(!threadSample(pi.dwProcessId, DWORD(tid), &sta, &wr, &ut, &cs)) continue;
                    if(!n) { cs0 = cs; ut0 = ut; }
                    cs1 = cs; ut1 = ut; ++n;
                    if(sta == 2) ++running; else if(sta == 1) ++ready;
                    else if(sta == 5) { if(!waiting) firstWait = GetTickCount() - t0; ++waiting; }
                    else ++other;
                }
                r = c.BreakRead(id, 0, &rec, &st);
                show("quiet", r, st, &rec);
                printf("    %u samples in %lu ms: running %u, ready %u, WAITING %u (first at %u ms), other %u; context switches %lu, user time +%lld ms\n",
                       n, ms, running, ready, waiting, firstWait, other, cs1 - cs0, (ut1 - ut0) / 10000);
                if(waiting || st.entries != seq1 || rec.rip != rip1)
                {
                    printf("FAIL: the held thread ran free with nothing re-arming (%u waiting samples, hold %u -> %u)\n", waiting, seq1, st.entries);
                    fails++;
                }
                continue;
            }
            default: printf("bad op %s\n", op.c_str()); continue;
            }
            r = c.BreakCmd(id, k, &st);
            if(r != THV_OK) { printf("  %s: command refused %08x\n", op.c_str(), r); fails++; break; }
            const bool ok = waitHeld(op.c_str(), seq, 3000) && (want ? rec.rip == want : rec.rip != rip0);
            if(!ok)
            {
                printf("FAIL: %s did not land (from %llx)\n", op.c_str(), (unsigned long long)rip0); fails++;
                // what Windows says the thread is doing meanwhile: running (spinning on its fault) or switched out
                threadState(pi.dwProcessId, DWORD(tid));
                // re-arm: every vCPU drops the page's leaves again; does the escaped thread get caught again?
                c.DwatchClear(id, &st);
                r = c.BreakArm(info.dirbase, hot, 1, nullptr, &id, &st);
                printf("  re-armed r=%08x id %u\n", r, id);
                if(waitHeld("rearm", ~0u, 5000) && rec.rip == hot) printf("  RE-ARM CAUGHT IT AGAIN (stale translation theory holds)\n");
                else printf("  re-arm did not catch it either\n");
                threadState(pi.dwProcessId, DWORD(tid));
                break;
            }
        }
    }
    r = c.DwatchClear(id, &st);
    TerminateProcess(pi.hProcess, 0);
    printf(fails ? "bp_live: FAIL (%d)\n" : "bp_live: PASS\n", fails);
    return fails ? 1 : 0;
}
